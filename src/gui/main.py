from qdarkstyle import load_stylesheet
from pyperclip import copy

from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem, QMessageBox, \
                            QMenu, QSystemTrayIcon, QAction, QPushButton, \
                            QDialog, QFormLayout, QDialogButtonBox, QSpinBox
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtCore import Qt, QTimer
try:
    from PyQt5.QtWinExtras import QWinTaskbarButton
except Exception:
    QWinTaskbarButton = None

from ui.ui_main import Ui_MainWindow

from gui.settings import Settings
from gui.about import About
from gui.device import Device
from gui.traffic import Traffic

from networking.scanner import Scanner
from networking.killer import Killer

from tools.qtools import colored_item, MsgType, Buttons, clickable
from tools.utils_gui import set_settings, get_settings
from tools.utils import goto, is_connected, get_default_iface
from tools.pfctl import ensure_pf_enabled, install_anchor, block_all_for, unblock_all_for

from assets import *

from bridge import ScanThread  # UpdateThread disabled for fork

from constants import *

# from qt_material import build_stylesheet


class LagSwitchDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Lag Switch Settings')
        self.setModal(True)
        layout = QFormLayout(self)
        
        # Lag duration - how long to block (creates the "lag" freeze)
        self.lagSpin = QSpinBox(self)
        self.lagSpin.setRange(100, 20000)
        self.lagSpin.setSingleStep(100)
        self.lagSpin.setValue(1500)
        self.lagSpin.setSuffix(' ms')
        layout.addRow('Lag duration (freeze time)', self.lagSpin)
        
        # Normal duration - how long connection works normally
        self.normalSpin = QSpinBox(self)
        self.normalSpin.setRange(100, 20000)
        self.normalSpin.setSingleStep(100)
        self.normalSpin.setValue(1500)
        self.normalSpin.setSuffix(' ms')
        layout.addRow('Normal duration (connection time)', self.normalSpin)
        
        # Info label
        from PyQt5.QtWidgets import QLabel
        info = QLabel('Cycles: Block traffic → Wait lag duration → Allow traffic → Wait normal duration → Repeat')
        info.setWordWrap(True)
        info.setStyleSheet('color: gray; font-size: 10px;')
        layout.addRow(info)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def values(self):
        return self.lagSpin.value(), self.normalSpin.value()


class ElmoCut(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.version = '1.1.0'
        self.icon = self.processIcon(app_icon)

        # Add window icon
        self.setWindowIcon(self.icon)
        self.setupUi(self)
        # stylesheet = build_stylesheet('dark_teal.xml', 0, {}, 'theme')
        # self.setStyleSheet(stylesheet)
        self.setStyleSheet(load_stylesheet())
        
        # Main Props
        self.scanner = Scanner()
        self.killer = Killer()
        self.full_kills = set()  # IPs with full kill active
        self.one_way_kills = set()  # MACs with one-way kill active
        self.lag_active = False
        self.lag_block_ms = 1500
        self.lag_release_ms = 1500
        self.lag_device_mac = None
        self.lag_timer = QTimer(self)
        self.lag_timer.setSingleShot(False)
        self.lag_timer.timeout.connect(self._lag_cycle)
        
        # Button active state styles
        self.BUTTON_ACTIVE_STYLE = "background-color: #c0392b; color: white; font-weight: bold;"
        self.BUTTON_NORMAL_STYLE = ""

        # Settings props
        self.minimize = True
        self.remember = False
        self.autoupdate = False  # Disabled - this is a fork

        self.from_tray = False

        # Threading
        self.scan_thread = ScanThread()
        self.scan_thread.thread_finished.connect(self.ScanThread_Reciever)
        self.scan_thread.progress.connect(self.pgbar.setValue)

        # Update thread disabled for fork
        # self.update_thread = UpdateThread()
        # self.update_thread.thread_finished.connect(self.UpdateThread_Reciever)
        
        # Initialize other sub-windows
        self.settings_window = Settings(self, self.icon)
        self.about_window = About(self, self.icon)
        self.device_window = Device(self, self.icon)
        self.traffic_window = Traffic(self, self.icon)

        # Connect buttons with icons and tooltips
        self.buttons = [
            (self.btnScanEasy,   self.scanEasy,      scan_easy_icon,  'ARP Scan - Fast network scan using ARP requests (may miss some devices)'),
            (self.btnScanHard,   self.scanHard,      scan_hard_icon,  'Ping Scan - Thorough scan using ICMP ping (slower but finds all devices)'),
            (self.btnKill,       self.kill,          kill_icon,       'Kill - Block internet access for the selected device'),
            (self.btnUnkill,     self.unkill,        unkill_icon,     'Unkill - Restore internet access for the selected device'),
            (self.btnKillAll,    self.killAll,       killall_icon,    'Kill All - Block internet access for ALL devices on the network'),
            (self.btnUnkillAll,  self.unkillAll,     unkillall_icon,  'Unkill All - Restore internet access for all blocked devices'),
            (self.btnSettings,   self.openSettings,  settings_icon,   'Settings - Configure scan options, interface, and appearance'),
            (self.btnAbout,      self.openAbout,     about_icon,      'About ArpCut - View credits and version info')
        ] 
        
        for btn, btn_func, btn_icon, btn_tip in self.buttons:
            btn.setToolTip(btn_tip)
            btn.clicked.connect(btn_func)
            btn.setIcon(self.processIcon(btn_icon))

        # Additional controls with tooltips - toggleable buttons
        self.btnLagSwitch = QPushButton('Lag Switch', self)
        self.btnLagSwitch.setMinimumHeight(50)
        self.btnLagSwitch.setToolTip('Lag Switch - Create intermittent lag by cycling connection on/off.\nClick to activate, click again to stop.')
        self.gridLayout.addWidget(self.btnLagSwitch, 5, 1, 1, 2)
        self.btnLagSwitch.clicked.connect(self.toggleLagSwitch)

        self.btnFullKill = QPushButton('Full Kill', self)
        self.btnFullKill.setMinimumHeight(50)
        self.btnFullKill.setToolTip('Full Kill - Complete traffic block using system firewall.\nClick to activate, click again to remove.')
        self.gridLayout.addWidget(self.btnFullKill, 5, 3, 1, 2)
        self.btnFullKill.clicked.connect(self.toggleFullKill)

        self.btnOneWayKill = QPushButton('One-Way Kill', self)
        self.btnOneWayKill.setMinimumHeight(50)
        self.btnOneWayKill.setToolTip('One-Way Kill - Block outgoing traffic only (can receive but not send).\nClick to activate, click again to remove.')
        self.gridLayout.addWidget(self.btnOneWayKill, 5, 5, 1, 2)
        self.btnOneWayKill.clicked.connect(self.toggleOneWayKill)

        # "Based on elmoCut" label instead of donate button
        self.lblDonate.setText("Based on elmoCut")
        
        self.pgbar.setVisible(False)

        # Table Widget
        self.tableScan.itemClicked.connect(self.deviceClicked)
        self.tableScan.itemDoubleClicked.connect(self.deviceDoubleClicked)
        self.tableScan.cellClicked.connect(self.cellClicked)
        self.tableScan.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tableScan.customContextMenuRequested.connect(self.table_context_menu)
        self.tableScan.setColumnCount(len(TABLE_HEADER_LABELS))
        self.tableScan.verticalHeader().setVisible(False)
        self.tableScan.setHorizontalHeaderLabels(TABLE_HEADER_LABELS)

        '''
           System tray icon and it's tray menu
        '''
        show_option = QAction('Show', self)
        hide_option = QAction('Hide', self)
        quit_option = QAction('Quit', self)
        kill_option = QAction(self.processIcon(kill_icon), '&Kill All', self)
        unkill_option = QAction(self.processIcon(unkill_icon),'&Unkill All', self)
        
        show_option.triggered.connect(self.trayShowClicked)
        hide_option.triggered.connect(self.hide_all)
        quit_option.triggered.connect(self.quit_all)
        kill_option.triggered.connect(self.killAll)
        unkill_option.triggered.connect(self.unkillAll)
        
        tray_menu = QMenu()
        tray_menu.addAction(show_option)
        tray_menu.addAction(hide_option)
        tray_menu.addSeparator()
        tray_menu.addAction(kill_option)
        tray_menu.addAction(unkill_option)
        tray_menu.addSeparator()
        self.traffic_option = QAction('Traffic for Selected', self)
        self.traffic_option.triggered.connect(self.openTraffic)
        tray_menu.addAction(self.traffic_option)
        tray_menu.addAction(quit_option)
        
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.icon)
        self.tray_icon.setToolTip('ArpCut')
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.tray_clicked)

        # Taskbar button (Windows only)
        self.taskbar_button = None
        self.taskbar_progress = None

        self.applySettings()
    
    @staticmethod
    def processIcon(icon_data):
        """
        Create icon pixmap object from raw data
        """
        pix = QPixmap()
        icon = QIcon()
        pix.loadFromData(icon_data)
        icon.addPixmap(pix)
        return icon
    
    def setImage(self, widget, raw_image):
        pix = QPixmap()
        pix.loadFromData(raw_image)
        widget.setPixmap(pix)
    
    def connected(self, show_msg_box=False):
        """
        Prompt when disconnected
        """
        # If interface is NULL, try to reinitialize
        if self.scanner.iface.name == 'NULL':
            self.scanner.iface = get_default_iface()
            self.scanner.init()
        
        if is_connected(current_iface=self.scanner.iface):
            return True
        self.log('Connection lost!', 'red')
        if show_msg_box:
            QMessageBox.critical(self, 'ArpCut', 'Connection Lost!')
        return False

    def log(self, text, color='white'):
        """
        Print log info at left label
        """
        self.lblleft.setText(f"<font color='{color}'>{text}</font>")
    
    def openSettings(self):
        """
        Open settings window
        """
        self.settings_window.hide()
        self.settings_window.loadInterfaces()
        self.settings_window.currentSettings()
        self.settings_window.show()
        self.settings_window.setWindowState(Qt.WindowNoState)

    def openAbout(self):
        """
        Open about window
        """
        self.about_window.hide()
        self.about_window.show()
        self.about_window.setWindowState(Qt.WindowNoState)

    def openTraffic(self):
        if not self.tableScan.selectedItems():
            self.log('No device selected', 'red')
            return
        device = self.current_index()
        if device['admin']:
            self.log('Admin device', 'orange')
            return
        victim_ip = device['ip']
        iface = self.scanner.iface.name
        self.traffic_window.stop()
        self.traffic_window.start(victim_ip, iface)
        self.traffic_window.hide()
        self.traffic_window.show()
        self.traffic_window.setWindowState(Qt.WindowNoState)

    def table_context_menu(self, pos):
        menu = QMenu(self)
        act_traffic = QAction('Traffic for Selected', self)
        act_probe = QAction('Probe IP…', self)
        act_traffic.triggered.connect(self.openTraffic)
        act_probe.triggered.connect(self.probe_ip)
        menu.addAction(act_traffic)
        menu.addAction(act_probe)
        menu.exec_(self.tableScan.viewport().mapToGlobal(pos))

    def probe_ip(self):
        from PyQt5.QtWidgets import QInputDialog
        ip, ok = QInputDialog.getText(self, 'Probe IP', 'Enter IP to probe:')
        if not ok or not ip:
            return
        self.log(f'Probing {ip}...', 'aqua')
        hit = self.scanner.probe_ip(ip)
        if hit:
            self.log(f'Discovered {hit[0]} {hit[1]}', 'lime')
            self.showDevices()
        else:
            self.log('No response', 'red')

    def applySettings(self):
        """
        Apply saved settings
        """
        self.settings_window.updateElmocutSettings()

    def trayShowClicked(self):
        self.show()
        # Restore window state if was minimized before hidden
        self.setWindowState(Qt.WindowNoState)
        self.activateWindow()

    def tray_clicked(self, event):
        """
        Show elmoCut when tray icon is left-clicked
        """
        if event == QSystemTrayIcon.Trigger:
            self.trayShowClicked()

    def hide_all(self):
        """
        Hide option for tray (Hides window and settings)
        """
        self.hide()
        self.settings_window.hide()
        self.about_window.hide()

    def quit_all(self):
        """
        Unkill any killed device on exit from tray icon
        """
        self.killer.unkill_all()
        self._clear_all_full_kills()
        self.stopLagSwitch()
        self.settings_window.close()
        self.about_window.close()
        self.tray_icon.hide()
        self.from_tray = True
        self.close()

    def showEvent(self, event):
        """
        https://stackoverflow.com/a/60123914/5305953
        Connect TaskBar icon to progressbar
        """
        if QWinTaskbarButton is None:
            return
        self.taskbar_button = QWinTaskbarButton()
        self.taskbar_progress = self.taskbar_button.progress()
        self.taskbar_button.setWindow(self.windowHandle())
        self.pgbar.valueChanged.connect(self.taskbar_progress.setValue)

    def resizeEvent(self, event=True):
        """
        Auto resize table widget columns dynamically
        """
        label_count = len(TABLE_HEADER_LABELS)
        for i in range(label_count):
            self.tableScan.setColumnWidth(i, self.tableScan.width() // label_count)

    def closeEvent(self, event):
        """
        Run in background if self.minimize is True else exit
        """
        self.stopLagSwitch()
        # If event recieved from tray icon
        if self.from_tray:
            event.accept()
            return
        
        # If event is recieved from close X button

        ## If minimize is true
        if self.minimize:
            event.ignore()
            self.hide_all()
            return

        ## If not, ukill all and shutdown
        self.killer.unkill_all()
        self._clear_all_full_kills()
        self.settings_window.close()
        self.about_window.close()

        self.hide()
        self.tray_icon.hide()

        QMessageBox.information(
            self,
            'Shutdown',
            'ArpCut will exit completely.\n\n'
            'Enable minimized from settings\n'
            'to be able to run in background.'
        )

        event.accept()

    def current_index(self):
        return self.scanner.devices[self.tableScan.currentRow()]
    
    def cellClicked(self, row, column):
        """
        Copy selected cell data to clipboard
        """
        # Get current row
        device = self.current_index()

        # Get cell text using dict.values instead of .itemAt()
        cell = list(device.values())[column]
        
        if len(cell) > 20:
            cell = cell[:20] + '...'
        
        self.lblcenter.setText(cell)
        copy(cell)

    def deviceClicked(self):
        """
        Disable kill, unkill buttons when admins are selected.
        Update toggle button states based on selected device.
        """
        not_enabled = not self.current_index()['admin']
        
        self.btnKill.setEnabled(not_enabled)
        self.btnUnkill.setEnabled(not_enabled)
        self.btnFullKill.setEnabled(not_enabled)
        self.btnOneWayKill.setEnabled(not_enabled)
        self.btnLagSwitch.setEnabled(not_enabled)
        
        # Update toggle button visual states for selected device
        self._updateFullKillButtonState()
        self._updateOneWayButtonState()
        self._updateLagSwitchButtonState()
    
    def _updateLagSwitchButtonState(self):
        """Update lag switch button based on whether it's active for selected device."""
        if not self.tableScan.selectedItems():
            return
        device = self.current_index()
        if self.lag_active and self.lag_device_mac == device['mac']:
            self.btnLagSwitch.setText('■ LAGGING')
            self.btnLagSwitch.setStyleSheet(self.BUTTON_ACTIVE_STYLE)
        else:
            self.btnLagSwitch.setText('Lag Switch')
            self.btnLagSwitch.setStyleSheet(self.BUTTON_NORMAL_STYLE)
    
    def deviceDoubleClicked(self):
        """
        Open device info window (when not admin)
        """
        device = self.current_index()
        if device['admin']:
            self.log('Admin device', color='orange')
            return
        
        self.device_window.load(device, self.tableScan.currentRow())
        self.device_window.hide()
        self.device_window.show()
        self.device_window.setWindowState(Qt.WindowNoState)
    
    def fillTableCell(self, row, column, text, colors=[]):
        # Center text in table cell
        ql = QTableWidgetItem()
        ql.setText(text)
        ql.setTextAlignment(Qt.AlignCenter)

        if colors:
            colored_item(ql, *colors)
        
        # Add cell to the specific location
        self.tableScan.setItem(row, column, ql)

    def fillTableRow(self, row, device):
        for column, text in enumerate(device.values()):
            # Skip 'admin' key
            if type(text) == bool:
                continue
            
            # Highlight Admins in green
            if device['admin']:
                self.fillTableCell(
                    row,
                    column,
                    text,
                    ['#00ff00', '#000000']
                )
            else:
                self.fillTableCell(
                    row,
                    column,
                    text,
                    # Highlight killed devices in red else transparent
                    ['#ff0000', '#ffffff'] * (device['mac'] in self.killer.killed)
                )

    def showDevices(self):
        """
        View scanlist devices with correct colors processed
        """
        # Ensure "Me" and "Router" are always shown even if scan hasn't run
        if not self.scanner.devices or not any(d.get('type') == 'Me' for d in self.scanner.devices):
            try:
                self.scanner.add_me()
            except Exception:
                pass
        if not self.scanner.devices or not any(d.get('type') == 'Router' for d in self.scanner.devices):
            try:
                self.scanner.add_router()
            except Exception:
                pass
        
        self.tableScan.clearSelection()
        self.tableScan.clearContents()
        self.tableScan.setRowCount(len(self.scanner.devices))

        for row, device in enumerate(self.scanner.devices):
            self.fillTableRow(row, device)
        
        status = f'{len(self.scanner.devices) - 2} devices' \
                 f' ({len(self.killer.killed)} killed)'
        
        status_tray = f'Devices Found: {len(self.scanner.devices) - 2}\n' \
                      f'Devices Killed: {len(self.killer.killed)}\n' \
                      f'Interface: {self.scanner.iface.name}'
        
        self.lblright.setText(status)
        self.tray_icon.setToolTip(status_tray)

        # Show selected cell data
        self.lblcenter.setText('Nothing Selected')
    
    def processDevices(self):
        """
        Rekill any paused device after scan
        """
        self.tableScan.clearSelection()

        # first device in list is the router
        self.killer.router = self.scanner.router

        # re-kill paused and update to current devices
        self.killer.rekill_stored(self.scanner.devices)
        
        # re-kill saved devices after exit
        for rem_device in self.scanner.devices:
            if rem_device['mac'] in get_settings('killed') * self.remember:
                self.killer.kill(rem_device)

        # clear old database
        self.killer.release()

        self.log(
            f'Found {len(self.scanner.devices) - 2} devices.',
            'orange'
        )

        self.showDevices()

    # @check_connection
    def kill(self):
        """
        Apply ARP spoofing to selected device
        """
        if not self.connected():
            return
        
        if not self.tableScan.selectedItems():
            self.log('No device selected', 'red')
            return

        device = self.current_index()
        
        if device['mac'] in self.killer.killed:
            self.log('Device is already killed', 'red')
            return
        
        # Killing process
        self.killer.kill(device)
        set_settings('killed', list(self.killer.killed) * self.remember)
        self.log('Killed ' + device['ip'], 'fuchsia')
        
        self.showDevices()
    
    # @check_connection
    def unkill(self):
        """
        Disable ARP spoofing on previously spoofed devices.
        Also clears any active one-way kill, full kill, or lag switch.
        """
        self.stopLagSwitch()
        if not self.connected():
            return
        
        if not self.tableScan.selectedItems():
            self.log('No device selected', 'red')
            return

        device = self.current_index()
            
        if device['mac'] not in self.killer.killed:
            self.log('Device is already unkilled', 'red')
            return
        
        # Unkilling process - clear all kill types
        self.killer.unkill(device)
        self._remove_full_kill(device)
        self.one_way_kills.discard(device['mac'])
        set_settings('killed', list(self.killer.killed) * self.remember)
        self.log('Unkilled ' + device['ip'], 'lime')
        
        # Update button states
        self._updateFullKillButtonState()
        self._updateOneWayButtonState()
        self.showDevices()
    
    # @check_connection
    def killAll(self):
        """
        Kill all scanned devices except admins
        """
        self.stopLagSwitch()
        if not self.connected():
            return
        
        self.killer.kill_all(self.scanner.devices)
        set_settings('killed', list(self.killer.killed) * self.remember)
        self.log('Killed All devices', 'fuchsia')

        self.showDevices()

    # @check_connection
    def unkillAll(self):
        """
        Unkill all killed devices except admins.
        Clears all one-way kills, full kills, and lag switches.
        """
        self.stopLagSwitch()
        if not self.connected():
            return
        
        self.killer.unkill_all()
        self._clear_all_full_kills()
        self.one_way_kills.clear()
        set_settings('killed', list(self.killer.killed) * self.remember)
        self.log('Unkilled All devices', 'lime')
        
        # Update button states
        self._updateFullKillButtonState()
        self._updateOneWayButtonState()
        self.showDevices()

    def scanEasy(self):
        """
        Easy Scan button connector
        """
        self.ScanThread_Starter()
    
    def scanHard(self):
        """
        Hard Scan button connector
        """
        # Set correct max for progress bar
        self.ScanThread_Starter(scan_type=1)

    def ScanThread_Starter(self, scan_type=0):
        """
        Scan Thread Starter
        """
        self.stopLagSwitch()
        if not self.connected(show_msg_box=True):
            return

        self.centralwidget.setEnabled(False)
        
        # Save copy of killed devices
        self.killer.store()
        
        self.killer.unkill_all()
        
        self.log(
            ['Arping', 'Pinging'][scan_type] + ' your network...',
            ['aqua', 'fuchsia'][scan_type]
        )
        
        self.pgbar.setVisible(True)
        if self.taskbar_progress:
            self.taskbar_progress.setVisible(True)
        self.pgbar.setMaximum(self.scanner.device_count)
        if self.taskbar_progress:
            self.taskbar_progress.setMaximum(self.scanner.device_count)
        self.pgbar.setValue(self.scanner.device_count * (not scan_type))
        
        self.scan_thread.scanner = self.scanner
        self.scan_thread.scan_type = scan_type
        self.scan_thread.start()

    def ScanThread_Reciever(self):
        """
        Scan Thread results reciever
        """
        self.centralwidget.setEnabled(True)
        self.pgbar.setVisible(False)
        if self.taskbar_progress:
            self.taskbar_progress.setVisible(False)
        self.processDevices()
    
    def UpdateThread_Starter(self):
        """
        Update Thread starter - Disabled for fork
        """
        pass  # Update checking disabled for this fork

    def UpdateThread_Reciever(self):
        """
        Update Thread reciever - Disabled for fork
        """
        pass  # Update checking disabled for this fork
    
    def toggleLagSwitch(self):
        if self.lag_active:
            self.stopLagSwitch()
            return
        if not self.tableScan.selectedItems():
            self.log('No device selected', 'red')
            return
        device = self.current_index()
        if device['admin']:
            self.log('Cannot lag admin device', 'orange')
            return
        dlg = LagSwitchDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        self.lag_block_ms, self.lag_release_ms = dlg.values()
        self.lag_device_mac = device['mac']
        self.lag_active = True
        self.btnLagSwitch.setText('■ LAGGING')
        self.btnLagSwitch.setStyleSheet(self.BUTTON_ACTIVE_STYLE)
        self.log(f'Lag switch ON: {self.lag_block_ms}ms lag / {self.lag_release_ms}ms normal', 'orange')
        self._lag_cycle()
        self.lag_timer.start(self.lag_block_ms + self.lag_release_ms)

    def _lag_cycle(self):
        if not self.lag_active:
            return
        device = self._get_device_by_mac(self.lag_device_mac)
        if not device:
            self.stopLagSwitch()
            return
        self.killer.kill(device)
        QTimer.singleShot(self.lag_block_ms, lambda: self._lag_release(device['mac']))

    def _lag_release(self, mac):
        if not self.lag_active:
            return
        device = self._get_device_by_mac(mac)
        if device and device['mac'] in self.killer.killed:
            self.killer.unkill(device)

    def stopLagSwitch(self):
        if not self.lag_active:
            return
        self.lag_timer.stop()
        device = self._get_device_by_mac(self.lag_device_mac)
        if device and device['mac'] in self.killer.killed:
            self.killer.unkill(device)
        self.lag_active = False
        self.lag_device_mac = None
        self.btnLagSwitch.setText('Lag Switch')
        self.btnLagSwitch.setStyleSheet(self.BUTTON_NORMAL_STYLE)
        self.log('Lag switch OFF', 'lime')

    def toggleOneWayKill(self):
        if not self.connected():
            return
        if not self.tableScan.selectedItems():
            self.log('No device selected', 'red')
            return
        device = self.current_index()
        if device['admin']:
            self.log('Cannot one-way kill admin device', 'orange')
            return
        
        mac = device['mac']
        if mac in self.one_way_kills:
            # Turn OFF - unkill the device
            self.killer.unkill(device)
            self.one_way_kills.discard(mac)
            self._updateOneWayButtonState()
            self.log(f'One-way kill OFF for {device["ip"]}', 'lime')
        else:
            # Turn ON
            self.killer.one_way_kill(device)
            self.one_way_kills.add(mac)
            self._updateOneWayButtonState()
            self.log(f'One-way kill ON for {device["ip"]}', 'orange')

    def _updateOneWayButtonState(self):
        """Update button appearance based on whether selected device has one-way kill."""
        if not self.tableScan.selectedItems():
            self.btnOneWayKill.setText('One-Way Kill')
            self.btnOneWayKill.setStyleSheet(self.BUTTON_NORMAL_STYLE)
            return
        device = self.current_index()
        if device['mac'] in self.one_way_kills:
            self.btnOneWayKill.setText('■ ONE-WAY ON')
            self.btnOneWayKill.setStyleSheet(self.BUTTON_ACTIVE_STYLE)
        else:
            self.btnOneWayKill.setText('One-Way Kill')
            self.btnOneWayKill.setStyleSheet(self.BUTTON_NORMAL_STYLE)

    def toggleFullKill(self):
        if not self.tableScan.selectedItems():
            self.log('No device selected', 'red')
            return
        device = self.current_index()
        if device['admin']:
            self.log('Cannot full kill admin device', 'orange')
            return
        
        victim_ip = device['ip']
        if victim_ip in self.full_kills:
            # Turn OFF
            self._remove_full_kill(device)
            self._updateFullKillButtonState()
            self.log(f'Full kill OFF for {victim_ip}', 'lime')
        else:
            # Turn ON
            iface = self.scanner.iface.name
            if ensure_pf_enabled() and install_anchor() and block_all_for(iface, victim_ip):
                self.full_kills.add(victim_ip)
                self._updateFullKillButtonState()
                self.log(f'Full kill ON for {victim_ip}', 'red')
            else:
                self.killer.kill(device)
                self.full_kills.add(victim_ip)
                self._updateFullKillButtonState()
                self.log('Fallback ARP kill engaged', 'red')

    def _updateFullKillButtonState(self):
        """Update button appearance based on whether selected device has full kill."""
        if not self.tableScan.selectedItems():
            self.btnFullKill.setText('Full Kill')
            self.btnFullKill.setStyleSheet(self.BUTTON_NORMAL_STYLE)
            return
        device = self.current_index()
        if device['ip'] in self.full_kills:
            self.btnFullKill.setText('■ FULL KILL ON')
            self.btnFullKill.setStyleSheet(self.BUTTON_ACTIVE_STYLE)
        else:
            self.btnFullKill.setText('Full Kill')
            self.btnFullKill.setStyleSheet(self.BUTTON_NORMAL_STYLE)

    def _get_device_by_mac(self, mac):
        for device in self.scanner.devices:
            if device['mac'] == mac:
                return device
        return None

    def _remove_full_kill(self, device):
        victim_ip = device['ip']
        if victim_ip in self.full_kills:
            if ensure_pf_enabled() and install_anchor():
                unblock_all_for(victim_ip)
            self.full_kills.discard(victim_ip)

    def _clear_all_full_kills(self):
        if not self.full_kills:
            return
        if ensure_pf_enabled() and install_anchor():
            for ip in list(self.full_kills):
                unblock_all_for(ip)
        self.full_kills.clear()
    
