"""MainWindow — presentation only. Renders controller state, emits user intent.

Device-centric: a scrollable list of device cards, one primary Cut per card, and
a selection-driven action bar for advanced actions. A glass privilege banner with
a real "Set Up Access" button replaces silent failure. No packet/firewall logic
here — all of that lives in the Controller.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox,
    QProgressBar, QPushButton, QScrollArea, QSystemTrayIcon, QVBoxLayout, QWidget,
)

from gui import icons
from gui.controller import Controller
from gui.theme import THEME, retheme
from gui.widgets.controls import IconButton, label
from gui.widgets.device_row import DeviceRow, display_name
from gui.widgets.glass import GlassWindow
from gui.widgets.titlebar import TitleBar
from tools.utils_gui import get_settings, set_settings


class MainWindow(GlassWindow):
    def __init__(self, controller: Controller) -> None:
        super().__init__()
        self.ctrl = controller
        self.setWindowTitle('ArpCut')
        self.setWindowIcon(icons.app_icon())
        self.resize(780, 640)
        self.setMinimumSize(560, 470)

        self._rows: dict[str, DeviceRow] = {}
        self._selected: str | None = None
        self._dialogs: dict[str, QWidget] = {}
        self._quitting = False
        self._is_admin = True
        self._onboarded = False

        self._build_titlebar()
        self._build_toolbar()
        self._build_banner()
        self._build_list()
        self._build_actionbar()
        self._build_statusbar()
        self._build_tray()

        c = self.ctrl
        c.devices_changed.connect(self._on_devices)
        c.states_changed.connect(self._refresh_states)
        c.status.connect(self._on_status)
        c.scan_started.connect(self._on_scan_started)
        c.scan_progress.connect(self._on_scan_progress)
        c.scan_finished.connect(self._on_scan_finished)
        c.privilege_changed.connect(self._on_privilege)
        c.host_blocks_changed.connect(lambda _: self._refresh_states())

    # -- construction --------------------------------------------------------

    def _content(self) -> QVBoxLayout:
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(16, 0, 16, 14)
        lay.setSpacing(12)
        self.body.addWidget(wrap)
        return lay

    def _build_titlebar(self) -> None:
        self.titlebar = TitleBar(self, title='ArpCut', logo=True)
        self._theme_btn = IconButton('moon' if THEME.name == 'dark' else 'sun',
                                     tooltip='Toggle light / dark', variant='toolbar')
        self._theme_btn.clicked.connect(self._toggle_theme)
        self.titlebar.add_right(self._theme_btn)
        self.body.addWidget(self.titlebar)
        self._root_lay = self._content()

    def _build_toolbar(self) -> None:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self._scan_btn = IconButton('scan', 'Scan', 'Fast ARP scan', variant='toolbar')
        self._scan_btn.clicked.connect(lambda: self.ctrl.scan(0))
        self._deep_btn = IconButton('deepscan', 'Deep', 'Thorough ping sweep', variant='toolbar')
        self._deep_btn.clicked.connect(lambda: self.ctrl.scan(1))
        bar.addWidget(self._scan_btn)
        bar.addWidget(self._deep_btn)

        self._search = QLineEdit()
        self._search.setPlaceholderText('Filter devices…')
        self._search.setClearButtonEnabled(True)
        self._search.addAction(icons.icon('search', THEME.text_faint, 16), QLineEdit.LeadingPosition)
        self._search.textChanged.connect(self._apply_filter)
        bar.addWidget(self._search, 1)

        restore = IconButton('restore', 'Restore All', 'Restore every device', variant='toolbar')
        restore.clicked.connect(self.ctrl.unkill_all)
        cut_all = IconButton('killall', 'Cut All', 'Cut every device', variant='solid')
        cut_all.set_active(True, 'danger')
        cut_all.clicked.connect(self._confirm_cut_all)
        settings = IconButton('settings', tooltip='Settings', variant='toolbar')
        settings.clicked.connect(lambda: self._open('settings'))
        about = IconButton('info', tooltip='About ArpCut', variant='toolbar')
        about.clicked.connect(lambda: self._open('about'))
        bar.addWidget(restore)
        bar.addWidget(cut_all)
        bar.addWidget(settings)
        bar.addWidget(about)
        self._root_lay.addLayout(bar)

        self._progress = QProgressBar()
        self._progress.setObjectName('ScanBar')
        self._progress.setFixedHeight(3)
        self._progress.setTextVisible(False)
        self._progress.hide()
        self._root_lay.addWidget(self._progress)

    def _build_banner(self) -> None:
        self._banner = QFrame()
        self._banner.setObjectName('Banner')
        self._banner.setProperty('tone', 'warn')
        lay = QHBoxLayout(self._banner)
        lay.setContentsMargins(14, 11, 12, 11)
        lay.setSpacing(11)
        self._banner_icon = QLabel()
        self._banner_icon.setProperty('role', 'bannerIcon')
        lay.addWidget(self._banner_icon, 0, Qt.AlignTop)
        self._banner_text = label('', 'banner')
        self._banner_text.setWordWrap(True)
        lay.addWidget(self._banner_text, 1)
        self._banner_btn = QPushButton('Set Up Access')
        self._banner_btn.setProperty('accent', 'primary')
        self._banner_btn.setCursor(Qt.PointingHandCursor)
        self._banner_btn.clicked.connect(self._open_privilege)
        lay.addWidget(self._banner_btn, 0, Qt.AlignVCenter)
        self._banner.hide()
        self._root_lay.addWidget(self._banner)

    def _build_list(self) -> None:
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        holder = QWidget()
        self._list = QVBoxLayout(holder)
        self._list.setContentsMargins(0, 0, 4, 0)
        self._list.setSpacing(8)
        self._list.addStretch(1)
        self._scroll.setWidget(holder)
        self._root_lay.addWidget(self._scroll, 1)

    def _build_actionbar(self) -> None:
        self._actionbar = QWidget()
        self._actionbar.setProperty('glass', 'panel')
        lay = QHBoxLayout(self._actionbar)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(6)
        self._action_title = label('', 'title')
        lay.addWidget(self._action_title)
        lay.addStretch(1)

        def act(glyph, text, tip, slot):
            b = IconButton(glyph, text, tip, size=16, variant='ghost')
            b.clicked.connect(slot)
            lay.addWidget(b)
            return b

        self._a_oneway = act('oneway', 'One-way', 'Block only the device\'s outbound traffic',
                             lambda: self._on_selected(self.ctrl.toggle_one_way))
        self._a_lag = act('lag', 'Lag', 'Intermittent lag switch', self._open_lag)
        self._a_block = act('port', 'Blocker', 'Block specific ports / hosts (PSN, GTA…)',
                            self._open_blocker)
        self._a_traffic = act('traffic', 'Traffic', 'Live traffic monitor', self._open_traffic)
        self._a_info = act('info', '', 'Device details', self._open_device)
        self._actionbar.hide()
        self._root_lay.addWidget(self._actionbar)

    def _build_statusbar(self) -> None:
        bar = QHBoxLayout()
        self._status = QLabel('Ready.')
        self._status.setObjectName('StatusLine')
        self._count = label('', 'faint')
        bar.addWidget(self._status, 1)
        bar.addWidget(self._count)
        self._root_lay.addLayout(bar)

    def _build_tray(self) -> None:
        self._tray = QSystemTrayIcon(icons.app_icon(), self)
        self._tray.setToolTip('ArpCut')
        menu = QMenu()
        menu.addAction(QAction('Show ArpCut', self, triggered=self._restore_window))
        menu.addSeparator()
        menu.addAction(QAction('Cut All', self, triggered=self.ctrl.kill_all))
        menu.addAction(QAction('Restore All', self, triggered=self.ctrl.unkill_all))
        menu.addSeparator()
        menu.addAction(QAction('Quit', self, triggered=self._real_quit))
        self._tray.setContextMenu(menu)
        self._tray.activated.connect(
            lambda r: self._restore_window() if r == QSystemTrayIcon.Trigger else None)
        self._tray.show()

    # -- controller signal handlers -----------------------------------------

    def _on_devices(self, devices: list) -> None:
        macs = {d['mac'] for d in devices}
        for mac in list(self._rows):
            if mac not in macs:
                self._rows.pop(mac).deleteLater()
        for i in reversed(range(self._list.count() - 1)):
            item = self._list.takeAt(i)
            if item.widget():
                item.widget().setParent(None)
        for device in devices:
            row = self._rows.get(device['mac'])
            if row is None or row.device['ip'] != device['ip']:
                if row:
                    row.deleteLater()
                row = DeviceRow(device)
                row.clicked.connect(self._select)
                row.activated.connect(lambda m: self._open_device())
                row.cut_toggled.connect(self.ctrl.toggle_cut)
                row.spoof_toggled.connect(self._on_spoof_toggled)
                self._rows[device['mac']] = row
            else:
                row.device = device
            self._list.insertWidget(self._list.count() - 1, row)
        self._refresh_states()
        self._apply_filter(self._search.text())
        self._update_count()

    def _on_spoof_toggled(self, mac: str) -> None:
        """Toggle routing-through-us. Turning it OFF while blocks depend on it
        warns first and clears them on confirm (keeps them on decline)."""
        if self.ctrl.is_spoofed(mac):
            blocks = self.ctrl.device_blocks(mac)
            if blocks:
                from PySide6.QtWidgets import QMessageBox
                resp = QMessageBox.warning(
                    self, 'Stop routing this device?',
                    'This device has active effects that need it routed through '
                    'your PC:\n\n  • ' + '\n  • '.join(blocks) + '\n\n'
                    'Stopping the spoof will clear them. Continue?',
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                if resp != QMessageBox.Yes:
                    self._refresh_states()          # re-sync the toggle we bounced
                    return
        self.ctrl.toggle_spoof(mac)

    def _refresh_states(self) -> None:
        for mac, row in self._rows.items():
            device = self.ctrl.device_by_mac(mac)
            if device:
                row.set_state(self.ctrl.state_of(device))
        self._update_actionbar()
        self._update_count()

    def _on_status(self, message: str, level: str) -> None:
        self._status.setText(message)
        self._status.setProperty('level', level if level in
                                 ('danger', 'good', 'warn', 'accent') else None)
        self._status.style().unpolish(self._status)
        self._status.style().polish(self._status)

    def _on_scan_started(self, scan_type: int) -> None:
        self._progress.show()
        self._progress.setRange(0, 0) if scan_type == 0 else self._progress.setRange(0, 100)
        self._scan_btn.setEnabled(False)
        self._deep_btn.setEnabled(False)

    def _on_scan_progress(self, done: int, total: int) -> None:
        if total:
            self._progress.setRange(0, total)
            self._progress.setValue(done)

    def _on_scan_finished(self, _completed: bool) -> None:
        self._progress.hide()
        self._scan_btn.setEnabled(True)
        self._deep_btn.setEnabled(True)

    def _on_privilege(self, admin: bool, iface: str) -> None:
        self._is_admin = admin
        if admin:
            self._banner.hide()
        else:
            self._banner_text.setText(
                'ArpCut needs administrator access to scan and cut devices. '
                'You can still ping-scan for now — set up access to unlock full power.')
            self._paint_banner()
            self._banner.show()
            self._maybe_onboard()
        self._update_count()

    def _maybe_onboard(self) -> None:
        """First-run: in the packaged app, guide the user through Set Up Access
        once. Dev runs just show the banner button (no interruption)."""
        import sys
        if self._onboarded:
            return
        self._onboarded = True
        if getattr(sys, 'frozen', False):
            self._open_privilege()

    def _paint_banner(self) -> None:
        self._banner_icon.setPixmap(icons.pixmap('lock', THEME.warn, 18))

    # -- selection & action bar ---------------------------------------------

    def _select(self, mac: str) -> None:
        self._selected = mac
        for m, row in self._rows.items():
            row.set_selected(m == mac)
        self._update_actionbar()

    def _selected_device(self):
        return self.ctrl.device_by_mac(self._selected) if self._selected else None

    def _on_selected(self, fn) -> None:
        if self._selected:
            fn(self._selected)

    def _update_actionbar(self) -> None:
        device = self._selected_device()
        if not device or device['admin']:
            self._actionbar.hide()
            return
        state = self.ctrl.state_of(device)
        self._action_title.setText(display_name(device))
        self._a_oneway.set_active(state['one_way'], 'warn')
        self._a_lag.set_active(state['lag'], 'warn')
        self._actionbar.show()

    def _update_count(self) -> None:
        n = max(0, len(self._rows) - 2)
        cut = len(self.ctrl.full_kills)
        iface = self.ctrl.iface_name()
        lock = '' if self._is_admin else '  ·  no admin'
        self._count.setText(f'{n} devices · {cut} cut · {iface}{lock}')

    def _apply_filter(self, text: str) -> None:
        text = text.strip().lower()
        for mac, row in self._rows.items():
            device = self.ctrl.device_by_mac(mac) or row.device
            hay = f'{display_name(device)} {device["ip"]} {device["mac"]} {device.get("vendor","")}'.lower()
            row.setVisible(text in hay)

    # -- dialogs -------------------------------------------------------------

    def _open(self, name: str) -> None:
        dlg = self._dialogs.get(name)
        if dlg is None:
            dlg = self._make_dialog(name)
            self._dialogs[name] = dlg
        dlg.show(); dlg.raise_(); dlg.activateWindow()

    def _make_dialog(self, name: str):
        if name == 'settings':
            from gui.dialogs.settings_dialog import SettingsDialog
            return SettingsDialog(self.ctrl, self)
        if name == 'about':
            from gui.dialogs.about_dialog import AboutDialog
            return AboutDialog(self)
        if name == 'privilege':
            from gui.dialogs.privilege_dialog import PrivilegeDialog
            return PrivilegeDialog(self.ctrl, self)
        raise KeyError(name)

    def _open_privilege(self) -> None:
        self._open('privilege')

    def _open_blocker(self) -> None:
        from gui.dialogs.blocker_dialog import BlockerDialog
        dlg = self._dialogs.get('blocker')
        if dlg is None:
            dlg = BlockerDialog(self.ctrl, self)
            self._dialogs['blocker'] = dlg
        dlg.set_target(self._selected_device())
        dlg.show(); dlg.raise_(); dlg.activateWindow()

    def _open_traffic(self) -> None:
        device = self._selected_device()
        if not device:
            return
        from gui.dialogs.traffic_dialog import TrafficDialog
        dlg = self._dialogs.get('traffic')
        if dlg is None:
            dlg = TrafficDialog(self.ctrl, self)
            self._dialogs['traffic'] = dlg
        dlg.start(device)
        dlg.show(); dlg.raise_(); dlg.activateWindow()

    def _open_device(self) -> None:
        device = self._selected_device()
        if not device:
            return
        from gui.dialogs.device_dialog import DeviceDialog
        DeviceDialog(self.ctrl, device, self).exec()

    def _open_lag(self) -> None:
        device = self._selected_device()
        if not device:
            return
        from gui.dialogs.lag_dialog import LagDialog
        if self.ctrl.lag_active_for(device['mac']):
            self.ctrl.stop_lag()
            return
        dlg = LagDialog(self)
        if dlg.exec():
            block_ms, release_ms, direction = dlg.values()
            self.ctrl.start_lag(device['mac'], block_ms, release_ms, direction)

    def _confirm_cut_all(self) -> None:
        if QMessageBox.question(self, 'Cut All',
                                'Cut every non-admin device off the network?') == QMessageBox.Yes:
            self.ctrl.kill_all()

    # -- theme ---------------------------------------------------------------

    def _toggle_theme(self) -> None:
        dark = THEME.name != 'dark'
        set_settings('dark', dark)
        retheme(QApplication.instance(), dark)

    def on_theme_changed(self) -> None:
        super().on_theme_changed()
        self._theme_btn.set_glyph('moon' if THEME.name == 'dark' else 'sun')
        self._paint_banner()

    # -- window lifecycle ----------------------------------------------------

    def _restore_window(self) -> None:
        self.showNormal(); self.raise_(); self.activateWindow()

    def _real_quit(self) -> None:
        self._quitting = True
        self.close()

    def closeEvent(self, event) -> None:
        minimized = bool(get_settings('minimized'))
        if minimized and not self._quitting:
            event.ignore()
            self.hide()
            self._tray.showMessage('ArpCut', 'Still running in the menu bar.',
                                   QSystemTrayIcon.Information, 2000)
            return
        self.ctrl.shutdown()
        self._tray.hide()
        event.accept()
        QApplication.instance().quit()
