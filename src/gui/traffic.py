from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem, QPushButton
from PyQt5.QtCore import Qt, QTimer

from networking.sniffer import TrafficSniffer
from networking.forwarder import MitmForwarder
from tools.pfctl import ensure_pf_enabled, install_anchor, block_dst, unblock_dst, export_rules, import_rules, is_blocked, pf_self_check, list_rules
from ui.ui_traffic import Ui_Traffic


class Traffic(QMainWindow):
    def __init__(self, parent, icon):
        super().__init__()
        self.parent = parent
        self.icon = icon
        self.setWindowIcon(icon)
        self.ui = Ui_Traffic()
        self.ui.setupUi(self)
        self.sniffer = TrafficSniffer()
        self.forwarder = MitmForwarder()
        self.flows = {}
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh)

        # Wire UI buttons
        self.ui.btnBlock.clicked.connect(self.block_selected)
        self.ui.btnUnblock.clicked.connect(self.unblock_selected)
        self.ui.btnExport.clicked.connect(self.export_rules)
        self.ui.btnImport.clicked.connect(self.import_rules)
        self.ui.btnPFTest.clicked.connect(self.pf_test)
        self.ui.patterns.itemSelectionChanged.connect(self.on_pattern_selected)
        self.ui.btnBlockPattern.clicked.connect(self.block_pattern)
        self.ui.btnUnblockPattern.clicked.connect(self.unblock_pattern)
        self.ui.btnForward = None
        self.ui.chkForward.stateChanged.connect(self.toggle_forward)
        # Add a simple toggle button in mode label area by reusing text as action hint

    def start(self, victim_ip: str, iface: str):
        self.ui.lblVictim.setText(victim_ip)
        # Observe-only message when not root
        try:
            import os
            is_root = (getattr(os, 'geteuid', lambda: 0)() == 0)
        except Exception:
            is_root = True
        if not is_root:
            self.ui.lblMode.setText('Observe-only (run as root for live capture and blocking)')
            self.ui.btnBlock.setEnabled(False)
            self.ui.btnUnblock.setEnabled(False)
        else:
            ok = pf_self_check()
            import sys
            if sys.platform.startswith('win'):
                self.ui.lblMode.setText('Active mode (Windows Firewall)' if ok else 'Windows Firewall not accessible')
            else:
                self.ui.lblMode.setText('Active mode' if ok else 'PF not enabled; run: sudo pfctl -E')
            self.ui.btnBlock.setEnabled(True)
            self.ui.btnUnblock.setEnabled(True)
        self.sniffer.start(victim_ip, iface, on_update=self.schedule_refresh)
        self.timer.start()
        # Do not auto-start forwarder here; user controls it via "Forward Mode" toggle

    def stop(self):
        self.timer.stop()
        self.sniffer.stop()
        self.forwarder.stop()

    def schedule_refresh(self):
        # Coalesce frequent updates
        if not self.timer.isActive():
            self.timer.start()

    def refresh(self):
        self.flows = self.sniffer.get_flows()
        rows = list(self.flows.items())
        self.ui.table.setRowCount(len(rows))
        for row, ((dst_ip, port, proto), stats) in enumerate(rows):
            self._set(row, 0, dst_ip)
            self._set(row, 1, str(port))
            self._set(row, 2, proto)
            self._set(row, 3, str(stats['packets']))
            self._set(row, 4, str(stats['bytes']))
        # Update preview with last packet
        layers = self.sniffer.get_last_packet_layers()
        hexview = self.sniffer.get_last_packet_hex()
        lines = []
        if 'ip' in layers:
            lines.append(f"IP {layers['ip']}")
        if 'tcp' in layers:
            lines.append(f"TCP {layers['tcp']}")
        if 'udp' in layers:
            lines.append(f"UDP {layers['udp']}")
        if 'payload' in layers:
            lines.append(f"PAYLOAD bytes={layers['payload']['length']}\n{layers['payload']['text']}")
        lines.append(hexview)
        self.ui.preview.setPlainText('\n'.join(lines))
        # Show simple blocked indicator in title
        try:
            row = self.ui.table.currentRow()
            if row >= 0:
                dst = self.ui.table.item(row, 0).text()
                self.setWindowTitle('Traffic - BLOCKED' if is_blocked(dst) else 'Traffic')
        except Exception:
            pass

        # Update patterns aggregation table
        patterns = self.sniffer.get_patterns()
        prowlist = list(patterns.items())
        self.ui.patterns.setRowCount(len(prowlist))
        for i, ((proto, port, bucket), stats) in enumerate(prowlist):
            self._set_pattern(i, 0, proto)
            self._set_pattern(i, 1, str(port))
            self._set_pattern(i, 2, str(bucket))
            self._set_pattern(i, 3, str(stats['packets']))
        # Refresh samples view for selected pattern
        self.on_pattern_selected()

    def _set(self, row, col, text):
        item = QTableWidgetItem()
        item.setText(text)
        item.setTextAlignment(Qt.AlignCenter)
        self.ui.table.setItem(row, col, item)

    def _set_pattern(self, row, col, text):
        item = QTableWidgetItem()
        item.setText(text)
        item.setTextAlignment(Qt.AlignCenter)
        self.ui.patterns.setItem(row, col, item)

    def on_pattern_selected(self):
        row = self.ui.patterns.currentRow()
        if row < 0:
            self.ui.pattern_samples.setRowCount(0)
            return
        proto = self.ui.patterns.item(row, 0).text()
        port = int(self.ui.patterns.item(row, 1).text())
        bucket = int(self.ui.patterns.item(row, 2).text())
        samples = self.sniffer.get_pattern_samples((proto, port, bucket))
        self.ui.pattern_samples.setRowCount(len(samples))
        for i, s in enumerate(samples):
            self._set_sample(i, 0, s['time'])
            self._set_sample(i, 1, s['dst'])
            self._set_sample(i, 2, str(s['length']))
            self._set_sample(i, 3, s['preview'])

    def _set_sample(self, row, col, text):
        item = QTableWidgetItem()
        item.setText(text)
        item.setTextAlignment(Qt.AlignLeft if col == 3 else Qt.AlignCenter)
        self.ui.pattern_samples.setItem(row, col, item)

    def selected_flow(self):
        row = self.ui.table.currentRow()
        if row < 0:
            return None
        dst = self.ui.table.item(row, 0).text()
        port = int(self.ui.table.item(row, 1).text())
        proto = self.ui.table.item(row, 2).text()
        return dst, port, proto

    def block_selected(self):
        target = self.selected_flow()
        if not target:
            return
        dst, port, proto = target
        victim = self.ui.lblVictim.text()
        iface = self.parent.scanner.iface.name
        if ensure_pf_enabled() and install_anchor():
            use_port = self.ui.chkIncludePort.isChecked()
            ok = block_dst(iface, victim, dst, port=(port if use_port else None), proto=proto)
            self.parent.log(('Blocked ' if ok else 'Failed blocking ') + dst, 'fuchsia' if ok else 'red')

    def unblock_selected(self):
        target = self.selected_flow()
        if not target:
            return
        dst, port, _ = target
        use_port = self.ui.chkIncludePort.isChecked()
        ok = unblock_dst(dst, port=(port if use_port else None))
        self.parent.log(('Unblocked ' if ok else 'Failed unblocking ') + dst, 'lime' if ok else 'red')

    def export_rules(self):
        from PyQt5.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(self, 'Export Rules', filter='PF Rules (*.rules);;All Files (*)')
        if path:
            export_rules(path)

    def import_rules(self):
        from PyQt5.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(self, 'Import Rules', filter='PF Rules (*.rules);;All Files (*)')
        if path:
            import_rules(path)

    def pf_test(self):
        iface = self.parent.scanner.iface.name
        victim = self.ui.lblVictim.text()
        from tools.pfctl import pf_test_roundtrip
        ok = pf_test_roundtrip(iface, victim)
        self.parent.log('PF Test: ' + ('OK' if ok else 'FAILED'), 'lime' if ok else 'red')

    def toggle_forward(self, _state):
        if self.ui.chkForward.isChecked():
            # Check if killer already has a forwarder for this victim
            victim_ip = self.ui.lblVictim.text()
            victim = next((d for d in self.parent.scanner.devices if d.get('ip') == victim_ip), None)
            if victim and victim.get('mac') in self.parent.killer.forwarders:
                self.parent.log('Forwarder already active via One-Way Kill', 'orange')
                return
            # Restart forwarder with current victim (observe-only, no drops)
            iface = self.parent.scanner.iface.guid or self.parent.scanner.iface.name
            v = victim or {'ip': victim_ip, 'mac': ''}
            r = {'ip': self.parent.scanner.router['ip'], 'mac': self.parent.scanner.router['mac']}
            iface_mac = self.parent.scanner.my_mac
            self.forwarder.start(v, r, iface, iface_mac, drop_from_victim=False, drop_to_victim=False)
            self.parent.log('Forward mode ON (observe only)', 'aqua')
        else:
            self.forwarder.stop()
            self.parent.log('Forward mode OFF', 'orange')

    def block_pattern(self):
        row = self.ui.patterns.currentRow()
        if row < 0:
            return
        proto = self.ui.patterns.item(row, 0).text()
        port = int(self.ui.patterns.item(row, 1).text())
        victim = self.ui.lblVictim.text()
        iface = self.parent.scanner.iface.name
        if ensure_pf_enabled() and install_anchor():
            ok = block_dst(iface, victim, 'any', port=port, proto=proto)
            self.parent.log(('Blocked pattern port ' if ok else 'Failed blocking pattern port ') + str(port), 'fuchsia' if ok else 'red')

    def unblock_pattern(self):
        row = self.ui.patterns.currentRow()
        if row < 0:
            return
        port = int(self.ui.patterns.item(row, 1).text())
        ok = unblock_dst('any', port=port)
        self.parent.log(('Unblocked pattern port ' if ok else 'Failed unblocking pattern port ') + str(port), 'lime' if ok else 'red')


