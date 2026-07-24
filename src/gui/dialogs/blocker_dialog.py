"""Blocker — everything you can block for the selected device, plus presets.

Device-scoped by design: you open it on a device and configure blocks *for that
device*. Three mechanisms:

* **DNS name** (interception) — while the device is MITM'd, its lookup of the name
  is answered with NXDOMAIN. Works even for names with **no IP** (e.g. PSN comms);
  this is the general form of the PSN preset.
* **Port** — a firewall rule dropping a port for the device.
* **Destination IP / domain** — firewall-drops a destination (resolves domains);
  affects devices routed through ArpCut.

All driven through the Controller — never the firewall/engine directly.
"""
from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout, QLineEdit, QSpinBox, QVBoxLayout, QWidget,
)

from gui.dialogs.base import Dialog
from gui.widgets.controls import IconButton, SegmentedControl, ToggleSwitch, hline, label
from networking.hostblock import PRESET_HOSTS

_BLURB = {
    'psn-comms': 'Forces PSN host migration — keeps you host in P2P games.',
    'gta-save': "Blocks Rockstar's save server — GTA Online can't cloud-save.",
}


class BlockerDialog(Dialog):
    def __init__(self, controller, parent=None) -> None:
        super().__init__('Blocker', parent, width=540)
        self.ctrl = controller
        self._target = None
        self._preset_toggles: dict[str, ToggleSwitch] = {}
        self._presets = {p.key: p for p in PRESET_HOSTS}

        self._target_lbl = label('No device selected.', 'title')
        self.content.addWidget(self._target_lbl)

        # --- curated presets ---
        self.content.addWidget(self.section('Curated presets'))
        for preset in PRESET_HOSTS:
            self.content.addWidget(self._preset_row(preset))

        self.content.addWidget(hline())

        # --- block a DNS name (interception, this device) ---
        self.content.addWidget(self.section('Block a DNS name  ·  this device'))
        self.content.addWidget(self.caption(
            'Intercepts the selected device\'s DNS lookup of this name and returns '
            'NXDOMAIN — so it can\'t reach it. Works even for names with no fixed IP '
            '(the PSN preset uses this). One name per add; subdomains are covered.'))
        drow = QHBoxLayout()
        self._dns_edit = QLineEdit()
        self._dns_edit.setPlaceholderText('e.g. np.communication.playstation.net')
        self._dns_edit.returnPressed.connect(self._block_dns)
        dadd = IconButton('plus', 'Block', variant='toolbar')
        dadd.clicked.connect(self._block_dns)
        drow.addWidget(self._dns_edit, 1)
        drow.addWidget(dadd)
        self.content.addLayout(drow)

        self.content.addWidget(hline())

        # --- block a port (this device) ---
        self.content.addWidget(self.section('Block a port  ·  this device'))
        prow = QHBoxLayout()
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(3074)
        self._port.setFixedWidth(90)
        self._proto = SegmentedControl([('tcp', 'TCP'), ('udp', 'UDP')])
        self._proto.set_value('udp')
        pblock = IconButton('plus', 'Block', variant='toolbar')
        pblock.clicked.connect(self._block_port)
        prow.addWidget(self._port)
        prow.addWidget(self._proto)
        prow.addStretch(1)
        prow.addWidget(pblock)
        self.content.addLayout(prow)

        self.content.addWidget(hline())

        # --- block a destination (network-wide) ---
        self.content.addWidget(self.section('Block a destination IP or domain  ·  network-wide'))
        self.content.addWidget(self.caption(
            'Firewall-drops traffic to this address for every device routed through '
            'ArpCut. Domains resolve to their current IPs (public-DNS fallback).'))
        hrow = QHBoxLayout()
        self._host_edit = QLineEdit()
        self._host_edit.setPlaceholderText('e.g. 8.8.8.8  or  matchmaking.example.com')
        self._host_edit.returnPressed.connect(self._block_host)
        hadd = IconButton('plus', 'Block', variant='toolbar')
        hadd.clicked.connect(self._block_host)
        hrow.addWidget(self._host_edit, 1)
        hrow.addWidget(hadd)
        self.content.addLayout(hrow)

        self.content.addWidget(hline())

        # --- active blocks ---
        head = QHBoxLayout()
        head.addWidget(self.section('Active blocks'))
        head.addStretch(1)
        refresh = IconButton('refresh', tooltip='Refresh', size=15, variant='ghost')
        refresh.clicked.connect(self._refresh)
        head.addWidget(refresh)
        self.content.addLayout(head)

        self._active_box = QVBoxLayout()
        self._active_box.setSpacing(6)
        self.content.addLayout(self._active_box)

        controller.host_blocks_changed.connect(lambda _: self._refresh())
        controller.states_changed.connect(self._refresh)
        self._refresh()

    # -- presets -------------------------------------------------------------

    def _preset_row(self, preset) -> QWidget:
        w = QWidget()
        w.setProperty('glass', 'panel')
        w.setMinimumHeight(58)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(12, 8, 12, 8)
        col = QVBoxLayout()
        col.setSpacing(3)
        title = label(preset.label, 'title')
        title.setWordWrap(False)
        note = label(_BLURB.get(preset.key, preset.note), 'muted')
        note.setWordWrap(False)
        note.setToolTip(preset.note)
        col.addWidget(title)
        col.addWidget(note)
        lay.addLayout(col, 1)
        toggle = ToggleSwitch()
        toggle.clicked.connect(lambda on, p=preset: self._toggle_preset(p, on))
        self._preset_toggles[preset.key] = toggle
        lay.addWidget(toggle)
        return w

    def _toggle_preset(self, preset, on: bool) -> None:
        if preset.method == 'dns':
            if not self._require_target('toggle a DNS preset'):
                self._preset_toggles[preset.key].setChecked(False)
                return
            self.ctrl.dns_block(self._target['mac'], preset.domains) if on \
                else self.ctrl.dns_unblock(self._target['mac'])
        else:
            self.ctrl.block_host(preset.key) if on else self.ctrl.unblock_host(preset.key)
        self._refresh()

    # -- target --------------------------------------------------------------

    def set_target(self, device) -> None:
        self._target = device if (device and not device['admin']) else None
        if self._target:
            self._target_lbl.setText(
                f'Configuring: {self._target["ip"]}  ·  {self._target["mac"].lower()}')
        else:
            self._target_lbl.setText('No device selected — pick one for per-device blocks.')
        self._refresh()

    def _require_target(self, what: str) -> bool:
        if self._target:
            return True
        self.ctrl.status.emit(f'Select a device first to {what}.', 'warn')
        return False

    # -- actions -------------------------------------------------------------

    def _block_dns(self) -> None:
        name = self._dns_edit.text().strip()
        if not name or not self._require_target('block a DNS name'):
            return
        self.ctrl.dns_block(self._target['mac'], [name])
        self._dns_edit.clear()
        self._refresh()

    def _block_port(self) -> None:
        target_ip = self._target['ip'] if self._target else None
        self.ctrl.block_port(self._port.value(), self._proto.value(), 'both', target_ip)
        self._refresh()

    def _block_host(self) -> None:
        text = self._host_edit.text().strip()
        if text:
            self.ctrl.block_host(text)
            self._host_edit.clear()

    # -- active list ---------------------------------------------------------

    def _refresh(self) -> None:
        active_hosts = self.ctrl.active_host_blocks()
        target_mac = self._target['mac'] if self._target else None
        for key, toggle in self._preset_toggles.items():
            preset = self._presets[key]
            checked = (bool(target_mac and self.ctrl.is_dns_blocked(target_mac))
                       if preset.method == 'dns' else key in active_hosts)
            toggle.blockSignals(True)
            toggle.setChecked(checked)
            toggle.blockSignals(False)

        while self._active_box.count():
            item = self._active_box.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
                w.deleteLater()

        empty = True
        for key, ips in active_hosts.items():
            empty = False
            self._active_box.addWidget(self._active_row(
                f'{key}  ({len(ips)} IP{"s" * (len(ips) != 1)})',
                lambda k=key: self.ctrl.unblock_host(k)))
        for ip, names in self.ctrl.active_dns_blocks().items():
            empty = False
            n = len(names)
            self._active_box.addWidget(self._active_row(
                f'DNS · {ip}  ({n} name{"s" * (n != 1)})',
                lambda i=ip: (self.ctrl.stop_dns_block_ip(i), self._refresh())))
        for port, proto, direction in self.ctrl.list_blocked_ports():
            empty = False
            self._active_box.addWidget(self._active_row(
                f'port {port}/{proto} · {direction}',
                lambda p=port, pr=proto: (self.ctrl.unblock_port(p, pr), self._refresh())))
        for ip, direction in self.ctrl.list_blocked_ips():
            empty = False
            self._active_box.addWidget(self._active_row(
                f'{ip} · {direction}',
                lambda i=ip: (self.ctrl.unblock_ip(i), self._refresh())))
        if empty:
            self._active_box.addWidget(self.caption('Nothing blocked.'))

    def _active_row(self, text: str, on_remove) -> QWidget:
        w = QWidget()
        w.setProperty('glass', 'panel')
        lay = QHBoxLayout(w)
        lay.setContentsMargins(12, 7, 8, 7)
        lay.addWidget(label(text, 'body'), 1)
        rm = IconButton('close', tooltip='Remove', size=14, variant='ghost')
        rm.clicked.connect(lambda: on_remove())
        lay.addWidget(rm)
        return w
