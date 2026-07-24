"""Device details + nickname editor."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPushButton

from gui import icons
from gui.dialogs.base import Dialog
from gui.theme import THEME
from gui.widgets.controls import label
from gui.widgets.device_row import display_name


class DeviceDialog(Dialog):
    def __init__(self, controller, device: dict, parent=None) -> None:
        super().__init__('Device', parent, width=400)
        self.ctrl = controller
        self.device = device

        header = QHBoxLayout()
        badge = QLabel()
        badge.setPixmap(icons.pixmap(icons.device_glyph(device['type']), THEME.accent, 30))
        header.addWidget(badge)
        header.addWidget(label(display_name(device), 'hero'), 1)
        self.content.addLayout(header)

        for field, value in (('IP address', device['ip']),
                             ('MAC address', device['mac'].lower()),
                             ('Vendor', device.get('vendor') or 'Unknown'),
                             ('Type', device['type'])):
            self.content.addLayout(self._info(field, value))

        self.content.addWidget(self.section('Nickname'))
        edit_row = QHBoxLayout()
        self._nick = QLineEdit(device.get('name', '') if device.get('name') != '-' else '')
        self._nick.setPlaceholderText('Give this device a friendly name')
        self._nick.returnPressed.connect(self._save)
        save = QPushButton('Save')
        save.setProperty('accent', 'primary')
        save.clicked.connect(self._save)
        edit_row.addWidget(self._nick, 1)
        edit_row.addWidget(save)
        self.content.addLayout(edit_row)

    def _info(self, name: str, value: str):
        row = QHBoxLayout()
        v = label(value, 'value')
        v.setTextInteractionFlags(v.textInteractionFlags() | Qt.TextSelectableByMouse)
        row.addWidget(label(name, 'muted'))
        row.addStretch(1)
        row.addWidget(v)
        return row

    def _save(self) -> None:
        self.ctrl.set_nickname(self.device['mac'], self._nick.text())
        self.accept()
