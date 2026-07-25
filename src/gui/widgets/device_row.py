"""Device card — one row per device in the device-centric list.

Renders a device (icon badge, name/vendor, IP/MAC, live state chips) and a
primary Cut toggle. Colors come from the global QSS (role/object selectors) and
live ``THEME`` reads in the badge's ``paintEvent``, so a theme switch repaints it.
"""
from __future__ import annotations

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout, QFrame, QWidget

from gui import icons
from gui.theme import THEME
from gui.widgets.controls import Chip, IconButton, label


def display_name(device: dict) -> str:
    if device['type'] == 'Me':
        return 'This Mac'
    if device['type'] == 'Router':
        return 'Router / Gateway'
    name = device.get('name', '-')
    if name and name != '-':
        return name
    vendor = device.get('vendor', '')
    if vendor and vendor not in ('NONE', 'Unknown', ''):
        return vendor
    return 'Unknown device'


class _Badge(QWidget):
    """Rounded tinted badge with a device glyph — painted live from THEME."""

    def __init__(self, glyph: str, tone: str) -> None:
        super().__init__()
        self.setFixedSize(42, 42)
        self._glyph = glyph
        self._tone = tone

    def set_look(self, glyph: str, tone: str) -> None:
        self._glyph, self._tone = glyph, tone
        self.update()

    def paintEvent(self, _e) -> None:
        t = THEME
        color = getattr(t, self._tone)
        tint = t.qcolor(getattr(t, f'{self._tone}_tint'))
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(tint)
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(QRectF(0, 0, 42, 42), 12, 12)
        p.drawPixmap(10, 10, icons.pixmap(self._glyph, color, 22))


class DeviceRow(QFrame):
    clicked = Signal(str)
    activated = Signal(str)
    cut_toggled = Signal(str)
    spoof_toggled = Signal(str)

    def __init__(self, device: dict, parent: QWidget = None) -> None:
        super().__init__(parent)
        self.device = device
        self.mac = device['mac']
        self.admin = device['admin']
        self.setObjectName('DeviceRow')
        self.setProperty('selected', False)
        self.setCursor(Qt.PointingHandCursor)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(12)

        self._badge = _Badge(icons.device_glyph(device['type']), self._type_tone())
        lay.addWidget(self._badge)

        text = QVBoxLayout()
        text.setSpacing(2)
        self._name = label(display_name(device), 'title')
        self._sub = label(self._subtitle(), 'subtitle')
        text.addWidget(self._name)
        text.addWidget(self._sub)
        lay.addLayout(text)
        lay.addStretch(1)

        self._chips = QHBoxLayout()
        self._chips.setSpacing(6)
        lay.addLayout(self._chips)

        if self.admin:
            lay.addWidget(label('YOU' if device['type'] == 'Me' else 'GATEWAY', 'tag'))
            self._cut = None
            self._spoof = None
        else:
            # Spoof = route this device through us (no drop). It's the prerequisite
            # for blockers/lag/monitor; those auto-enable it, and it can be toggled
            # here directly so you can see when traffic is being routed.
            self._spoof = IconButton('wifi', text='Spoof',
                                     tooltip='Route this device through your PC '
                                             '(required for blockers, lag, monitor)',
                                     checkable=True, variant='ghost')
            self._spoof.setMinimumWidth(90)
            self._spoof.clicked.connect(lambda: self.spoof_toggled.emit(self.mac))
            lay.addWidget(self._spoof)

            self._cut = IconButton('cut', text='Cut',
                                   tooltip='Cut this device off the internet '
                                           '(ARP redirect + firewall drop)',
                                   checkable=True, variant='ghost')
            self._cut.setMinimumWidth(84)
            self._cut.clicked.connect(lambda: self.cut_toggled.emit(self.mac))
            lay.addWidget(self._cut)

    def _subtitle(self) -> str:
        return f'{self.device["ip"]}  ·  {self.device["mac"].lower()}'

    def _type_tone(self) -> str:
        return {'Me': 'accent', 'Router': 'purple'}.get(self.device['type'], 'good')

    def set_selected(self, on: bool) -> None:
        self.setProperty('selected', on)
        self.style().unpolish(self)
        self.style().polish(self)

    def set_state(self, state: dict) -> None:
        while self._chips.count():
            item = self._chips.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
                w.deleteLater()

        cut = state.get('cut')
        spoof = state.get('spoof')
        monitor = state.get('monitor')
        one_way = state.get('one_way')
        dns = state.get('dns')
        badge_tone = ('accent' if monitor else 'danger' if cut
                      else 'purple' if dns else 'warn' if one_way
                      else 'good' if spoof else self._type_tone())
        self._badge.set_look(icons.device_glyph(self.device['type']), badge_tone)

        if monitor:
            self._chips.addWidget(Chip('Monitor', 'accent'))
        elif one_way:
            self._chips.addWidget(Chip('One-way', 'warn'))
        elif cut:
            self._chips.addWidget(Chip('Cut', 'danger'))
        elif spoof:
            self._chips.addWidget(Chip('Routed', 'good'))
        if dns:
            self._chips.addWidget(Chip('PSN', 'purple'))
        if state.get('lag'):
            self._chips.addWidget(Chip('Lag', 'warn'))

        if self._spoof is not None:
            # Cut implies routing too, but the drop is total; show spoof active
            # whenever the device is routed through us.
            self._spoof.set_active(bool(spoof), 'good')
            self._spoof.setText('  Routed' if spoof else '  Spoof')

        if self._cut is not None:
            self._cut.set_active(bool(cut), 'danger')
            self._cut.setText('  Restore' if cut else '  Cut')
            self._cut.set_glyph('restore' if cut else 'cut')
            self._cut.setToolTip("Restore this device's internet" if cut
                                 else 'Cut this device off the internet '
                                      '(ARP redirect + firewall drop)')

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.mac)
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        if not self.admin:
            self.activated.emit(self.mac)
        super().mouseDoubleClickEvent(event)
