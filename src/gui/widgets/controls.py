"""Reusable, theme-driven controls: icon buttons, toggle switch, chips, segments.

Colors come from the global QSS via role/tone properties (chips, segments) or
from live ``THEME`` reads in ``paintEvent`` (toggle) / icon recolors (buttons),
so everything repaints on a theme switch. No captured color literals here.
"""
from __future__ import annotations

from PySide6.QtCore import (
    Property, QEasingCurve, QPropertyAnimation, QRectF, QSize, Qt, Signal,
)
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QAbstractButton, QButtonGroup, QFrame, QHBoxLayout, QLabel, QPushButton,
    QSizePolicy,
)

from gui import icons
from gui.theme import THEME


def label(text: str = '', role: str = 'body', parent=None) -> QLabel:
    """A QLabel that follows the theme via its ``role`` property (styled in QSS)."""
    lbl = QLabel(text, parent)
    lbl.setProperty('role', role)
    return lbl


class IconButton(QPushButton):
    """A ghost/solid button whose SVG icon recolors with hover and active state."""

    def __init__(self, name: str, text: str = '', tooltip: str = '',
                 size: int = 18, parent=None, checkable: bool = False,
                 variant: str = 'ghost') -> None:
        super().__init__(parent)
        self._name = name
        self._isize = size
        self._variant = variant
        self._hover = False
        if text:
            self.setText('  ' + text)
        if tooltip:
            self.setToolTip(tooltip)
        self.setCheckable(checkable)
        self.setCursor(Qt.PointingHandCursor)
        self.setIconSize(QSize(size, size))
        self.toggled.connect(lambda _: self.refresh())
        self.refresh()

    def set_glyph(self, name: str) -> None:
        self._name = name
        self.refresh()

    def set_active(self, on: bool, tint: str = 'danger') -> None:
        self.setProperty('accent', tint if on else None)
        if self.isCheckable():
            self.blockSignals(True)
            self.setChecked(on)
            self.blockSignals(False)
        self.style().unpolish(self)
        self.style().polish(self)
        self.refresh()

    def _icon_color(self) -> str:
        t = THEME
        if self.property('accent'):
            return t.on_accent
        if not self.isEnabled():
            return t.text_faint
        if self._hover or self._variant == 'solid':
            return t.text
        return t.text_muted

    def refresh(self) -> None:
        self.setIcon(icons.icon(self._name, self._icon_color(), self._isize))

    on_theme_changed = refresh  # theme switch → recolor icon

    def enterEvent(self, e):
        self._hover = True
        self.refresh()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._hover = False
        self.refresh()
        super().leaveEvent(e)

    def changeEvent(self, e):
        self.refresh()
        super().changeEvent(e)


class ToggleSwitch(QAbstractButton):
    """An iOS-style animated on/off switch (reads THEME live)."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(46, 28)
        self._pos = 3.0
        self._anim = QPropertyAnimation(self, b'knob', self)
        self._anim.setDuration(150)
        self._anim.setEasingCurve(QEasingCurve.InOutCubic)
        self.toggled.connect(self._animate)

    def _animate(self, on: bool) -> None:
        self._anim.stop()
        self._anim.setEndValue(self.width() - 25 if on else 3.0)
        self._anim.start()

    def get_knob(self) -> float:
        return self._pos

    def set_knob(self, v: float) -> None:
        self._pos = v
        self.update()

    knob = Property(float, get_knob, set_knob)

    def sizeHint(self) -> QSize:
        return QSize(46, 28)

    def paintEvent(self, _e) -> None:
        t = THEME
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        track = t.qcolor(t.accent) if self.isChecked() else t.qcolor(t.border_strong)
        p.setBrush(track)
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(QRectF(0, 0, self.width(), self.height()), 14, 14)
        p.setBrush(QColor('#FFFFFF'))
        p.drawEllipse(QRectF(self._pos, 3, 22, 22))


class Chip(QLabel):
    """A small rounded status badge; tone drives color via the global QSS."""

    def __init__(self, text: str, tone: str = 'danger', parent=None) -> None:
        super().__init__(text.upper(), parent)
        self.setProperty('chip', tone)
        self.setAlignment(Qt.AlignCenter)


class SegmentedControl(QFrame):
    """A pill of mutually-exclusive options (styled entirely by global QSS)."""

    changed = Signal(str)

    def __init__(self, options: list[tuple[str, str]], parent=None) -> None:
        super().__init__(parent)
        self.setProperty('seg', 'true')
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(3, 3, 3, 3)
        lay.setSpacing(3)
        self._buttons: dict[str, QPushButton] = {}
        for value, text in options:
            b = QPushButton(text)
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            b.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            b.clicked.connect(lambda _=False, v=value: self._pick(v))
            self._group.addButton(b)
            lay.addWidget(b)
            self._buttons[value] = b

    def _pick(self, value: str) -> None:
        self._buttons[value].setChecked(True)
        self.changed.emit(value)

    def set_value(self, value: str) -> None:
        if value in self._buttons:
            self._buttons[value].setChecked(True)

    def value(self) -> str:
        for v, b in self._buttons.items():
            if b.isChecked():
                return v
        return ''


def hline() -> QFrame:
    line = QFrame()
    line.setProperty('role', 'hline')
    line.setFixedHeight(1)
    return line
