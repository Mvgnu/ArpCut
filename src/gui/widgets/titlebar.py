"""Custom title bar with macOS-style traffic-light window controls.

Frameless windows lose the native title bar, so we draw our own: three
traffic-light buttons (close / minimize / zoom) that reveal their glyph on
hover, an app mark + title, and native drag via the parent's ``start_drag``.
"""
from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QAbstractButton, QHBoxLayout, QLabel, QWidget

from gui import icons
from gui.theme import THEME

_COLORS = {'close': '#FF5F57', 'min': '#FEBC2E', 'zoom': '#28C840'}


class _Light(QAbstractButton):
    def __init__(self, kind: str, parent: 'TrafficLights') -> None:
        super().__init__(parent)
        self._kind = kind
        self._group = parent
        self.setFixedSize(13, 13)
        self.setCursor(Qt.ArrowCursor)

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        active = self.window().isActiveWindow()
        base = QColor(_COLORS[self._kind]) if active else QColor(THEME.border_strong)
        p.setBrush(base)
        p.setPen(Qt.NoPen)
        p.drawEllipse(QRectF(0.5, 0.5, 12, 12))
        if self._group.hovered:
            p.setPen(QPen(QColor(0, 0, 0, 150), 1.3))
            c = 6.5
            if self._kind == 'close':
                p.drawLine(4, 4, 9, 9)
                p.drawLine(9, 4, 4, 9)
            elif self._kind == 'min':
                p.drawLine(4, int(c), 9, int(c))
            else:  # zoom
                p.drawLine(4, int(c), 9, int(c))
                p.drawLine(int(c), 4, int(c), 9)


class TrafficLights(QWidget):
    def __init__(self, win: QWidget, minimize: bool = True, zoom: bool = True) -> None:
        super().__init__(win)
        self._win = win
        self.hovered = False
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        close = _Light('close', self)
        close.clicked.connect(win.close)
        lay.addWidget(close)
        self._lights = [close]

        if minimize:
            mn = _Light('min', self)
            mn.clicked.connect(win.showMinimized)
            lay.addWidget(mn)
            self._lights.append(mn)
        if zoom:
            zm = _Light('zoom', self)
            zm.clicked.connect(self._toggle_zoom)
            lay.addWidget(zm)
            self._lights.append(zm)

    def _toggle_zoom(self) -> None:
        self._win.showNormal() if self._win.isMaximized() else self._win.showMaximized()

    def enterEvent(self, e):
        self.hovered = True
        for lt in self._lights:
            lt.update()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self.hovered = False
        for lt in self._lights:
            lt.update()
        super().leaveEvent(e)


class TitleBar(QWidget):
    """Draggable title bar. Left: traffic lights. Then optional logo + title.
    Right: a slot for extra controls via ``add_right``."""

    def __init__(self, win: QWidget, title: str = '', logo: bool = False,
                 minimize: bool = True, zoom: bool = True, height: int = 46) -> None:
        super().__init__(win)
        self._win = win
        self.setFixedHeight(height)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(18, 0, 14, 0)
        lay.setSpacing(12)

        lay.addWidget(TrafficLights(win, minimize, zoom))

        if logo:
            mark = QLabel()
            mark.setPixmap(icons.app_logo(20).scaled(
                20, 20, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            mark.setAttribute(Qt.WA_TransparentForMouseEvents)  # let the bar drag
            lay.addWidget(mark)

        self._title = QLabel(title)
        self._title.setProperty('role', 'titlebar')
        self._title.setAttribute(Qt.WA_TransparentForMouseEvents)  # let the bar drag
        lay.addWidget(self._title)

        lay.addStretch(1)
        self._right = QHBoxLayout()
        self._right.setSpacing(8)
        lay.addLayout(self._right)

    def add_right(self, widget: QWidget) -> None:
        self._right.addWidget(widget)

    def set_title(self, text: str) -> None:
        self._title.setText(text)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._win.start_drag()
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        self._win.showNormal() if self._win.isMaximized() else self._win.showMaximized()
        super().mouseDoubleClickEvent(event)
