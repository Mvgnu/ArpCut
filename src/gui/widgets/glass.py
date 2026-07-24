"""Frosted-glass window chrome — the frameless, translucent, rounded shell.

``GlassRoot`` paints the frosted panel (translucent fill + top sheen + hairline
border). ``_Frameless`` turns any top-level widget into a borderless, shadowed,
draggable, edge-resizable glass window using Qt6's native ``startSystemMove`` /
``startSystemResize`` (no manual geometry math). ``GlassWindow`` and
``GlassDialog`` are the two concrete shells the app builds on.
"""
from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QDialog, QGraphicsDropShadowEffect, QVBoxLayout, QWidget,
)

from gui.theme import THEME

RADIUS = 16
DIALOG_RADIUS = 14
_GRIP = 6  # px hot-zone around edges for resizing


class GlassRoot(QWidget):
    """The visible frosted panel. Everything else sits inside it."""

    def __init__(self, radius: int = RADIUS, parent: QWidget = None) -> None:
        super().__init__(parent)
        self.setObjectName('GlassRoot')
        self._radius = radius

    def paintEvent(self, _event) -> None:
        t = THEME
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        path = QPainterPath()
        path.addRoundedRect(rect, self._radius, self._radius)

        # Frosted base fill (translucent — desktop shows faintly through).
        p.fillPath(path, QColor(*t.window_rgba))

        # Soft top sheen for the "glass" curvature.
        grad = QLinearGradient(0, 0, 0, self.height())
        grad.setColorAt(0.0, t.qcolor(t.sheen))
        grad.setColorAt(0.18, QColor(255, 255, 255, 0))
        p.fillPath(path, grad)

        # Hairline border.
        p.setPen(QPen(t.qcolor(t.border_strong), 1))
        p.drawPath(path)


class _Frameless:
    """Shared frameless-glass behavior for QWidget / QDialog top-levels.

    Subclasses call ``_build_glass(radius, margin)`` and add content to
    ``self.body`` (a QVBoxLayout inside the frosted root).
    """

    def _build_glass(self, radius: int = RADIUS, margin: int = 26) -> None:
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setMouseTracking(True)
        self._margin = margin

        outer = QVBoxLayout(self)
        outer.setContentsMargins(margin, margin, margin, margin)

        self.root = GlassRoot(radius, self)
        self.root.setMouseTracking(True)
        self._shadow = QGraphicsDropShadowEffect(self.root)
        self._shadow.setBlurRadius(float(margin) * 1.4)
        self._shadow.setColor(QColor(*THEME.shadow_rgba))
        self._shadow.setOffset(0, 10)
        self.root.setGraphicsEffect(self._shadow)
        outer.addWidget(self.root)

        self.body = QVBoxLayout(self.root)
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(0)

    # -- edge resizing via native system resize -----------------------------

    def _edges_at(self, pos):
        m, r = self._margin, self.rect()
        x, y = pos.x(), pos.y()
        left, right = x <= m + _GRIP, x >= r.width() - m - _GRIP
        top, bottom = y <= m + _GRIP, y >= r.height() - m - _GRIP
        edges = Qt.Edge(0)
        if left:
            edges |= Qt.LeftEdge
        if right:
            edges |= Qt.RightEdge
        if top:
            edges |= Qt.TopEdge
        if bottom:
            edges |= Qt.BottomEdge
        return edges

    @staticmethod
    def _cursor_for(edges):
        horiz = edges & (Qt.LeftEdge | Qt.RightEdge)
        vert = edges & (Qt.TopEdge | Qt.BottomEdge)
        if horiz and vert:
            tl_br = (edges & Qt.LeftEdge and edges & Qt.TopEdge) or \
                    (edges & Qt.RightEdge and edges & Qt.BottomEdge)
            return Qt.SizeFDiagCursor if tl_br else Qt.SizeBDiagCursor
        if horiz:
            return Qt.SizeHorCursor
        if vert:
            return Qt.SizeVerCursor
        return Qt.ArrowCursor

    def mouseMoveEvent(self, event):
        if not self.isMaximized():
            self.setCursor(self._cursor_for(self._edges_at(event.position().toPoint())))
        super().mouseMoveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and not self.isMaximized():
            edges = self._edges_at(event.position().toPoint())
            if edges and (handle := self.windowHandle()):
                handle.startSystemResize(edges)
                return
        super().mousePressEvent(event)

    def leaveEvent(self, event):
        self.unsetCursor()
        super().leaveEvent(event)

    def start_drag(self) -> None:
        """Called by a title bar to move the whole window natively."""
        if handle := self.windowHandle():
            handle.startSystemMove()

    def on_theme_changed(self) -> None:
        """Re-tint the drop shadow for the new theme (fill repaints live)."""
        self._shadow.setColor(QColor(*THEME.shadow_rgba))


class GlassWindow(_Frameless, QWidget):
    def __init__(self, parent: QWidget = None) -> None:
        super().__init__(parent)
        self._build_glass(RADIUS, 26)


class GlassDialog(_Frameless, QDialog):
    def __init__(self, parent: QWidget = None) -> None:
        super().__init__(parent)
        self._build_glass(DIALOG_RADIUS, 22)
        self.root.setObjectName('GlassDialogRoot')
