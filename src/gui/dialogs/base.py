"""Shared frosted-glass dialog shell: close-only title bar + a padded body."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QScrollArea, QVBoxLayout, QWidget

from gui.widgets.controls import label
from gui.widgets.glass import GlassDialog
from gui.widgets.titlebar import TitleBar


class Dialog(GlassDialog):
    def __init__(self, title: str, parent=None, width: int = 480, height: int = 0,
                 scroll: bool = False, max_height: int = 720) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.titlebar = TitleBar(self, title, minimize=False, zoom=False, height=42)
        self.body.addWidget(self.titlebar)

        wrap = QWidget()
        self.content = QVBoxLayout(wrap)
        self.content.setContentsMargins(22, 4, 22, 22)
        self.content.setSpacing(14)

        if scroll:
            # Content taller than the window scrolls instead of growing off-screen.
            area = QScrollArea()
            area.setWidgetResizable(True)
            area.setFrameShape(QScrollArea.NoFrame)
            area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            area.setWidget(wrap)
            self.body.addWidget(area, 1)
            self.setMaximumHeight(max_height + 2 * self._margin)
        else:
            self.body.addWidget(wrap)

        if width:
            self.setMinimumWidth(width + 2 * self._margin)
        if height:
            self.setMinimumHeight(height + 2 * self._margin)

    def section(self, text: str) -> QLabel:
        return label(text.upper(), 'section')

    def caption(self, text: str) -> QLabel:
        lbl = label(text, 'caption')
        lbl.setWordWrap(True)
        return lbl
