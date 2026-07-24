"""Lag switch parameters — block/release intervals and direction."""
from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QPushButton, QSpinBox

from gui.dialogs.base import Dialog
from gui.widgets.controls import SegmentedControl, label


class LagDialog(Dialog):
    def __init__(self, parent=None) -> None:
        super().__init__('Lag Switch', parent, width=380)

        self.content.addWidget(self.caption(
            'Cycles the connection: blocks traffic for the lag interval, then '
            'restores it for the clear interval — repeatedly.'))

        self._block = self._spin(1500)
        self._release = self._spin(1500)
        self.content.addLayout(self._row('Lag for (ms)', self._block))
        self.content.addLayout(self._row('Clear for (ms)', self._release))

        self.content.addWidget(self.section('Direction'))
        self._dir = SegmentedControl([('both', 'Both'), ('out', 'Outbound'), ('in', 'Inbound')])
        self._dir.set_value('both')
        self.content.addWidget(self._dir)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton('Cancel')
        cancel.clicked.connect(self.reject)
        start = QPushButton('Start')
        start.setProperty('accent', 'primary')
        start.clicked.connect(self.accept)
        buttons.addWidget(cancel)
        buttons.addWidget(start)
        self.content.addLayout(buttons)

    def _spin(self, val: int) -> QSpinBox:
        s = QSpinBox()
        s.setRange(100, 20000)
        s.setSingleStep(100)
        s.setValue(val)
        s.setFixedWidth(100)
        return s

    def _row(self, text: str, widget):
        row = QHBoxLayout()
        row.addWidget(label(text, 'body'), 1)
        row.addWidget(widget)
        return row

    def values(self) -> tuple[int, int, str]:
        return self._block.value(), self._release.value(), self._dir.value()
