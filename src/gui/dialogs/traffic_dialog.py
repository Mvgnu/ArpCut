"""Live traffic monitor.

To see a device's traffic on a switched network you must be the man-in-the-middle.
The **Route & Capture** toggle ARP-routes the device's traffic through this Mac
(kernel-forwarded, so it stays online) and sniffs it. Toggle off to stop and
restore the device.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QTableWidget,
    QTableWidgetItem,
)

from gui.dialogs.base import Dialog
from gui.theme import THEME
from gui.widgets.controls import ToggleSwitch, label
from gui.widgets.device_row import display_name


def _human(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024
    return f'{n:.1f} TB'


class TrafficDialog(Dialog):
    def __init__(self, controller, parent=None) -> None:
        super().__init__('Traffic Monitor', parent, width=580, height=440)
        self.ctrl = controller
        self._device = None
        self._mac = None

        self._subtitle = self.caption('')
        self.content.addWidget(self._subtitle)

        row = QHBoxLayout()
        self._status = QLabel('Paused')
        self._status.setObjectName('StatusLine')
        row.addWidget(self._status, 1)
        row.addWidget(label('Route & Capture', 'body'))
        self._toggle = ToggleSwitch()
        self._toggle.setToolTip('Route this device through your Mac and capture its traffic')
        self._toggle.toggled.connect(self._on_toggle)
        row.addWidget(self._toggle)
        self.content.addLayout(row)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(['Destination', 'Port', 'Proto', 'Traffic'])
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.horizontalHeader().setHighlightSections(False)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for c in (1, 2, 3):
            self._table.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.content.addWidget(self._table, 1)

        # Live flows arrive by push (no polling); a slow timer is a safety net.
        controller.flows_changed.connect(self._on_flows)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)

    # -- lifecycle -----------------------------------------------------------

    def start(self, device: dict) -> None:
        self._device = device
        self._mac = device['mac']
        self._subtitle.setText(f'Live flows for {display_name(device)}  ·  {device["ip"]}')
        self._toggle.blockSignals(True)
        self._toggle.setChecked(True)
        self._toggle.blockSignals(False)
        self._begin()

    def _begin(self) -> None:
        capturing = self.ctrl.start_monitor(self._mac)
        if capturing:
            self._set_status('● Capturing — routed through your Mac', 'good')
        else:
            self._set_status('● Needs administrator access to capture', 'warn')
        self._timer.start(2000)   # fallback; real updates come via flows_changed
        self._refresh()

    def _end(self) -> None:
        self._timer.stop()
        if self._mac:
            self.ctrl.stop_monitor(self._mac)
        self._set_status('Paused — device restored', 'muted')

    def _on_flows(self, flows) -> None:
        if self._mac and self._toggle.isChecked():
            self._render(flows)

    def _on_toggle(self, on: bool) -> None:
        self._begin() if on else self._end()

    # -- rendering -----------------------------------------------------------

    def _set_status(self, text: str, level: str) -> None:
        self._status.setText(text)
        self._status.setProperty('level', level if level in
                                 ('good', 'warn', 'danger', 'accent') else None)
        self._status.style().unpolish(self._status)
        self._status.style().polish(self._status)

    def _refresh(self) -> None:
        self._render(self.ctrl.flows())

    def _render(self, flows) -> None:
        rows = sorted(flows, key=lambda f: f.get('bytes', 0), reverse=True)[:200]
        self._table.setRowCount(len(rows))
        for r, f in enumerate(rows):
            self._set(r, 0, str(f.get('dst', '')), THEME.text)
            self._set(r, 1, str(f.get('port', '')), THEME.text_muted)
            self._set(r, 2, str(f.get('proto', '')), THEME.text_muted)
            self._set(r, 3, f'{_human(f.get("bytes", 0))}  ·  {f.get("packets", 0)} pkts', THEME.text_muted)
        if not rows and self._toggle.isChecked() and self.ctrl.can_capture():
            self._set_status('● Capturing — waiting for traffic…', 'good')

    def _set(self, row: int, col: int, text: str, color: str) -> None:
        item = QTableWidgetItem(text)
        item.setForeground(THEME.qcolor(color))
        if col > 0:
            item.setTextAlignment(Qt.AlignCenter)
        self._table.setItem(row, col, item)

    def closeEvent(self, event):
        self._timer.stop()
        if self._mac:
            self.ctrl.stop_monitor(self._mac)
        super().closeEvent(event)
