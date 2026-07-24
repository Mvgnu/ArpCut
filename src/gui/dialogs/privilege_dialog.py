"""Set Up Access — the in-app path to grant ArpCut the privilege it needs.

Closes the gap the banner used to only *mention*: a clear, non-technical flow to
either relaunch with administrator access (works today, native auth prompt) or
install the persistent root helper (the Wireshark/Little-Snitch model). No
Terminal, no commands to type.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout,
    QWidget,
)

from gui import icons
from gui.dialogs.base import Dialog
from gui.theme import THEME
from gui.widgets.controls import IconButton, hline, label


class PrivilegeDialog(Dialog):
    def __init__(self, controller, parent=None) -> None:
        super().__init__('Set Up Access', parent, width=460)
        self.ctrl = controller

        # header
        head = QHBoxLayout()
        head.setSpacing(12)
        self._hicon = QLabel()
        head.addWidget(self._hicon, 0, Qt.AlignTop)
        htext = QVBoxLayout()
        htext.setSpacing(3)
        htext.addWidget(label('Administrator access', 'hero'))
        htext.addWidget(self.caption(
            'ArpCut works at the raw-network level to discover and cut devices. '
            'Every operating system requires administrator access for that — the '
            'same as Wireshark or Little Snitch. Grant it once, below.'))
        head.addLayout(htext, 1)
        self.content.addLayout(head)

        # live status panel
        self._status_panel = QWidget()
        self._status_panel.setProperty('glass', 'panel')
        srow = QHBoxLayout(self._status_panel)
        srow.setContentsMargins(14, 12, 14, 12)
        self._status_icon = QLabel()
        self._status_text = label('', 'body')
        srow.addWidget(self._status_icon)
        srow.addWidget(self._status_text, 1)
        self.content.addWidget(self._status_panel)

        # primary action
        self._grant_btn = QPushButton()
        self._grant_btn.setProperty('accent', 'primary')
        self._grant_btn.setMinimumHeight(38)
        self._grant_btn.setCursor(Qt.PointingHandCursor)
        self._grant_btn.clicked.connect(self._grant)
        self.content.addWidget(self._grant_btn)
        self._grant_hint = self.caption('')
        self.content.addWidget(self._grant_hint)

        # advanced: persistent helper (macOS/Linux)
        self._helper_box = QWidget()
        hb = QVBoxLayout(self._helper_box)
        hb.setContentsMargins(0, 0, 0, 0)
        hb.setSpacing(8)
        hb.addWidget(hline())
        hb.addWidget(label('Keep it set up (recommended)', 'section'))
        hb.addWidget(self.caption(
            'Install a small background helper that holds the privilege, so ArpCut '
            'just works on every launch — no prompt each time.'))
        self._helper_btn = IconButton('shield-check', 'Install Background Helper',
                                      variant='toolbar')
        self._helper_btn.clicked.connect(self._install_helper)
        hb.addWidget(self._helper_btn)
        self.content.addWidget(self._helper_box)

        self.refresh()

    # -- state ---------------------------------------------------------------

    def refresh(self) -> None:
        st = self.ctrl.privilege_status()
        plat, ok = st['platform'], st['ok']
        self._hicon.setPixmap(icons.pixmap('shield-check' if ok else 'lock',
                                           THEME.good if ok else THEME.warn, 30))
        self._status_icon.setPixmap(icons.pixmap('check' if ok else 'alert',
                                                 THEME.good if ok else THEME.warn, 18))
        if st['root']:
            self._status_text.setText('ArpCut is running with administrator access. You\'re all set.')
        elif st['helper_running']:
            self._status_text.setText('The background helper is installed and running. You\'re all set.')
        elif st['helper_installed']:
            self._status_text.setText('Helper installed but not responding yet — relaunch ArpCut.')
        else:
            self._status_text.setText('Running as a standard user — scanning and cutting are limited.')

        # primary button label per platform
        self._grant_btn.setText('Grant Administrator Access')
        self._grant_btn.setVisible(not ok)
        if plat == 'windows':
            self._grant_hint.setText('You\'ll see a Windows UAC prompt. Npcap must also be installed.')
        elif plat == 'linux':
            self._grant_hint.setText('You\'ll be asked for your password (PolicyKit).')
        else:
            self._grant_hint.setText('You\'ll see the macOS password prompt, then ArpCut reopens with access.')
        self._grant_hint.setVisible(not ok)
        # helper option only where a daemon applies
        self._helper_box.setVisible(plat in ('macos', 'linux') and not st['helper_running'])
        self._helper_btn.setText('  Reinstall Background Helper' if st['helper_installed']
                                 else '  Install Background Helper')

    # -- actions -------------------------------------------------------------

    def _grant(self) -> None:
        self._restart_with_access()

    def _install_helper(self) -> None:
        ok, _msg = self.ctrl.install_helper()
        self.refresh()
        if ok and QMessageBox.question(
                self, 'ArpCut',
                'Background helper installed.\n\nRestart ArpCut with administrator '
                'access now to start using it?') == QMessageBox.Yes:
            self._restart_with_access()

    def _restart_with_access(self) -> None:
        """Relaunch ArpCut elevated (native prompt) and hand off by quitting this one."""
        ok, _msg = self.ctrl.elevate()
        if ok:
            self.ctrl.shutdown()
            QApplication.instance().quit()
        else:
            self.refresh()
