"""About — app mark, version, credits, links."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel

from gui import icons
from gui.dialogs.base import Dialog
from gui.widgets.controls import IconButton, label
from constants import __version__
from tools.utils import goto


class AboutDialog(Dialog):
    def __init__(self, parent=None) -> None:
        super().__init__('About', parent, width=380)

        logo = QLabel()
        logo.setPixmap(icons.app_logo(88))
        logo.setAlignment(Qt.AlignCenter)
        self.content.addWidget(logo)

        for text, role in (('ArpCut', 'hero'),
                           (f'Version {__version__}', 'muted'),
                           ('A modern, hardened network-control tool for macOS, '
                            'Windows and Linux.', 'caption'),
                           ('Based on elmoCut by elmoiv.', 'faint')):
            lbl = label(text, role)
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setWordWrap(True)
            self.content.addWidget(lbl)

        gh = IconButton('github', 'View on GitHub', variant='toolbar')
        gh.clicked.connect(lambda: goto('https://github.com/Mvgnu/ArpCut'))
        self.content.addWidget(gh)
