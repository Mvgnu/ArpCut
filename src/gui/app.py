"""QApplication bootstrap — wires theme, controller, and window together."""
from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from gui import icons, theme
from gui.controller import Controller
from gui.window import MainWindow
from tools.utils_gui import (
    get_settings, migrate_settings_file, repair_settings,
)


def main() -> int:
    migrate_settings_file()
    repair_settings()

    app = QApplication(sys.argv)
    app.setApplicationName('ArpCut')
    app.setApplicationDisplayName('ArpCut')
    app.setWindowIcon(icons.app_icon())
    app.setQuitOnLastWindowClosed(False)  # tray keeps us alive

    theme.apply(app, dark=bool(get_settings('dark')))

    controller = Controller()
    window = MainWindow(controller)
    window.show()
    controller.start()

    return app.exec()


if __name__ == '__main__':
    raise SystemExit(main())
