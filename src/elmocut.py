"""ArpCut entry point — bootstrap the PySide6 GUI.

The whole UI lives in ``gui/`` (PySide6). This module only fixes up ``sys.path``,
does the Windows-only Npcap driver check, and hands off to ``gui.app.main``.
"""
import os
import sys

sys.path.append(os.path.dirname(__file__))


def _setup_logging() -> None:
    """Log to a rotating file so packaged (windowed, no-console) runs are
    diagnosable — the user can share the log after reproducing an issue.

    File: ``%APPDATA%/arpcut/arpcut.log`` (Windows) / the platform config dir.
    Our own packages log at DEBUG; third-party stays at WARNING.
    """
    import logging
    from logging.handlers import RotatingFileHandler
    try:
        from constants import DOCUMENTS_PATH
        os.makedirs(DOCUMENTS_PATH, exist_ok=True)
        path = os.path.join(DOCUMENTS_PATH, 'arpcut.log')
        handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=2,
                                      encoding='utf-8')
        handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)-7s %(name)s: %(message)s'))
        root = logging.getLogger()
        root.setLevel(logging.WARNING)
        root.addHandler(handler)
        for name in ('networking', 'privilege', 'tools', 'gui'):
            logging.getLogger(name).setLevel(logging.DEBUG)
        logging.getLogger(__name__).info('--- ArpCut starting (log at %s) ---', path)
    except Exception:  # noqa: BLE001 - logging must never break startup
        pass


def _require_npcap() -> None:
    """Windows needs the Npcap driver for raw capture; nudge the user if missing."""
    if not sys.platform.startswith('win'):
        return
    from tools.utils_gui import npcap_exists
    if npcap_exists():
        return
    from tools.utils import goto
    from constants import NPCAP_URL
    print('Npcap is not installed — opening the download page.', file=sys.stderr)
    goto(NPCAP_URL)
    sys.exit(1)


def _flush_firewall() -> int:
    """Remove every ArpCut firewall rule. Called by the uninstaller (all OSes)."""
    from tools import firewall
    for ip, _ in firewall.list_blocked_ips():
        firewall.unblock_ip(ip)
    for port, proto, _ in firewall.list_blocked_ports():
        firewall.unblock_port(port, proto)
    firewall.clear_all_port_blocks()
    firewall.clear_anchor()
    return 0


if __name__ == '__main__':
    # The packaged app binary doubles as the root helper daemon: the LaunchDaemon
    # runs it with --helper (as root), so no separate helper executable is needed.
    if '--helper' in sys.argv:
        from privilege.helper import main as helper_main
        raise SystemExit(helper_main())
    if '--flush-firewall' in sys.argv:
        raise SystemExit(_flush_firewall())
    _setup_logging()
    _require_npcap()
    from gui.app import main
    raise SystemExit(main())
