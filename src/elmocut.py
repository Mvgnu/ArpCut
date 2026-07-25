"""ArpCut entry point — bootstrap the PySide6 GUI.

The whole UI lives in ``gui/`` (PySide6). This module only fixes up ``sys.path``,
does the Windows-only Npcap driver check, and hands off to ``gui.app.main``.
"""
import os
import sys

sys.path.append(os.path.dirname(__file__))


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
    _require_npcap()
    from gui.app import main
    raise SystemExit(main())
