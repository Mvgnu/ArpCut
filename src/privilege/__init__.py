"""Privilege separation — unprivileged GUI ↔ root helper daemon.

Client-side surface (safe to import from the GUI; no scapy, no root):

    from privilege import HelperClient
    helper = HelperClient()
    if helper.available():
        helper.call('kill', mac='aa:bb:cc:dd:ee:ff')

The daemon side (``privilege.helper``) is imported only by the root process.
"""
from privilege.client import HelperClient, HelperError
from privilege.protocol import COMMANDS, Request, Response
from privilege.service import HELPER_LABEL, SOCKET_PATH

__all__ = [
    'HelperClient', 'HelperError', 'COMMANDS', 'Request', 'Response',
    'HELPER_LABEL', 'SOCKET_PATH',
]
