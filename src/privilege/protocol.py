"""Typed command protocol between the unprivileged GUI and the root helper.

Messages are newline-delimited JSON:

    request  = {"cmd": <name>, "args": {...}}
    response = {"ok": <bool>, "result": <any>, "error": <str|null>}

Commands are a **fixed registry** with per-command argument validation. The helper
executes only these commands against the engine — there is no "run arbitrary
command" verb — so the entire privileged surface is exactly this enum. Every
argument is validated before the helper acts, closing the injection surface that
the old ``shell=True`` calls had.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

PROTOCOL_VERSION = 1

# ---------------------------------------------------------------------------
# Argument validators
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$')
_IFACE_RE = re.compile(r'^[A-Za-z0-9._\\{}-]+$')


def is_ipv4(v: Any) -> bool:
    return isinstance(v, str) and bool(_IPV4_RE.match(v)) and \
        all(0 <= int(p) <= 255 for p in v.split('.'))


def is_mac(v: Any) -> bool:
    return isinstance(v, str) and bool(_MAC_RE.match(v))


def is_port(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 65535


def is_direction(v: Any) -> bool:
    return v in ('in', 'out', 'both')


def is_proto(v: Any) -> bool:
    return v in ('tcp', 'udp', 'both')


def is_scan_type(v: Any) -> bool:
    return v in ('arp', 'ping')


def is_bool(v: Any) -> bool:
    return isinstance(v, bool)


def is_pos_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def is_domains(v: Any) -> bool:
    return isinstance(v, list) and len(v) > 0 and all(isinstance(x, str) and x for x in v)


def is_iface(v: Any) -> bool:
    return isinstance(v, str) and bool(_IFACE_RE.match(v))


def is_nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def is_target(v: Any) -> bool:
    # A preset key / domain / IP, or a list of those.
    if isinstance(v, str):
        return len(v) > 0
    return isinstance(v, list) and all(isinstance(x, str) and x for x in v)


# ---------------------------------------------------------------------------
# Command registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Arg:
    name: str
    validate: Callable[[Any], bool]
    required: bool = True


@dataclass(frozen=True)
class Command:
    name: str
    args: tuple[Arg, ...] = ()
    desc: str = ''


COMMANDS: dict[str, Command] = {c.name: c for c in (
    Command('ping', desc='Health check → "pong".'),
    Command('subscribe', desc='Mark this connection as the GUI session (push + auto-cleanup on drop).'),
    Command('cleanup', desc='Restore everything: unkill all + clear every firewall rule.'),
    Command('status', desc='Privilege + interface + gateway summary.'),
    Command('scan', (Arg('type', is_scan_type),), 'Run an ARP or ping scan.'),
    Command('get_devices', desc='Current discovered device list.'),
    Command('kill', (Arg('mac', is_mac),), 'ARP-spoof (block) a device.'),
    Command('unkill', (Arg('mac', is_mac),), 'Restore a device.'),
    Command('kill_all', desc='Block all non-admin devices.'),
    Command('unkill_all', desc='Restore all devices.'),
    Command('one_way_kill', (Arg('mac', is_mac),), 'Block a device outbound (kernel).'),
    Command('spoof', (Arg('mac', is_mac),), 'Route a device through us (no drop) — base for monitor/lag/blocks.'),
    Command('lag', (Arg('mac', is_mac), Arg('on', is_bool)), 'Toggle a full kernel drop of a device (lag switch).'),
    Command('block_ip', (Arg('ip', is_ipv4), Arg('direction', is_direction, required=False)),
            'Firewall-block an IP.'),
    Command('unblock_ip', (Arg('ip', is_ipv4),), 'Remove an IP block.'),
    Command('block_port', (Arg('port', is_port), Arg('proto', is_proto, required=False),
                           Arg('direction', is_direction, required=False),
                           Arg('target_ip', is_ipv4, required=False)),
            'Firewall-block a port.'),
    Command('unblock_port', (Arg('port', is_port), Arg('proto', is_proto, required=False)),
            'Remove a port block.'),
    Command('block_host', (Arg('target', is_target), Arg('iface', is_iface, required=False)),
            'Block a host preset / domain / IP (PSN, GTA, …).'),
    Command('unblock_host', (Arg('key', is_nonempty_str),), 'Remove a host block.'),
    Command('refresh_hosts', desc='Re-resolve active host blocks (IP rotation).'),
    Command('active_host_blocks', desc='Map of active host-block key → IPs.'),
    Command('set_forwarding', (Arg('enabled', is_bool),), 'Toggle kernel IP forwarding.'),
    # -- primitives the GUI controller orchestrates over ---------------------
    Command('set_iface', (Arg('iface', is_iface),), 'Switch the active interface (re-init).'),
    Command('set_scan_params', (Arg('count', is_pos_int), Arg('threads', is_pos_int)),
            'Set scan address-count and thread pool size.'),
    Command('probe', (Arg('ip', is_ipv4),), 'Actively probe one IP; return [ip, mac] or null.'),
    Command('block_all_for', (Arg('ip', is_ipv4),), 'Firewall-drop all traffic for an IP (the real cut).'),
    Command('unblock_all_for', (Arg('ip', is_ipv4),), 'Remove the full block for an IP.'),
    Command('list_blocked_ports', desc='List (port, proto, direction) blocks.'),
    Command('list_blocked_ips', desc='List (ip, direction) blocks.'),
    Command('start_sniff', (Arg('ip', is_ipv4),), 'Start capturing a device (root-side sniffer).'),
    Command('stop_sniff', desc='Stop the capture.'),
    Command('flows', desc='Current captured flows.'),
    Command('dns_block', (Arg('ip', is_ipv4), Arg('domains', is_domains)),
            'RPZ-style: NXDOMAIN a device\'s queries for names (e.g. PSN).'),
    Command('dns_unblock', (Arg('ip', is_ipv4),), 'Stop DNS-name blocking for a device.'),
    Command('dns_unblock_name', (Arg('ip', is_ipv4), Arg('name', is_nonempty_str)),
            'Stop blocking one DNS name for a device.'),
    Command('active_dns_blocks', desc='Map of target IP → blocked DNS names.'),
)}


def validate(cmd: str, args: dict) -> Optional[str]:
    """Return an error string if (cmd, args) is invalid, else None."""
    command = COMMANDS.get(cmd)
    if command is None:
        return f'unknown command: {cmd}'
    if not isinstance(args, dict):
        return 'args must be an object'
    allowed = {a.name for a in command.args}
    for key in args:
        if key not in allowed:
            return f'unexpected argument: {key}'
    for arg in command.args:
        if arg.name not in args:
            if arg.required:
                return f'missing argument: {arg.name}'
            continue
        if not arg.validate(args[arg.name]):
            return f'invalid argument: {arg.name}'
    return None


# ---------------------------------------------------------------------------
# Wire types + framing
# ---------------------------------------------------------------------------

@dataclass
class Request:
    cmd: str
    args: dict = field(default_factory=dict)


@dataclass
class Response:
    ok: bool
    result: Any = None
    error: Optional[str] = None


def encode(obj) -> bytes:
    """Serialize a Request/Response to a newline-terminated JSON frame."""
    if isinstance(obj, Request):
        payload = {'cmd': obj.cmd, 'args': obj.args}
    elif isinstance(obj, Response):
        payload = {'ok': obj.ok, 'result': obj.result, 'error': obj.error}
    else:
        raise TypeError(f'cannot encode {type(obj)!r}')
    return (json.dumps(payload) + '\n').encode('utf-8')


def decode_request(line: bytes) -> Request:
    data = json.loads(line.decode('utf-8'))
    return Request(cmd=data.get('cmd', ''), args=data.get('args') or {})


def decode_response(line: bytes) -> Response:
    data = json.loads(line.decode('utf-8'))
    return Response(ok=bool(data.get('ok')), result=data.get('result'),
                    error=data.get('error'))
