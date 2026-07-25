"""The one firewall module for ArpCut — pf (macOS), netsh (Windows), nft (Linux).

Every public function branches on ``sys.platform`` and applies rules through the
native tool for that OS:

- **macOS**: ``pfctl`` anchors under ``/etc/pf.anchors/com.arpcut``.
- **Windows**: ``netsh advfirewall`` with rules prefixed ``arpcut_``.
- **Linux**: ``nftables`` — a dedicated ``inet arpcut`` table with comment-tagged
  rules (see the ``_Nft`` helper at the bottom of this file).

All rules live in an isolated namespace per OS, so we never touch the user's
existing ruleset. Public functions return ``bool``; the last error detail is in
``last_error()``.
"""
import sys
import os
import re
import shlex
import threading
from subprocess import run, PIPE, CompletedProcess
from typing import Callable, Optional

ANCHOR: str = 'com.arpcut'

# ---------------------------------------------------------------------------
# Error state container — replaces the old ``_LAST_ERR`` global string.
# ---------------------------------------------------------------------------

class _ErrorState:
    """Thread-safe container for the last error detail.  Avoids ``global``.

    The lag switch and GUI can call firewall ops concurrently, so guard the
    single shared message with a lock.
    """
    __slots__ = ('message', '_lock')

    def __init__(self) -> None:
        self.message: str = ''
        self._lock = threading.Lock()

    def set(self, msg: str) -> None:
        with self._lock:
            self.message = msg or ''

    def clear(self) -> None:
        with self._lock:
            self.message = ''

    def get(self) -> str:
        with self._lock:
            return self.message


_err = _ErrorState()


def last_error() -> str:
    """Return the last error message reported by any pfctl/netsh operation."""
    return _err.get()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

# Regex for valid IPv4
_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

# Interface names must be alphanumeric + hyphen/underscore/dot (no shell metacharacters)
_IFACE_RE = re.compile(r'^[a-zA-Z0-9._-]+$')


def _is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IPv4 address.

    Rejects inputs containing whitespace (including trailing newlines / CR)
    that could bypass downstream shell commands.
    """
    if not ip or ip != ip.strip():
        return False
    if not _IP_RE.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def _is_valid_iface(name: str) -> bool:
    """Validate an interface name to prevent shell injection.

    Accepts only ``[a-zA-Z0-9._-]+`` — the character class used by all major
    OSes for NIC names (e.g. ``en0``, ``eth0``, ``Wi-Fi``).
    """
    if not name:
        return False
    return bool(_IFACE_RE.match(name))


def _is_valid_port(port: int) -> bool:
    """Validate that a port number is in the valid TCP/UDP range."""
    return isinstance(port, int) and 1 <= port <= 65535


def _is_valid_proto(proto: str) -> bool:
    """Validate protocol string (tcp or udp only)."""
    return proto.lower() in ('tcp', 'udp')


# ---------------------------------------------------------------------------
# Shell execution
# ---------------------------------------------------------------------------

def _exec(cmd) -> CompletedProcess[str]:
    """Run a command WITHOUT a shell, capturing stdout and stderr.

    ``cmd`` may be a string (split with ``shlex``) or an argv list. No shell means
    the validated IP/port/proto values interpolated into rule commands cannot be
    reinterpreted as shell syntax.
    """
    args = shlex.split(cmd, posix=not sys.platform.startswith('win')) \
        if isinstance(cmd, str) else cmd
    return run(args, stdout=PIPE, stderr=PIPE, text=True)


def _netsh_delete_ok(res: CompletedProcess[str]) -> bool:
    """True if a netsh delete succeeded or matched nothing (idempotent no-op).

    Previously these deletes ignored the return code and always reported success,
    hiding real failures. "No rules match" means there was nothing to remove,
    which is a legitimate success for an idempotent unblock.
    """
    if res.returncode == 0:
        _err.clear()
        return True
    out = (res.stdout or '') + (res.stderr or '')
    if 'No rules match' in out:
        _err.clear()
        return True
    _err.set(res.stderr or res.stdout or 'netsh delete failed')
    return False


# ---------------------------------------------------------------------------
# Locale-independent Windows helpers
#
# netsh output is localized: the firewall state prints 'ON'/'EIN'/... and each
# rule is prefixed with a localized 'Rule Name:'/'Regelname:' label. Parsing
# those English words silently breaks on non-English Windows (blocks look
# applied but readback/cleanup find nothing). These helpers avoid the localized
# text entirely — the registry for state, the ``arpcut_*`` token for rule names.
# ---------------------------------------------------------------------------

_ARPCUT_RULE_RE = re.compile(r'arpcut_[A-Za-z0-9_]+')


def _win_firewall_enabled() -> bool:
    """True if any Windows Firewall profile is enabled (reads the registry)."""
    if not sys.platform.startswith('win'):
        return False
    try:
        import winreg
    except ImportError:
        return False
    base = (r'SYSTEM\CurrentControlSet\Services\SharedAccess'
            r'\Parameters\FirewallPolicy')
    for prof in ('DomainProfile', 'StandardProfile', 'PublicProfile'):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + '\\' + prof) as k:
                if int(winreg.QueryValueEx(k, 'EnableFirewall')[0]) == 1:
                    return True
        except OSError:
            continue
    return False


def _arpcut_rule_names_in(text: str) -> list[str]:
    """Return the distinct ``arpcut_*`` rule names in netsh show-rule output.

    Matches the rule-name token directly, ignoring the localized label, so it
    works regardless of the Windows display language.
    """
    seen: list[str] = []
    for m in _ARPCUT_RULE_RE.finditer(text):
        if m.group(0) not in seen:
            seen.append(m.group(0))
    return seen


# ---------------------------------------------------------------------------
# PF rule helpers
# ---------------------------------------------------------------------------

def _is_valid_pf_rule(rule: str) -> bool:
    """Check if a pf rule looks valid (basic sanity check)."""
    if not rule or rule.startswith('#'):
        return False
    # Must start with 'block' and contain valid-looking IPs or 'any'
    if not rule.startswith('block'):
        return False
    # Check that any IP-like strings in the rule are actually valid IPs or 'any'
    parts = rule.split()
    for i, part in enumerate(parts):
        if part in ('from', 'to') and i + 1 < len(parts):
            next_part = parts[i + 1]
            if next_part != 'any' and not _is_valid_ip(next_part):
                return False
    return True


def _read_existing_rules() -> list[str]:
    """Read existing rules from anchor file, filtering out comments, empty lines, and invalid rules."""
    try:
        path = _anchor_file()
        with open(path, 'r') as f:
            lines = f.readlines()
        valid: list[str] = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and _is_valid_pf_rule(line):
                valid.append(line)
        return valid
    except OSError:
        return []


def _anchor_file() -> str:
    """Return the absolute path to the pf anchor rules file."""
    return f'/etc/pf.anchors/{ANCHOR}'


def _write_pf_rules(new_rules: list[str], replace: bool = False) -> bool:
    """Write rules to pf anchor file and reload.

    If ``replace=False``, appends to existing rules.
    If ``replace=True``, overwrites all rules.
    Returns True on success, False on any error.
    """
    if not ensure_pf_enabled() or not install_anchor():
        return False
    try:
        path = _anchor_file()
        if replace:
            all_rules = new_rules
        else:
            # Idempotent append — never accumulate duplicate rules.
            all_rules = _read_existing_rules()
            for rule in new_rules:
                if rule not in all_rules:
                    all_rules.append(rule)

        with open(path, 'w') as f:
            f.write("# ArpCut anchor - autogenerated\n")
            for rule in all_rules:
                f.write(f"{rule}\n")
        res = _exec(f"pfctl -a {ANCHOR} -f {path}")
        if res.returncode != 0:
            _err.set(res.stderr or res.stdout or 'pfctl failed')
            return False
        _err.clear()
        return True
    except Exception as e:
        _err.set(str(e))
        return False


def _remove_rules_where(predicate: Callable[[str], bool]) -> bool:
    """Remove anchor-file rules where ``predicate(line)`` is true, then reload.

    Callers pass a token-aware predicate (e.g. :func:`_pf_line_targets_ip`) so
    removal is exact — never a substring match that would strip a neighbouring
    IP's rule (unblocking ``10.0.0.1`` must not touch ``10.0.0.10``).
    """
    try:
        path = _anchor_file()
        with open(path, 'r') as f:
            lines = f.readlines()
        with open(path, 'w') as f:
            for line in lines:
                if not predicate(line):
                    f.write(line)
        res = _exec(f"pfctl -a {ANCHOR} -f {path}")
        if res.returncode != 0:
            _err.set(res.stderr or res.stdout or 'pfctl reload failed')
            return False
        _err.clear()
        return True
    except Exception as e:
        _err.set(str(e))
        return False


# ---------------------------------------------------------------------------
# PF lifecycle
# ---------------------------------------------------------------------------

def ensure_pf_enabled() -> bool:
    """Ensure the macOS packet filter is enabled."""
    if sys.platform != 'darwin':
        return True
    status = _exec('pfctl -s info')
    if status.returncode != 0:
        _err.set(status.stderr or status.stdout or 'pfctl -s info failed')
        return False
    if 'Status: Enabled' in status.stdout:
        return True
    # Try to enable
    en = _exec('pfctl -E')
    if en.returncode != 0:
        _err.set(en.stderr or en.stdout or 'pfctl -E failed')
    else:
        _err.clear()
    return en.returncode == 0


def clear_anchor() -> bool:
    """Clear all rules from the anchor file."""
    if sys.platform.startswith('linux'):
        return _nft.clear()
    if sys.platform != 'darwin':
        return True
    try:
        path = _anchor_file()
        with open(path, 'w') as f:
            f.write("# ArpCut anchor - autogenerated\n")
        _exec(f"pfctl -a {ANCHOR} -f {path}")
        return True
    except OSError:
        return False


def install_anchor() -> bool:
    """Ensure the ArpCut anchor file exists and is referenced by ``/etc/pf.conf``."""
    if sys.platform != 'darwin':
        return True
    path = _anchor_file()
    # Clean the anchor file first - remove any garbage/invalid rules
    try:
        if os.path.exists(path):
            # File exists - read and filter
            with open(path, 'r') as f:
                lines = f.readlines()
            valid: list[str] = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#') and _is_valid_pf_rule(line):
                    valid.append(line)
            # Rewrite with only valid rules
            with open(path, 'w') as f:
                f.write("# ArpCut anchor - autogenerated\n")
                for rule in valid:
                    f.write(f"{rule}\n")
        else:
            # File doesn't exist - create empty
            with open(path, 'w') as f:
                f.write("# ArpCut anchor - autogenerated\n")
    except Exception as e:
        _err.set(f'failed to clean anchor file: {e}')
        return False

    # Ensure pf.conf references our anchor
    try:
        with open('/etc/pf.conf', 'r') as f:
            conf = f.read()
        if f'anchor "{ANCHOR}"' not in conf and f'load anchor "{ANCHOR}"' not in conf:
            with open('/etc/pf.conf', 'a') as f:
                f.write(f"\n# ArpCut anchor\nanchor \"{ANCHOR}\"\nload anchor \"{ANCHOR}\" from \"{_anchor_file()}\"\n")
    except OSError:
        _err.set('failed to read/write /etc/pf.conf')
        return False

    # Load the (now clean) anchor
    res = _exec(f"pfctl -a {ANCHOR} -f {path}")
    if res.returncode != 0:
        _err.set(res.stderr or res.stdout or 'pfctl anchor load failed')
        return False
    _err.clear()
    return True


def list_rules() -> list[str]:
    """Return current rules in the ArpCut pf anchor."""
    if sys.platform != 'darwin':
        return []
    if not ensure_pf_enabled() or not install_anchor():
        return []
    res = _exec(f'pfctl -a {ANCHOR} -s rules')
    if res.returncode != 0:
        _err.set(res.stderr or res.stdout or 'pfctl list failed')
        return []
    _err.clear()
    return res.stdout.splitlines()


# ---------------------------------------------------------------------------
# Block / unblock per-victim (all traffic)
# ---------------------------------------------------------------------------

def block_all_for(iface: str, victim_ip: str) -> bool:
    """Block all traffic for a victim IP (used by the Kill feature)."""
    if sys.platform.startswith('linux'):
        return _nft.block_all_for(iface, victim_ip)
    if not _is_valid_ip(victim_ip):
        _err.set(f'Invalid victim IP: {victim_ip}')
        return False
    if not _is_valid_iface(iface):
        _err.set(f'Invalid interface name: {iface}')
        return False

    if sys.platform == 'darwin':
        rule = f'block drop quick on {iface} from {victim_ip} to any'
        return _write_pf_rules([rule], replace=False)
    elif sys.platform.startswith('win'):
        # Block BOTH directions — outbound (to the victim IP) and inbound (from
        # it). Outbound-only left devices able to receive, so the cut was partial.
        base = f'arpcut_block_{victim_ip.replace(".", "_")}'
        ok = True
        for direction in ('out', 'in'):
            res = _exec(
                f'netsh advfirewall firewall add rule name="{base}_{direction}" '
                f'dir={direction} action=block remoteip={victim_ip} enable=yes')
            if res.returncode != 0:
                _err.set(res.stderr or res.stdout or 'netsh failed')
                ok = False
        if ok:
            _err.clear()
        return ok
    return False


def unblock_all_for(victim_ip: str) -> bool:
    """Unblock all traffic for a victim IP."""
    if sys.platform.startswith('linux'):
        return _nft.unblock_all_for(victim_ip)
    if not _is_valid_ip(victim_ip):
        _err.set(f'Invalid victim IP: {victim_ip}')
        return False

    if sys.platform == 'darwin':
        return _remove_rules_where(lambda line: _pf_line_targets_ip(line, victim_ip))
    elif sys.platform.startswith('win'):
        base = f'arpcut_block_{victim_ip.replace(".", "_")}'
        ok = True
        # Delete the split rules plus the legacy single-name rule (older builds).
        for name in (f'{base}_out', f'{base}_in', base):
            ok = _netsh_delete_ok(_exec(
                f'netsh advfirewall firewall delete rule name="{name}"')) and ok
        return ok
    return False


# ---------------------------------------------------------------------------
# Block / unblock destination traffic
# ---------------------------------------------------------------------------

def block_dst(iface: str, victim_ip: str, dst_ip: str, port: Optional[int] = None, proto: Optional[str] = None) -> bool:
    """Block traffic from victim to a specific destination."""
    if not _is_valid_ip(victim_ip):
        _err.set(f'Invalid victim IP: {victim_ip}')
        return False
    if not _is_valid_ip(dst_ip):
        _err.set(f'Invalid destination IP: {dst_ip}')
        return False
    if not _is_valid_iface(iface):
        _err.set(f'Invalid interface name: {iface}')
        return False
    if port is not None and not _is_valid_port(port):
        _err.set(f'Invalid port: {port}')
        return False
    if proto is not None and not _is_valid_proto(proto):
        _err.set(f'Invalid protocol: {proto}')
        return False

    if sys.platform != 'darwin':
        if sys.platform.startswith('win'):
            rule_name = f'arpcut_{victim_ip.replace(".", "_")}_to_{dst_ip.replace(".", "_")}'
            if port:
                rule_name += f'_p{port}'
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={dst_ip} enable=yes'
            if port:
                cmd += f' protocol={proto.lower() if proto else "TCP"} localport={port}'
            res = _exec(cmd)
            return res.returncode == 0
        return False
    port_clause = f' port {port}' if port else ''
    proto_clause = f' proto {proto.lower()}' if proto and proto.upper() in ['TCP', 'UDP'] else ''
    rule = f'block drop quick on {iface}{proto_clause} from {victim_ip} to {dst_ip}{port_clause}'
    return _write_pf_rules([rule], replace=False)


def unblock_dst(dst_ip: str, port: Optional[int] = None) -> bool:
    """Remove blocking rules targeting a destination IP."""
    if not _is_valid_ip(dst_ip):
        _err.set(f'Invalid destination IP: {dst_ip}')
        return False
    if port is not None and not _is_valid_port(port):
        _err.set(f'Invalid port: {port}')
        return False

    if sys.platform != 'darwin':
        if sys.platform.startswith('win'):
            list_cmd = 'netsh advfirewall firewall show rule name=all dir=out'
            res = _exec(list_cmd)
            if res.returncode != 0:
                _err.set(res.stderr or res.stdout or 'netsh show rule failed')
                return False
            ok = True
            target = dst_ip.replace('.', '_')
            for name in _arpcut_rule_names_in(res.stdout):
                if target in name:
                    ok = _netsh_delete_ok(_exec(
                        f'netsh advfirewall firewall delete rule name="{name}"')) and ok
            return ok
        return False
    return _remove_rules_where(lambda line: _pf_line_targets_ip(line, dst_ip))


def export_rules(path: str) -> bool:
    """Export current anchor rules to the given file path."""
    try:
        with open(_anchor_file(), 'r') as src, open(path, 'w') as dst:
            dst.write(src.read())
        return True
    except OSError:
        return False


def import_rules(path: str) -> bool:
    """Import rules from a file into the anchor."""
    try:
        with open(path, 'r') as src, open(_anchor_file(), 'w') as dst:
            dst.write(src.read())
        _exec(f"pfctl -a {ANCHOR} -f {_anchor_file()}")
        return True
    except OSError:
        return False


def is_blocked(dst_ip: str) -> bool:
    """Check if a destination IP has any active blocking rules."""
    if sys.platform.startswith('linux'):
        return any(ip == dst_ip for ip, _ in _nft.list_blocked_ips())
    if sys.platform != 'darwin':
        return False
    rules = list_rules()
    return any(_pf_line_targets_ip(r, dst_ip) for r in rules)


def pf_self_check() -> bool:
    """Verify that the firewall backend is operational."""
    if sys.platform != 'darwin':
        if sys.platform.startswith('win'):
            # netsh must be operational AND a firewall profile enabled. The state
            # word ('ON'/'EIN'/…) is localized, so check enablement via registry.
            res = _exec('netsh advfirewall show allprofiles state')
            return res.returncode == 0 and _win_firewall_enabled()
        return True
    if not ensure_pf_enabled():
        return False
    return install_anchor()


def pf_test_roundtrip(iface: str, victim_ip: str) -> bool:
    """End-to-end smoke test: block, verify, unblock."""
    if sys.platform != 'darwin':
        return True
    if not _is_valid_iface(iface) or not _is_valid_ip(victim_ip):
        return False
    ok1 = block_all_for(iface, victim_ip)
    rules = list_rules()
    present = any(_pf_line_targets_ip(r, victim_ip) for r in rules)
    ok2 = unblock_all_for(victim_ip)
    return ok1 and present and ok2


# ============== IP BLOCKING ==============

def block_ip(iface: str, ip: str, direction: str = 'both') -> bool:
    """Block all traffic to/from a specific IP."""
    if sys.platform.startswith('linux'):
        return _nft.block_ip(iface, ip, direction)
    if not _is_valid_ip(ip):
        _err.set(f'Invalid IP address: {ip}')
        return False
    if not _is_valid_iface(iface):
        _err.set(f'Invalid interface name: {iface}')
        return False
    if direction not in ('in', 'out', 'both'):
        _err.set(f'Invalid direction: {direction}')
        return False

    if sys.platform == 'darwin':
        rules = [
            f'block drop quick on {iface} from {ip} to any',
            f'block drop quick on {iface} from any to {ip}'
        ]
        return _write_pf_rules(rules, replace=False)
    elif sys.platform.startswith('win'):
        rule_name = f'arpcut_ip_{ip.replace(".", "_")}'
        ok = True
        if direction in ('in', 'both'):
            res = _exec(f'netsh advfirewall firewall add rule name="{rule_name}_in" dir=in action=block remoteip={ip} enable=yes')
            ok = ok and res.returncode == 0
        if direction in ('out', 'both'):
            res = _exec(f'netsh advfirewall firewall add rule name="{rule_name}_out" dir=out action=block remoteip={ip} enable=yes')
            ok = ok and res.returncode == 0
        if not ok:
            _err.set(res.stderr or res.stdout or 'netsh failed')  # type: ignore[possibly-undefined]
        else:
            _err.clear()
        return ok
    return False


def _pf_line_targets_ip(line: str, ip: str) -> bool:
    """True if a pf rule line targets exactly ``ip`` (exact token match).

    Rules are of the form ``... from {ip} to any`` / ``... from any to {ip}``.
    Token equality avoids the substring collision where unblocking ``10.0.0.1``
    would also strip rules for ``10.0.0.10`` / ``10.0.0.100``.
    """
    toks = line.split()
    for kw in ('from', 'to'):
        if kw in toks:
            i = toks.index(kw)
            if i + 1 < len(toks) and toks[i + 1] == ip:
                return True
    return False


def _pf_line_targets_port(line: str, port: int) -> bool:
    """True if a pf rule line targets exactly ``port`` (exact token match).

    Avoids the substring collision where unblocking port 80 would also strip
    ``port 8080`` rules. Handles both ``port 443`` and ``port = 443`` forms.
    """
    toks = line.split()
    if 'port' in toks:
        i = toks.index('port')
        nxt = toks[i + 1] if i + 1 < len(toks) else ''
        if nxt == '=':
            nxt = toks[i + 2] if i + 2 < len(toks) else ''
        return nxt == str(port)
    return False


def unblock_ip(ip: str) -> bool:
    """Remove IP blocking rules."""
    if sys.platform.startswith('linux'):
        return _nft.unblock_ip(ip)
    if not _is_valid_ip(ip):
        _err.set(f'Invalid IP address: {ip}')
        return False

    if sys.platform == 'darwin':
        try:
            path = _anchor_file()
            with open(path, 'r') as f:
                lines = f.readlines()
            with open(path, 'w') as f:
                for line in lines:
                    if not _pf_line_targets_ip(line, ip):
                        f.write(line)
            res = _exec(f"pfctl -a {ANCHOR} -f {path}")
            if res.returncode != 0:
                _err.set(res.stderr or res.stdout or 'pfctl failed')
                return False
            _err.clear()
            return True
        except Exception as e:
            _err.set(str(e))
            return False
    elif sys.platform.startswith('win'):
        rule_name = f'arpcut_ip_{ip.replace(".", "_")}'
        res_in = _exec(f'netsh advfirewall firewall delete rule name="{rule_name}_in"')
        res_out = _exec(f'netsh advfirewall firewall delete rule name="{rule_name}_out"')
        ok = (res_in.returncode == 0) or (res_out.returncode == 0)
        if not ok:
            _err.set((res_in.stderr or '') + '\n' + (res_out.stderr or ''))
        else:
            _err.clear()
        return ok
    return False


def list_blocked_ips() -> list[tuple[str, str]]:
    """Return list of blocked IPs as ``[(ip, direction), ...]``."""
    if sys.platform.startswith('linux'):
        return _nft.list_blocked_ips()
    blocked: list[tuple[str, str]] = []
    if sys.platform == 'darwin':
        rules = list_rules()
        for rule in rules:
            if 'block drop quick' in rule and 'port' not in rule:
                parts = rule.split()
                try:
                    if 'from' in parts and 'to' in parts:
                        from_idx = parts.index('from')
                        to_idx = parts.index('to')
                        from_ip = parts[from_idx + 1]
                        to_ip = parts[to_idx + 1]
                        if from_ip != 'any':
                            blocked.append((from_ip, 'in'))
                        elif to_ip != 'any':
                            blocked.append((to_ip, 'out'))
                except (ValueError, IndexError):
                    pass
    elif sys.platform.startswith('win'):
        res = _exec('netsh advfirewall firewall show rule name=all')
        if res.returncode == 0:
            regex = re.compile(r'arpcut_ip_([0-9]{1,3}(?:_[0-9]{1,3}){3})_(in|out)', re.IGNORECASE)
            for line in res.stdout.splitlines():
                line = line.strip()
                if 'arpcut_ip_' in line.lower():
                    m = regex.search(line)
                    if m:
                        ip = m.group(1).replace('_', '.')
                        direction = m.group(2)
                        blocked.append((ip, direction))
    return blocked


# ============== PORT BLOCKING ==============

def block_port(iface: str, port: int, proto: str = 'tcp', direction: str = 'both', target_ip: Optional[str] = None) -> bool:
    """Block a specific port on the network interface.

    If ``target_ip`` is provided, only blocks that port for traffic from/to that IP.
    ``direction`` is ignored on macOS (anchors don't support in/out).
    """
    if sys.platform.startswith('linux'):
        return _nft.block_port(iface, port, proto, direction, target_ip)
    if not _is_valid_port(port):
        _err.set(f'Invalid port number: {port}')
        return False
    if not _is_valid_iface(iface):
        _err.set(f'Invalid interface name: {iface}')
        return False
    if not _is_valid_proto(proto):
        _err.set(f'Invalid protocol: {proto}')
        return False
    if target_ip is not None and not _is_valid_ip(target_ip):
        _err.set(f'Invalid target IP: {target_ip}')
        return False

    if sys.platform == 'darwin':
        if target_ip:
            rule = f'block drop quick on {iface} proto {proto} from {target_ip} to any port {port}'
        else:
            rule = f'block drop quick on {iface} proto {proto} from any to any port {port}'
        return _write_pf_rules([rule], replace=False)
    elif sys.platform.startswith('win'):
        rule_name = f'arpcut_port_{port}_{proto}'
        ok = True
        if direction in ('in', 'both'):
            res = _exec(f'netsh advfirewall firewall add rule name="{rule_name}_in" dir=in action=block protocol={proto} localport={port} enable=yes')
            ok = ok and res.returncode == 0
        if direction in ('out', 'both'):
            res = _exec(f'netsh advfirewall firewall add rule name="{rule_name}_out" dir=out action=block protocol={proto} localport={port} enable=yes')
            ok = ok and res.returncode == 0
        if not ok:
            _err.set(res.stderr or res.stdout or 'netsh failed')  # type: ignore[possibly-undefined]
        else:
            _err.clear()
        return ok
    return False


def unblock_port(port: int, proto: str = 'tcp') -> bool:
    """Remove port blocking rules for the specified port."""
    if sys.platform.startswith('linux'):
        return _nft.unblock_port(port, proto)
    if not _is_valid_port(port):
        _err.set(f'Invalid port number: {port}')
        return False

    if sys.platform == 'darwin':
        return _remove_rules_where(lambda line: _pf_line_targets_port(line, port))
    elif sys.platform.startswith('win'):
        rule_name = f'arpcut_port_{port}_{proto}'
        res_in = _exec(f'netsh advfirewall firewall delete rule name="{rule_name}_in"')
        res_out = _exec(f'netsh advfirewall firewall delete rule name="{rule_name}_out"')
        ok = (res_in.returncode == 0) or (res_out.returncode == 0)
        if not ok:
            _err.set((res_in.stderr or '') + '\n' + (res_out.stderr or ''))
        else:
            _err.clear()
        return ok
    return False


def is_port_blocked(port: int) -> bool:
    """Check if a port is currently blocked."""
    if sys.platform.startswith('linux'):
        return _nft.is_port_blocked(port)
    if not _is_valid_port(port):
        return False

    if sys.platform == 'darwin':
        rules = list_rules()
        return any(_pf_line_targets_port(r, port) for r in rules)
    elif sys.platform.startswith('win'):
        res = _exec(f'netsh advfirewall firewall show rule name="arpcut_port_{port}_tcp_in"')
        return 'arpcut_port' in res.stdout.lower()
    return False


def list_blocked_ports() -> list[tuple[int, str, str]]:
    """Return list of currently blocked ports as ``[(port, proto, direction), ...]``."""
    if sys.platform.startswith('linux'):
        return _nft.list_blocked_ports()
    blocked: list[tuple[int, str, str]] = []
    if sys.platform == 'darwin':
        rules = list_rules()
        for rule in rules:
            if 'port' in rule:
                parts = rule.split()
                try:
                    port_idx = parts.index('port')
                    # Handle both "port 443" and "port = 443" formats
                    port_val = parts[port_idx + 1]
                    if port_val == '=':
                        port_val = parts[port_idx + 2]
                    port_num = int(port_val)
                    proto = 'tcp'
                    if 'proto' in parts:
                        proto_idx = parts.index('proto')
                        proto = parts[proto_idx + 1]
                    direction = 'both'  # macOS anchors don't distinguish direction
                    blocked.append((port_num, proto, direction))
                except (ValueError, IndexError):
                    pass
    elif sys.platform.startswith('win'):
        res = _exec('netsh advfirewall firewall show rule name=all')
        if res.returncode == 0:
            regex = re.compile(r'arpcut_port_([0-9]+)_([a-z]+)_(in|out)', re.IGNORECASE)
            for line in res.stdout.splitlines():
                line = line.strip()
                if 'arpcut_port_' in line.lower():
                    m = regex.search(line)
                    if m:
                        port_num = int(m.group(1))
                        proto = m.group(2)
                        direction = m.group(3)
                        blocked.append((port_num, proto, direction))
    return blocked


def clear_all_port_blocks() -> bool:
    """Remove all port blocking rules."""
    if sys.platform.startswith('linux'):
        return _nft.clear_ports()
    if sys.platform == 'darwin':
        return _remove_rules_where(lambda line: 'port' in line.split())
    elif sys.platform.startswith('win'):
        res = _exec('netsh advfirewall firewall show rule name=all')
        if res.returncode != 0:
            _err.set(res.stderr or res.stdout or 'netsh show rule failed')
            return False
        ok = True
        for name in _arpcut_rule_names_in(res.stdout):
            if name.startswith('arpcut_port'):
                ok = _netsh_delete_ok(_exec(
                    f'netsh advfirewall firewall delete rule name="{name}"')) and ok
        return ok
    return False


# ---------------------------------------------------------------------------
# Linux nftables backend — a dedicated ``inet arpcut`` table with a forward-hook
# chain. Rules are comment-tagged (``arpcut_ip_<ip>_<dir>`` / ``arpcut_port_...``)
# so we list and delete exactly our own rules by handle. Commands run through an
# arg-list runner (no shell), which the ``linux`` branches above dispatch to.
# ---------------------------------------------------------------------------

_NFT_FAMILY = 'inet'
_NFT_TABLE = 'arpcut'
_NFT_CHAIN = 'arpcut_fwd'
_NFT_HANDLE_RE = re.compile(r'#\s*handle\s+(\d+)')
_NFT_COMMENT_RE = re.compile(r'comment\s+"([^"]+)"')


def _nft_default_run(argv: list[str]) -> CompletedProcess[str]:
    return run(argv, stdout=PIPE, stderr=PIPE, text=True)


def _norm_protos(proto: str) -> tuple[str, ...]:
    p = str(proto).lower()
    if p == 'both':
        return ('tcp', 'udp')
    return (p,) if p in ('tcp', 'udp') else ()


class _Nft:
    """nftables rule management. Comment-tagged rules → exact idempotent removal."""

    def __init__(self, runner=None) -> None:
        self._run = runner or _nft_default_run

    def _tokens(self, *tokens: str) -> CompletedProcess[str]:
        return self._run(['nft', *tokens])

    def _cmd(self, command: str) -> CompletedProcess[str]:
        # A whole nft command as one arg keeps `comment "..."` quoting natural.
        return self._run(['nft', command])

    def _list_tagged(self) -> list[tuple[str, int]]:
        res = self._tokens('-a', 'list', 'chain', _NFT_FAMILY, _NFT_TABLE, _NFT_CHAIN)
        if res.returncode != 0:
            return []
        tagged: list[tuple[str, int]] = []
        for line in res.stdout.splitlines():
            mc, mh = _NFT_COMMENT_RE.search(line), _NFT_HANDLE_RE.search(line)
            if mc and mh:
                tagged.append((mc.group(1), int(mh.group(1))))
        return tagged

    def _delete_where(self, keep) -> bool:
        ok = True
        for comment, handle in self._list_tagged():
            if keep(comment):
                res = self._tokens('delete', 'rule', _NFT_FAMILY, _NFT_TABLE,
                                   _NFT_CHAIN, 'handle', str(handle))
                ok = (res.returncode == 0) and ok
        return ok

    def ensure(self) -> bool:
        self._tokens('add', 'table', _NFT_FAMILY, _NFT_TABLE)
        self._cmd(f'add chain {_NFT_FAMILY} {_NFT_TABLE} {_NFT_CHAIN} '
                  '{ type filter hook forward priority 0 ; policy accept ; }')
        return True

    def clear(self) -> bool:
        self._tokens('flush', 'chain', _NFT_FAMILY, _NFT_TABLE, _NFT_CHAIN)
        return True

    def clear_ports(self) -> bool:
        return self._delete_where(lambda c: c.startswith('arpcut_port_'))

    def block_ip(self, iface: str, ip: str, direction: str = 'both') -> bool:
        if not _is_valid_ip(ip):
            _err.set(f'Invalid IP: {ip}')
            return False
        self.ensure()
        wanted: list[tuple[str, str]] = []
        if str(direction) in ('out', 'both'):
            wanted.append(('out', f'ip saddr {ip}'))
        if str(direction) in ('in', 'both'):
            wanted.append(('in', f'ip daddr {ip}'))
        if not wanted:
            return False
        existing = {c for c, _ in self._list_tagged()}
        ok = True
        for tag, match in wanted:
            comment = f'arpcut_ip_{ip}_{tag}'
            if comment in existing:
                continue  # idempotent
            res = self._cmd(f'add rule {_NFT_FAMILY} {_NFT_TABLE} {_NFT_CHAIN} '
                            f'{match} drop comment "{comment}"')
            ok = (res.returncode == 0) and ok
        return ok

    def unblock_ip(self, ip: str) -> bool:
        if not _is_valid_ip(ip):
            return False
        return self._delete_where(
            lambda c: c in (f'arpcut_ip_{ip}_in', f'arpcut_ip_{ip}_out'))

    def list_blocked_ips(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for comment, _ in self._list_tagged():
            m = re.match(r'arpcut_ip_(.+)_(in|out)$', comment)
            if m:
                out.append((m.group(1), m.group(2)))
        return out

    def block_all_for(self, iface: str, victim_ip: str) -> bool:
        return self.block_ip(iface, victim_ip, 'both')

    def unblock_all_for(self, victim_ip: str) -> bool:
        return self.unblock_ip(victim_ip)

    def block_port(self, iface: str, port: int, proto: str = 'tcp',
                   direction: str = 'both', target_ip=None) -> bool:
        if not _is_valid_port(port):
            return False
        protos = _norm_protos(proto)
        if not protos or (target_ip and not _is_valid_ip(target_ip)):
            return False
        self.ensure()
        existing = {c for c, _ in self._list_tagged()}
        scope = f'ip saddr {target_ip} ' if target_ip else ''
        ok = True
        for p in protos:
            comment = f'arpcut_port_{port}_{p}'
            if comment in existing:
                continue
            res = self._cmd(f'add rule {_NFT_FAMILY} {_NFT_TABLE} {_NFT_CHAIN} '
                            f'{scope}{p} dport {port} drop comment "{comment}"')
            ok = (res.returncode == 0) and ok
        return ok

    def unblock_port(self, port: int, proto: str = 'tcp') -> bool:
        protos = _norm_protos(proto)
        if not protos:
            return False
        wanted = {f'arpcut_port_{port}_{p}' for p in protos}
        return self._delete_where(lambda c: c in wanted)

    def list_blocked_ports(self) -> list[tuple[int, str, str]]:
        out: list[tuple[int, str, str]] = []
        for comment, _ in self._list_tagged():
            m = re.match(r'arpcut_port_(\d+)_(tcp|udp)$', comment)
            if m:
                out.append((int(m.group(1)), m.group(2), 'both'))
        return out

    def is_port_blocked(self, port: int) -> bool:
        return any(p == port for p, _, _ in self.list_blocked_ports())


_nft = _Nft()
