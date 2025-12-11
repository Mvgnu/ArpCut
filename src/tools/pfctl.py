import sys
from subprocess import run, PIPE

ANCHOR = 'com.arpcut'


def _exec(cmd):
    return run(cmd, shell=True, stdout=PIPE, stderr=PIPE, text=True)


def ensure_pf_enabled():
    if sys.platform != 'darwin':
        return True
    status = _exec('pfctl -s info')
    if status.returncode != 0:
        return False
    if 'Status: Enabled' in status.stdout:
        return True
    # Try to enable
    en = _exec('pfctl -E')
    return en.returncode == 0


def _anchor_file():
    return f'/etc/pf.anchors/{ANCHOR}'


def install_anchor():
    if sys.platform != 'darwin':
        return True
    # Ensure anchor file exists
    _exec(f"sh -c 'test -f {_anchor_file()} || : > {_anchor_file()}'")
    # Ensure pf.conf references our anchor (append at end to keep rule order valid)
    try:
        with open('/etc/pf.conf', 'r') as f:
            conf = f.read()
        if f'anchor "{ANCHOR}"' not in conf and f'load anchor "{ANCHOR}"' not in conf:
            with open('/etc/pf.conf', 'a') as f:
                f.write(f"\n# ArpCut anchor\nanchor \"{ANCHOR}\"\nload anchor \"{ANCHOR}\" from \"{_anchor_file()}\"\n")
    except Exception:
        return False
    # Load anchor explicitly (avoid full pf.conf reload errors)
    _exec(f"pfctl -a {ANCHOR} -f {_anchor_file()}")
    return True


def list_rules():
    if sys.platform != 'darwin':
        return []
    res = _exec(f'pfctl -a {ANCHOR} -s rules')
    return res.stdout.splitlines() if res.returncode == 0 else []


def block_dst(iface: str, victim_ip: str, dst_ip: str, port: int | None = None, proto: str | None = None):
    if sys.platform != 'darwin':
        # Windows: use netsh advfirewall (simplified - block destination IP)
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
    port_clause = f' port = {port}' if port else ''
    proto_clause = f' proto {proto.lower()}' if proto and proto.upper() in ['TCP','UDP'] else ''
    rule = f'block drop quick out on {iface}{proto_clause} from {victim_ip} to {dst_ip}{port_clause}'
    # Append rule to anchor
    _exec(f"sh -c 'echo " + '"' + f"{rule}" + '"' + f" >> {_anchor_file()}'")
    _exec(f"pfctl -a {ANCHOR} -f {_anchor_file()}")
    return True


def unblock_dst(dst_ip: str, port: int | None = None):
    if sys.platform != 'darwin':
        # Windows: remove firewall rule by name pattern
        if sys.platform.startswith('win'):
            # List rules and delete matching ones
            list_cmd = 'netsh advfirewall firewall show rule name=all dir=out'
            res = _exec(list_cmd)
            if res.returncode == 0:
                lines = res.stdout.splitlines()
                rule_name = None
                for line in lines:
                    if 'arpcut' in line.lower() and dst_ip.replace('.', '_') in line:
                        # Extract rule name from line like "Rule Name: elmocut_..."
                        if 'Rule Name:' in line:
                            rule_name = line.split('Rule Name:')[1].strip()
                            _exec(f'netsh advfirewall firewall delete rule name="{rule_name}"')
            return True
        return False
    # Safely rewrite the anchor file without shell quoting issues
    try:
        path = _anchor_file()
        with open(path, 'r') as f:
            lines = f.readlines()
        with open(path, 'w') as f:
            for line in lines:
                if dst_ip not in line:
                    f.write(line)
        _exec(f"pfctl -a {ANCHOR} -f {path}")
        return True
    except Exception:
        return False


def export_rules(path: str):
    try:
        with open(_anchor_file(), 'r') as src, open(path, 'w') as dst:
            dst.write(src.read())
        return True
    except Exception:
        return False


def import_rules(path: str):
    try:
        with open(path, 'r') as src, open(_anchor_file(), 'w') as dst:
            dst.write(src.read())
        _exec(f"pfctl -a {ANCHOR} -f {_anchor_file()}")
        return True
    except Exception:
        return False


def is_blocked(dst_ip: str) -> bool:
    if sys.platform != 'darwin':
        return False
    rules = list_rules()
    return any(dst_ip in r for r in rules)


def pf_self_check() -> bool:
    if sys.platform != 'darwin':
        # Windows: check if firewall is accessible
        if sys.platform.startswith('win'):
            res = _exec('netsh advfirewall show allprofiles state')
            return res.returncode == 0 and 'ON' in res.stdout
        return True
    if not ensure_pf_enabled():
        return False
    return install_anchor()


def block_all_for(iface: str, victim_ip: str) -> bool:
    if sys.platform != 'darwin':
        # Windows: use netsh advfirewall
        if sys.platform.startswith('win'):
            rule_name = f'arpcut_block_{victim_ip.replace(".", "_")}'
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={victim_ip} enable=yes'
            res = _exec(cmd)
            return res.returncode == 0
        return False
    rule = f'block drop quick out on {iface} from {victim_ip} to any'
    _exec(f"sh -c 'echo " + '"' + f"{rule}" + '"' + f" >> {_anchor_file()}'")
    _exec(f"pfctl -a {ANCHOR} -f {_anchor_file()}")
    return True


def unblock_all_for(victim_ip: str) -> bool:
    if sys.platform != 'darwin':
        # Windows: remove firewall rule
        if sys.platform.startswith('win'):
            rule_name = f'arpcut_block_{victim_ip.replace(".", "_")}'
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            _exec(cmd)  # Ignore return code (rule may not exist)
            return True
        return False
    try:
        path = _anchor_file()
        with open(path, 'r') as f:
            lines = f.readlines()
        with open(path, 'w') as f:
            for line in lines:
                if f'from {victim_ip} ' not in line:
                    f.write(line)
        _exec(f"pfctl -a {ANCHOR} -f {path}")
        return True
    except Exception:
        return False


def pf_test_roundtrip(iface: str, victim_ip: str) -> bool:
    if sys.platform != 'darwin':
        return True
    tmp_ip = '203.0.113.9'
    ok1 = block_all_for(iface, victim_ip)
    rules = list_rules()
    present = any(victim_ip in r for r in rules)
    ok2 = unblock_all_for(victim_ip)
    return ok1 and present and ok2


# ============== IP BLOCKING ==============

def block_ip(iface: str, ip: str, direction: str = 'both') -> bool:
    """Block all traffic to/from a specific IP."""
    if sys.platform == 'darwin':
        rules = []
        if direction in ('in', 'both'):
            rules.append(f'block drop quick in on {iface} from {ip} to any')
        if direction in ('out', 'both'):
            rules.append(f'block drop quick out on {iface} from any to {ip}')
        for rule in rules:
            _exec(f"sh -c 'echo " + '"' + f"{rule}" + '"' + f" >> {_anchor_file()}'")
        _exec(f"pfctl -a {ANCHOR} -f {_anchor_file()}")
        return True
    elif sys.platform.startswith('win'):
        rule_name = f'arpcut_ip_{ip.replace(".", "_")}'
        if direction in ('in', 'both'):
            _exec(f'netsh advfirewall firewall add rule name="{rule_name}_in" dir=in action=block remoteip={ip} enable=yes')
        if direction in ('out', 'both'):
            _exec(f'netsh advfirewall firewall add rule name="{rule_name}_out" dir=out action=block remoteip={ip} enable=yes')
        return True
    return False


def unblock_ip(ip: str) -> bool:
    """Remove IP blocking rules."""
    if sys.platform == 'darwin':
        try:
            path = _anchor_file()
            with open(path, 'r') as f:
                lines = f.readlines()
            with open(path, 'w') as f:
                for line in lines:
                    if f'from {ip} ' not in line and f'to {ip}' not in line:
                        f.write(line)
            _exec(f"pfctl -a {ANCHOR} -f {path}")
            return True
        except Exception:
            return False
    elif sys.platform.startswith('win'):
        rule_name = f'arpcut_ip_{ip.replace(".", "_")}'
        _exec(f'netsh advfirewall firewall delete rule name="{rule_name}_in"')
        _exec(f'netsh advfirewall firewall delete rule name="{rule_name}_out"')
        return True
    return False


def list_blocked_ips() -> list:
    """Return list of blocked IPs as [(ip, direction), ...]"""
    blocked = []
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
                        direction = 'in' if ' in on ' in rule else 'out'
                        if from_ip != 'any':
                            blocked.append((from_ip, direction))
                        elif to_ip != 'any':
                            blocked.append((to_ip, direction))
                except (ValueError, IndexError):
                    pass
    elif sys.platform.startswith('win'):
        res = _exec('netsh advfirewall firewall show rule name=all')
        if res.returncode == 0:
            current_rule = {}
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith('Rule Name:'):
                    name = line.split(':', 1)[1].strip()
                    if 'arpcut_ip_' in name.lower():
                        parts = name.split('_')
                        if len(parts) >= 6:
                            ip = '.'.join(parts[2:6])
                            direction = parts[-1] if parts[-1] in ('in', 'out') else 'both'
                            blocked.append((ip, direction))
    return blocked


# ============== PORT BLOCKING ==============

def block_port(iface: str, port: int, proto: str = 'tcp', direction: str = 'both') -> bool:
    """
    Block a specific port on the network interface.
    direction: 'in', 'out', or 'both'
    """
    if sys.platform == 'darwin':
        rules = []
        if direction in ('in', 'both'):
            rules.append(f'block drop quick in on {iface} proto {proto} from any to any port = {port}')
        if direction in ('out', 'both'):
            rules.append(f'block drop quick out on {iface} proto {proto} from any to any port = {port}')
        for rule in rules:
            _exec(f"sh -c 'echo " + '"' + f"{rule}" + '"' + f" >> {_anchor_file()}'")
        _exec(f"pfctl -a {ANCHOR} -f {_anchor_file()}")
        return True
    elif sys.platform.startswith('win'):
        rule_name = f'arpcut_port_{port}_{proto}'
        if direction in ('in', 'both'):
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}_in" dir=in action=block protocol={proto} localport={port} enable=yes'
            _exec(cmd)
        if direction in ('out', 'both'):
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}_out" dir=out action=block protocol={proto} localport={port} enable=yes'
            _exec(cmd)
        return True
    return False


def unblock_port(port: int, proto: str = 'tcp') -> bool:
    """Remove port blocking rules for the specified port."""
    if sys.platform == 'darwin':
        try:
            path = _anchor_file()
            with open(path, 'r') as f:
                lines = f.readlines()
            with open(path, 'w') as f:
                for line in lines:
                    if f'port = {port}' not in line:
                        f.write(line)
            _exec(f"pfctl -a {ANCHOR} -f {path}")
            return True
        except Exception:
            return False
    elif sys.platform.startswith('win'):
        rule_name = f'arpcut_port_{port}_{proto}'
        _exec(f'netsh advfirewall firewall delete rule name="{rule_name}_in"')
        _exec(f'netsh advfirewall firewall delete rule name="{rule_name}_out"')
        return True
    return False


def is_port_blocked(port: int) -> bool:
    """Check if a port is currently blocked."""
    if sys.platform == 'darwin':
        rules = list_rules()
        return any(f'port = {port}' in r for r in rules)
    elif sys.platform.startswith('win'):
        res = _exec(f'netsh advfirewall firewall show rule name="arpcut_port_{port}_tcp_in"')
        return 'arpcut_port' in res.stdout.lower()
    return False


def list_blocked_ports() -> list:
    """Return list of currently blocked ports as [(port, proto, direction), ...]"""
    blocked = []
    if sys.platform == 'darwin':
        rules = list_rules()
        for rule in rules:
            if 'port =' in rule:
                # Parse rule like: block drop quick in on en0 proto tcp from any to any port = 443
                parts = rule.split()
                try:
                    port_idx = parts.index('port')
                    port = int(parts[port_idx + 2])
                    proto = 'tcp'
                    if 'proto' in parts:
                        proto_idx = parts.index('proto')
                        proto = parts[proto_idx + 1]
                    direction = 'in' if ' in on ' in rule else 'out'
                    blocked.append((port, proto, direction))
                except (ValueError, IndexError):
                    pass
    return blocked


def clear_all_port_blocks() -> bool:
    """Remove all port blocking rules."""
    if sys.platform == 'darwin':
        try:
            path = _anchor_file()
            with open(path, 'r') as f:
                lines = f.readlines()
            with open(path, 'w') as f:
                for line in lines:
                    if 'port =' not in line:
                        f.write(line)
            _exec(f"pfctl -a {ANCHOR} -f {path}")
            return True
        except Exception:
            return False
    elif sys.platform.startswith('win'):
        # Delete all arpcut_port rules
        res = _exec('netsh advfirewall firewall show rule name=all')
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if 'arpcut_port' in line.lower() and 'Rule Name:' in line:
                    rule_name = line.split('Rule Name:')[1].strip()
                    _exec(f'netsh advfirewall firewall delete rule name="{rule_name}"')
        return True
    return False


