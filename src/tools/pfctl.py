import sys
from subprocess import run, PIPE

ANCHOR = 'com.elmocut'


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
                f.write(f"\n# elmoCut anchor\nanchor \"{ANCHOR}\"\nload anchor \"{ANCHOR}\" from \"{_anchor_file()}\"\n")
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
            rule_name = f'elmocut_{victim_ip.replace(".", "_")}_to_{dst_ip.replace(".", "_")}'
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
                    if 'elmocut' in line.lower() and dst_ip.replace('.', '_') in line:
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
            rule_name = f'elmocut_block_{victim_ip.replace(".", "_")}'
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
            rule_name = f'elmocut_block_{victim_ip.replace(".", "_")}'
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


