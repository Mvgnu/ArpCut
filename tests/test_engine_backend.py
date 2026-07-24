"""Engine-backend wiring: RemoteEngine↔HelperServer over a real socket, the
Controller driving a mock engine, and interface parity between the two backends.

This is how we verify the unprivileged (helper) path without needing root: the
loopback exercises the exact wire protocol the GUI uses against the real
HelperServer + dispatch table.
"""
import os
import socket
import tempfile
import threading
import time

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from PySide6.QtWidgets import QApplication  # noqa: E402

from privilege.helper import HelperServer  # noqa: E402
from privilege.client import HelperClient  # noqa: E402
from privilege.remote import RemoteEngine  # noqa: E402

_app = QApplication.instance() or QApplication([])

FAKE = [
    {'ip': '192.168.1.10', 'mac': 'aa:bb:cc:dd:ee:01', 'vendor': 'Apple', 'type': 'Me', 'name': '', 'admin': True},
    {'ip': '192.168.1.1', 'mac': 'aa:bb:cc:dd:ee:02', 'vendor': 'Netgear', 'type': 'Router', 'name': '', 'admin': True},
    {'ip': '192.168.1.42', 'mac': 'aa:bb:cc:dd:ee:03', 'vendor': 'Sony', 'type': 'User', 'name': 'PS5', 'admin': False},
    {'ip': '192.168.1.55', 'mac': 'aa:bb:cc:dd:ee:04', 'vendor': 'Samsung', 'type': 'User', 'name': '-', 'admin': False},
]
PS5 = FAKE[2]['mac']


class MockEngine:
    """Full engine surface; records calls and returns JSON-friendly data."""

    def __init__(self):
        self.calls = []
        self.on_flows = None       # wired by the server on 'subscribe'

    def _rec(self, name, *a):
        self.calls.append((name, *a))
        return True

    def cleanup(self):
        return self._rec('cleanup')

    def status(self):
        return {'admin': True, 'iface': 'en0', 'my_ip': '192.168.1.10',
                'gateway_ip': '192.168.1.1', 'gateway_mac': 'aa:bb:cc:dd:ee:02',
                'device_count': len(FAKE)}

    def set_iface(self, name):
        self._rec('set_iface', name)
        return {'iface': name}

    def set_scan_params(self, count, threads):
        return self._rec('set_scan_params', count, threads)

    def scan(self, scan_type):
        self._rec('scan', scan_type)
        return FAKE

    def devices(self):
        return FAKE

    def probe(self, ip):
        self._rec('probe', ip)
        return [ip, 'aa:bb:cc:dd:ee:09']

    def kill(self, mac):
        return self._rec('kill', mac)

    def unkill(self, mac):
        return self._rec('unkill', mac)

    def kill_all(self):
        return self._rec('kill_all')

    def unkill_all(self):
        return self._rec('unkill_all')

    def one_way_kill(self, mac):
        return self._rec('one_way_kill', mac)

    def block_all_for(self, ip):
        return self._rec('block_all_for', ip)

    def unblock_all_for(self, ip):
        return self._rec('unblock_all_for', ip)

    def block_ip(self, ip, direction='both'):
        return self._rec('block_ip', ip, direction)

    def unblock_ip(self, ip):
        return self._rec('unblock_ip', ip)

    def block_port(self, port, proto='tcp', direction='both', target_ip=None):
        return self._rec('block_port', port, proto, target_ip)

    def unblock_port(self, port, proto='tcp'):
        return self._rec('unblock_port', port, proto)

    def list_blocked_ports(self):
        return [[3074, 'udp', 'both']]

    def list_blocked_ips(self):
        return [['1.2.3.4', 'both']]

    def block_host(self, target, iface=None):
        self._rec('block_host', target, iface)
        return {'key': 'psn-comms', 'added': ['1.1.1.1'], 'removed': [],
                'failed': [], 'desired': ['1.1.1.1'], 'ok': True}

    def unblock_host(self, key):
        return self._rec('unblock_host', key)

    def refresh_hosts(self):
        return {}

    def active_host_blocks(self):
        return {'psn-comms': ['1.1.1.1']}

    def set_forwarding(self, enabled):
        return self._rec('set_forwarding', enabled)

    def start_sniff(self, ip):
        self._rec('start_sniff', ip)
        if self.on_flows:  # simulate the sniffer pushing a flow
            self.on_flows([{'dst': '1.1.1.1', 'port': 443, 'proto': 'TCP', 'bytes': 10, 'packets': 1}])
        return True

    def dns_block(self, ip, domains):
        return self._rec('dns_block', ip, tuple(domains))

    def dns_unblock(self, ip):
        return self._rec('dns_unblock', ip)

    def active_dns_blocks(self):
        return {'192.168.1.42': ['np.communication.playstation.net']}

    def stop_sniff(self):
        return self._rec('stop_sniff')

    def flows(self):
        return [{'dst': '8.8.8.8', 'port': 53, 'proto': 'UDP', 'bytes': 100, 'packets': 2}]


class _Server:
    """A real AF_UNIX HelperServer in a thread — the actual wire path."""

    def __init__(self, engine):
        self.engine = engine
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 's.sock')
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(5)
        threading.Thread(target=HelperServer(engine).serve_forever,
                         args=(self.sock,), daemon=True).start()

    def remote(self):
        r = RemoteEngine(sock_path=self.path)
        assert r.available()   # connects + subscribes over the real socket
        return r


# ---- RemoteEngine ↔ HelperServer over a real socket ------------------------

def test_remote_roundtrips_every_command():
    eng = MockEngine()
    remote = _Server(eng).remote()

    assert remote.available() is True
    assert remote.status()['iface'] == 'en0'
    assert remote.scan('arp') == FAKE
    assert remote.devices()[2]['mac'] == PS5
    assert remote.probe('192.168.1.99') == ['192.168.1.99', 'aa:bb:cc:dd:ee:09']
    assert remote.kill(PS5) is True
    assert remote.unkill(PS5) is True
    assert remote.one_way_kill(PS5) is True
    assert remote.block_all_for('192.168.1.42') is True
    assert remote.unblock_all_for('192.168.1.42') is True
    assert remote.block_ip('192.168.1.42', 'out') is True
    assert remote.unblock_ip('192.168.1.42') is True
    assert remote.block_port(3074, 'udp', 'both', '192.168.1.42') is True
    assert remote.unblock_port(3074, 'udp') is True
    assert remote.list_blocked_ports() == [[3074, 'udp', 'both']]
    assert remote.list_blocked_ips() == [['1.2.3.4', 'both']]
    assert remote.block_host('psn-comms')['key'] == 'psn-comms'
    assert remote.unblock_host('psn-comms') is True
    assert remote.active_host_blocks() == {'psn-comms': ['1.1.1.1']}
    assert remote.set_forwarding(True) is True
    assert remote.start_sniff('192.168.1.42') is True
    assert remote.flows()[0]['dst'] == '8.8.8.8'
    assert remote.stop_sniff() is True
    assert remote.dns_block('192.168.1.42', ['np.communication.playstation.net']) is True
    assert remote.active_dns_blocks()['192.168.1.42'][0].endswith('playstation.net')
    assert remote.dns_unblock('192.168.1.42') is True

    # the calls really reached the engine on the other side of the socket
    assert ('kill', PS5) in eng.calls
    assert ('block_all_for', '192.168.1.42') in eng.calls
    assert ('start_sniff', '192.168.1.42') in eng.calls


def test_remote_bad_arg_rejected_before_engine():
    eng = MockEngine()
    remote = _Server(eng).remote()
    try:
        remote.kill('not-a-mac')
        assert False, 'should have raised'
    except Exception as exc:
        assert 'invalid argument' in str(exc)
    assert not any(c[0] == 'kill' for c in eng.calls)  # never reached the engine


def test_flows_are_pushed_over_the_session():
    eng = MockEngine()
    remote = _Server(eng).remote()
    received = []
    remote.on_flows = received.append
    remote.start_sniff('192.168.1.42')  # engine pushes a flow event to the session
    for _ in range(100):
        if received:
            break
        time.sleep(0.02)
    assert received and received[0][0]['dst'] == '1.1.1.1'  # arrived by push, no poll


def test_session_drop_restores_everything():
    eng = MockEngine()
    remote = _Server(eng).remote()
    remote.kill(PS5)          # something is now "blocked"
    remote.close()            # GUI goes away (quit / crash)
    for _ in range(100):
        if any(c[0] == 'cleanup' for c in eng.calls):
            break
        time.sleep(0.02)
    # the helper restored everything on the dropped session — no orphaned block
    assert any(c[0] == 'cleanup' for c in eng.calls)


# ---- Controller drives the engine (mock ops, no scapy/root) ----------------

def _ctrl(ops):
    from gui.controller import Controller
    c = Controller(ops=ops)
    c._devices = list(FAKE)
    c._iface = 'en0'
    c._admin = True
    c._privileged = True
    return c


def test_controller_cut_is_arp_plus_firewall():
    ops = MockEngine()
    c = _ctrl(ops)
    c.toggle_cut(PS5)
    assert ('kill', PS5) in ops.calls
    assert ('block_all_for', '192.168.1.42') in ops.calls
    assert PS5 in c._cut and c.state_of(FAKE[2])['cut'] is True
    c.toggle_cut(PS5)  # restore
    assert ('unblock_all_for', '192.168.1.42') in ops.calls
    assert PS5 not in c._cut


def test_controller_one_way_and_kill_all():
    ops = MockEngine()
    c = _ctrl(ops)
    c.toggle_one_way(PS5)
    assert ('one_way_kill', PS5) in ops.calls and PS5 in c.one_way_kills
    c.kill_all()
    cut_ips = {ip for (name, ip) in ops.calls if name == 'block_all_for'}
    assert '192.168.1.42' in cut_ips and '192.168.1.55' in cut_ips  # both users
    assert '192.168.1.1' not in cut_ips                             # router spared


def test_controller_monitor_forwards_and_sniffs():
    ops = MockEngine()
    c = _ctrl(ops)
    assert c.start_monitor(PS5) is True
    assert ('set_forwarding', True) in ops.calls
    assert ('kill', PS5) in ops.calls
    assert ('start_sniff', '192.168.1.42') in ops.calls
    assert c.state_of(FAKE[2])['monitor'] is True
    assert c.flows()[0]['dst'] == '8.8.8.8'
    c.stop_monitor(PS5)
    assert ('stop_sniff',) in ops.calls and PS5 not in c._monitoring


def test_controller_dns_block_mitms_then_intercepts():
    ops = MockEngine()
    c = _ctrl(ops)
    c.dns_block(PS5, ['np.communication.playstation.net'])
    assert ('set_forwarding', True) in ops.calls   # forwarding so device stays online
    assert ('kill', PS5) in ops.calls              # MITM so its DNS flows through us
    assert any(x[0] == 'dns_block' and x[1] == '192.168.1.42' for x in ops.calls)
    assert c.is_dns_blocked(PS5) and c.state_of(FAKE[2])['dns'] is True
    c.dns_unblock(PS5)
    assert ('dns_unblock', '192.168.1.42') in ops.calls and not c.is_dns_blocked(PS5)


# ---- both backends present the same surface --------------------------------

def test_local_and_remote_share_interface():
    from privilege.helper import Engine as LocalEngine
    surface = ['status', 'set_iface', 'set_scan_params', 'scan', 'devices', 'probe',
               'kill', 'unkill', 'kill_all', 'unkill_all', 'one_way_kill',
               'block_all_for', 'unblock_all_for', 'block_ip', 'unblock_ip',
               'block_port', 'unblock_port', 'list_blocked_ports', 'list_blocked_ips',
               'block_host', 'unblock_host', 'refresh_hosts', 'active_host_blocks',
               'set_forwarding', 'start_sniff', 'stop_sniff', 'flows']
    for name in surface:
        assert callable(getattr(LocalEngine, name, None)), f'LocalEngine.{name}'
        assert callable(getattr(RemoteEngine, name, None)), f'RemoteEngine.{name}'
