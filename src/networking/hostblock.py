"""Host blocklist — block network services by DNS name or verified IP, idempotently.

Two kinds of curated preset:

* **Domain presets** (e.g. PSN ``np.communication.playstation.net``) resolve to
  their *current* IPs at block time, so they survive IP rotation.
* **Static-IP presets** (e.g. the verified Rockstar GTA-Online save server) block
  known-good addresses directly.

Both flow through the same reconcile logic, tracking exactly which IPs each preset
put in the firewall, so ``unblock``/``refresh`` are precise and re-blocking is a
no-op. This replaces the ad-hoc ``COMMON_IPS`` list in the Port Blocker.

The PSN case is the on-host equivalent of the router-side Bind9/RPZ recipe in
``psn code.txt`` — no separate DNS/proxy server required.

Firewall operations are injected (defaulting to ``tools.firewall``) so the logic
is unit-testable without touching the real system firewall or the network.
"""
from __future__ import annotations

import logging
import random
import socket
import struct
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Union

log = logging.getLogger(__name__)

# Public resolvers to try when the system resolver returns nothing (broken or
# hijacked local DNS). Domains with no A record anywhere (e.g. the PSN comms
# name) still yield nothing — those need DNS-name interception, not IP blocking.
_PUBLIC_DNS = ('1.1.1.1', '8.8.8.8')

# Injected firewall surface: (iface, ip, direction) -> ok ; (ip) -> ok
BlockIpFn = Callable[[str, str, str], bool]
UnblockIpFn = Callable[[str], bool]
Resolver = Callable[[str], "set[str]"]


@dataclass(frozen=True)
class HostPreset:
    """A curated, named target the user can toggle.

    A preset may carry resolved ``domains``, verified static ``ips``, or both.
    ``method`` picks how it's enforced: ``'ip'`` resolves + firewall-blocks the IP
    (network-wide); ``'dns'`` intercepts a target device's DNS query for the name
    and answers NXDOMAIN — needed for names with no A record (e.g. PSN comms).
    """
    key: str
    label: str
    domains: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    note: str = ''
    method: str = 'ip'


# Curated, *verified* presets. Domains resolve live; static IPs are known-good.
# Keep this list correct — never pad it with guessed IPs.
PRESET_HOSTS: tuple[HostPreset, ...] = (
    HostPreset(
        key='psn-comms',
        label='PSN party / host-migration',
        domains=('np.communication.playstation.net',),
        method='dns',   # no A record → intercept the console's DNS query, not an IP
        note=('Select the console, then toggle: ArpCut intercepts its DNS lookup '
              'of the PSN comms server and returns NXDOMAIN — forcing host '
              'migration / keeping you host in P2P games. Toggle off to restore.'),
    ),
    HostPreset(
        key='gta-save',
        label='GTA Online — save block (Rockstar)',
        ips=('192.81.241.171',),
        note=('Blocks the Rockstar save server so GTA Online cannot commit a '
              'cloud save for the target — a verified session/save exploit. '
              'Static IP, kept because it is known-good.'),
    ),
)

PRESETS_BY_KEY: dict[str, HostPreset] = {p.key: p for p in PRESET_HOSTS}


def _looks_like_ipv4(value: str) -> bool:
    parts = value.split('.')
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _dns_a_query(domain: str, server: str, timeout: float = 3.0) -> set[str]:
    """Raw UDP DNS A-record query to a specific resolver (no root needed)."""
    tid = random.randint(0, 0xffff)
    pkt = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    pkt += b''.join(bytes([len(p)]) + p.encode() for p in domain.split('.')) + b'\x00'
    pkt += struct.pack('>HH', 1, 1)  # QTYPE=A, QCLASS=IN
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    qd, an = struct.unpack('>H', data[4:6])[0], struct.unpack('>H', data[6:8])[0]

    def skip_name(o: int) -> int:
        while True:
            length = data[o]
            if length == 0:
                return o + 1
            if length & 0xc0 == 0xc0:   # compression pointer
                return o + 2
            o += 1 + length

    off = 12
    for _ in range(qd):
        off = skip_name(off) + 4
    ips: set[str] = set()
    for _ in range(an):
        off = skip_name(off)
        rtype, _rclass, _ttl, rdlen = struct.unpack('>HHIH', data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.add('.'.join(str(b) for b in data[off:off + 4]))
        off += rdlen
    return ips


def resolve_ipv4(domain: str) -> set[str]:
    """Resolve a domain to its current IPv4 addresses (best-effort, never raises).

    Tries the system resolver first, then public resolvers directly if that
    yields nothing — so a broken/hijacked local DNS doesn't silently break blocks.
    """
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(domain, None, socket.AF_INET):
            ips.add(info[4][0])
    except (socket.gaierror, OSError) as exc:
        log.debug('system resolver could not resolve %s: %s', domain, exc)
    if ips:
        return ips
    for server in _PUBLIC_DNS:
        try:
            got = _dns_a_query(domain, server)
            if got:
                log.info('resolved %s via %s (system resolver had nothing)', domain, server)
                return got
        except OSError as exc:
            log.debug('public DNS %s failed for %s: %s', server, domain, exc)
    log.warning('Could not resolve %s (no A record anywhere?)', domain)
    return ips


@dataclass
class BlockResult:
    """Outcome of a block/refresh reconcile for one key."""
    key: str
    desired: set[str]
    added: set[str] = field(default_factory=set)
    removed: set[str] = field(default_factory=set)
    failed: set[str] = field(default_factory=set)

    @property
    def ok(self) -> bool:
        # No desired IPs (e.g. a domain that failed to resolve) is a soft failure.
        return not self.failed and bool(self.desired)


@dataclass
class _ActiveBlock:
    domains: tuple[str, ...]
    static_ips: tuple[str, ...]
    ips: set[str] = field(default_factory=set)  # IPs currently in the firewall


PresetOrTarget = Union[HostPreset, str, Iterable[str]]


class HostBlocklist:
    """Idempotently block services by domain name or verified IP.

    Per key it tracks the exact IP set it blocked, so re-blocking reconciles
    (add new, keep existing, no duplicates), ``refresh`` follows IP rotation, and
    ``unblock`` removes precisely what it added — nothing more.
    """

    def __init__(
        self,
        block_ip: Optional[BlockIpFn] = None,
        unblock_ip: Optional[UnblockIpFn] = None,
        resolver: Resolver = resolve_ipv4,
        direction: str = 'both',
    ) -> None:
        if block_ip is None or unblock_ip is None:
            # Bind to the real firewall lazily so tests need not import it.
            from tools import firewall
            block_ip = block_ip or firewall.block_ip
            unblock_ip = unblock_ip or firewall.unblock_ip
        self._block_ip = block_ip
        self._unblock_ip = unblock_ip
        self._resolve = resolver
        self._direction = direction
        self._blocks: dict[str, _ActiveBlock] = {}

    @staticmethod
    def _target_parts(target: PresetOrTarget) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
        """Return (key, domains, static_ips) for any accepted target form."""
        if isinstance(target, HostPreset):
            return target.key, target.domains, target.ips
        if isinstance(target, str):
            preset = PRESETS_BY_KEY.get(target)
            if preset:
                return preset.key, preset.domains, preset.ips
            if _looks_like_ipv4(target):
                return target, (), (target,)
            return target, (target,), ()          # bare domain, keyed by itself
        # iterable of raw domains/IPs
        items = tuple(target)
        domains = tuple(i for i in items if not _looks_like_ipv4(i))
        ips = tuple(i for i in items if _looks_like_ipv4(i))
        return ','.join(sorted(items)), domains, ips

    def _desired(self, domains: Iterable[str], static_ips: Iterable[str]) -> set[str]:
        desired: set[str] = set(static_ips)
        for domain in domains:
            desired |= self._resolve(domain)
        return desired

    def block(self, target: PresetOrTarget, iface: str) -> BlockResult:
        """Block any of ``target``'s IPs not already blocked under its key."""
        key, domains, static_ips = self._target_parts(target)
        desired = self._desired(domains, static_ips)
        record = self._blocks.setdefault(
            key, _ActiveBlock(domains=domains, static_ips=static_ips))
        record.domains, record.static_ips = domains, static_ips

        result = BlockResult(key=key, desired=desired)
        for ip in desired - record.ips:
            if self._block_ip(iface, ip, self._direction):
                record.ips.add(ip)
                result.added.add(ip)
            else:
                result.failed.add(ip)
        if not record.ips:
            self._blocks.pop(key, None)
        return result

    def unblock(self, key: str) -> bool:
        """Remove exactly the IPs blocked under ``key``."""
        record = self._blocks.pop(key, None)
        if not record:
            return True  # unblocking something not blocked is a no-op success
        ok = True
        for ip in record.ips:
            ok = self._unblock_ip(ip) and ok
        return ok

    def refresh(self, iface: str) -> dict[str, BlockResult]:
        """Re-resolve every active key and reconcile rules to the new IP set."""
        results: dict[str, BlockResult] = {}
        for key, record in list(self._blocks.items()):
            desired = self._desired(record.domains, record.static_ips)
            result = BlockResult(key=key, desired=desired)
            for ip in record.ips - desired:               # stale → remove
                if self._unblock_ip(ip):
                    record.ips.discard(ip)
                    result.removed.add(ip)
            for ip in desired - record.ips:               # new → add
                if self._block_ip(iface, ip, self._direction):
                    record.ips.add(ip)
                    result.added.add(ip)
                else:
                    result.failed.add(ip)
            if not record.ips:
                self._blocks.pop(key, None)
            results[key] = result
        return results

    def active(self) -> dict[str, set[str]]:
        """Map of key → currently-blocked IPs."""
        return {key: set(rec.ips) for key, rec in self._blocks.items()}

    def is_active(self, key: str) -> bool:
        return bool(self._blocks.get(key))
