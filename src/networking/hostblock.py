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
import secrets
import socket
import struct
import threading
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
    labels = domain.rstrip('.').encode('idna').split(b'.')
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError('Invalid DNS name')
    question = b''.join(bytes([len(label)]) + label for label in labels) + b'\x00'
    if len(question) > 255:
        raise ValueError('DNS name too long')
    question += struct.pack('>HH', 1, 1)  # QTYPE=A, QCLASS=IN
    tid = secrets.randbits(16)
    pkt = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    pkt += question
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, sender = s.recvfrom(4096)
    finally:
        s.close()
    if sender != (server, 53):
        return set()
    return _parse_dns_a_response(data, tid, question)


def _parse_dns_a_response(data: bytes, tid: int, question: bytes) -> set[str]:
    """Reject mismatched/truncated DNS datagrams before consuming answers."""
    if len(data) < 12:
        raise ValueError('Truncated DNS header')
    got_tid, flags, qd, an, _, _ = struct.unpack('>HHHHHH', data[:12])
    if (got_tid != tid or not flags & 0x8000 or flags & 0x7a0f
            or qd != 1 or data[12:12 + len(question)] != question):
        return set()

    def skip_name(o: int) -> int:
        while True:
            if o >= len(data):
                raise ValueError('Truncated DNS name')
            length = data[o]
            if length == 0:
                return o + 1
            if length & 0xc0 == 0xc0:   # compression pointer
                if o + 1 >= len(data) or ((length & 0x3f) << 8 | data[o + 1]) >= len(data):
                    raise ValueError('Invalid DNS compression pointer')
                return o + 2
            if length > 63 or o + 1 + length >= len(data):
                raise ValueError('Invalid DNS label')
            o += 1 + length

    off = 12 + len(question)
    ips: set[str] = set()
    for _ in range(an):
        off = skip_name(off)
        if off + 10 > len(data):
            raise ValueError('Truncated DNS answer')
        rtype, _rclass, _ttl, rdlen = struct.unpack('>HHIH', data[off:off + 10])
        off += 10
        if off + rdlen > len(data):
            raise ValueError('Truncated DNS data')
        if rtype == 1 and _rclass == 1 and rdlen == 4:
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
    except (OSError, UnicodeError, ValueError) as exc:
        log.debug('system resolver could not resolve %s: %s', domain, exc)
    if ips:
        return ips
    for server in _PUBLIC_DNS:
        try:
            got = _dns_a_query(domain, server)
            if got:
                log.info('resolved %s via %s (system resolver had nothing)', domain, server)
                return got
        except (OSError, ValueError, struct.error) as exc:
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
        self._lock = threading.RLock()

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
        with self._lock:
            record = self._blocks.setdefault(
                key, _ActiveBlock(domains=domains, static_ips=static_ips))
            record.domains, record.static_ips = domains, static_ips

            result = BlockResult(key=key, desired=desired)
            for ip in desired - record.ips:
                if self._shared(ip, key) or self._block_ip(iface, ip, self._direction):
                    record.ips.add(ip)
                    result.added.add(ip)
                else:
                    result.failed.add(ip)
            if not record.ips:
                self._blocks.pop(key, None)
        return result

    def _shared(self, ip: str, key: str) -> bool:
        """Whether another active key still owns the same firewall rule."""
        return any(ip in rec.ips for name, rec in self._blocks.items() if name != key)

    def unblock(self, key: str) -> bool:
        """Remove exactly the IPs blocked under ``key``."""
        with self._lock:
            record = self._blocks.get(key)
            if not record:
                return True  # unblocking something not blocked is a no-op success
            for ip in set(record.ips):
                if self._shared(ip, key) or self._unblock_ip(ip):
                    record.ips.discard(ip)
            if record.ips:
                return False  # retain failed deletions so a later cleanup can retry
            self._blocks.pop(key, None)
            return True

    def clear(self) -> bool:
        """Remove all owned rules, retaining any failed deletion for retry."""
        with self._lock:
            ok = True
            for key in list(self._blocks):
                ok = self.unblock(key) and ok
            return ok

    def refresh(self, iface: str) -> dict[str, BlockResult]:
        """Re-resolve every active key and reconcile rules to the new IP set."""
        results: dict[str, BlockResult] = {}
        with self._lock:
            for key, record in list(self._blocks.items()):
                desired = self._desired(record.domains, record.static_ips)
                result = BlockResult(key=key, desired=desired)
                # A transient DNS failure must not forget rules we still own.
                if not desired:
                    results[key] = result
                    continue
                for ip in record.ips - desired:               # stale → remove
                    if self._shared(ip, key) or self._unblock_ip(ip):
                        record.ips.discard(ip)
                        result.removed.add(ip)
                    else:
                        result.failed.add(ip)
                for ip in desired - record.ips:               # new → add
                    if self._shared(ip, key) or self._block_ip(iface, ip, self._direction):
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
        with self._lock:
            return {key: set(rec.ips) for key, rec in self._blocks.items()}

    def is_active(self, key: str) -> bool:
        with self._lock:
            return bool(self._blocks.get(key))
