"""DnsSpoofer packet logic — name matching + NXDOMAIN forging (no root, no send).

Verifies the RPZ-style interception: a blocked device's query for a blocked name
produces a forged NXDOMAIN reply addressed back to that device; anything else is
left alone.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import scapy.all as sc  # noqa: E402
from scapy.all import DNS, DNSQR, Ether, IP, UDP  # noqa: E402

from networking.dnsblock import DnsSpoofer, _name_blocked  # noqa: E402

PSN = 'np.communication.playstation.net'


def test_name_blocked_matches_name_and_subdomains_only():
    doms = {PSN}
    assert _name_blocked(PSN, doms)
    assert _name_blocked('NP.Communication.PlayStation.Net.', doms)  # case + trailing dot
    assert _name_blocked('foo.' + PSN, doms)                          # subdomain
    assert not _name_blocked('playstation.net', doms)                 # parent, not blocked
    assert not _name_blocked(PSN + '.attacker.com', doms)             # suffix trick


def _query(qname, src='10.0.0.5', dst='10.0.0.1', tid=0x1234):
    return (Ether(src='aa:bb:cc:dd:ee:05', dst='11:22:33:44:55:66') /
            IP(src=src, dst=dst) / UDP(sport=5353, dport=53) /
            DNS(id=tid, rd=1, qd=DNSQR(qname=qname)))


def test_blocked_query_gets_forged_nxdomain(monkeypatch):
    sent = []
    monkeypatch.setattr(sc, 'sendp', lambda pkt, **k: sent.append(pkt))

    sp = DnsSpoofer('lo0')
    sp._targets = {'10.0.0.5': {PSN}}

    sp._process(_query(PSN))
    assert len(sent) == 1
    r = sent[0]
    assert r[DNS].id == 0x1234 and r[DNS].qr == 1 and r[DNS].rcode == 3  # NXDOMAIN
    assert r[IP].dst == '10.0.0.5'          # reply goes back to the console
    assert r[IP].src == '10.0.0.1'          # spoofed as its resolver
    assert r[UDP].dport == 5353             # matches the query's source port


def test_non_blocked_or_wrong_target_is_ignored(monkeypatch):
    sent = []
    monkeypatch.setattr(sc, 'sendp', lambda pkt, **k: sent.append(pkt))

    sp = DnsSpoofer('lo0')
    sp._targets = {'10.0.0.5': {PSN}}

    sp._process(_query('www.google.com'))          # not a blocked name
    sp._process(_query(PSN, src='10.0.0.9'))       # not a blocked target
    assert sent == []


def test_active_reports_targets_and_names():
    sp = DnsSpoofer('lo0')
    sp._targets = {'10.0.0.5': {PSN}}
    assert sp.active() == {'10.0.0.5': [PSN]}


# -- WinDivert forward-drop decision (fail-safe) -----------------------------

def _query_payload(qname, tid=0x1234):
    return bytes(DNS(id=tid, rd=1, qd=DNSQR(qname=qname)))


def test_should_drop_only_blocked_query():
    sp = DnsSpoofer('lo0')
    sp._targets = {'10.0.0.5': {PSN}}
    # blocked name from a targeted source → drop the forwarded query
    assert sp._should_drop_query('10.0.0.5', _query_payload(PSN)) is True
    assert sp._should_drop_query('10.0.0.5', _query_payload('sub.' + PSN)) is True


def test_should_not_drop_allowed_or_wrong_source():
    sp = DnsSpoofer('lo0')
    sp._targets = {'10.0.0.5': {PSN}}
    assert sp._should_drop_query('10.0.0.5', _query_payload('www.google.com')) is False
    assert sp._should_drop_query('10.0.0.9', _query_payload(PSN)) is False   # wrong source
    # a DNS *response* (qr=1) is not a query → never dropped
    resp = bytes(DNS(id=1, qr=1, qd=DNSQR(qname=PSN)))
    assert sp._should_drop_query('10.0.0.5', resp) is False


def test_should_not_drop_on_garbage_payload():
    sp = DnsSpoofer('lo0')
    sp._targets = {'10.0.0.5': {PSN}}
    assert sp._should_drop_query('10.0.0.5', b'') is False
    assert sp._should_drop_query('10.0.0.5', b'\x00\x01\x02not-dns') is False
