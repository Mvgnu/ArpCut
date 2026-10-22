"""Headless uninstall cleanup reports actual namespace cleanup failure."""
import elmocut
from tools import firewall


def test_cleanup_success(monkeypatch):
    monkeypatch.setattr(firewall, 'clear_all_rules', lambda: True)
    assert elmocut._flush_firewall() == 0


def test_cleanup_failure_returns_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(firewall, 'clear_all_rules', lambda: False)
    monkeypatch.setattr(firewall, 'last_error', lambda: 'permission denied')
    assert elmocut._flush_firewall() == 1
    assert 'permission denied' in capsys.readouterr().err


def test_cleanup_exception_returns_nonzero(monkeypatch, capsys):
    def unavailable():
        raise OSError('firewall tool unavailable')

    monkeypatch.setattr(firewall, 'clear_all_rules', unavailable)
    assert elmocut._flush_firewall() == 1
    assert 'firewall tool unavailable' in capsys.readouterr().err
