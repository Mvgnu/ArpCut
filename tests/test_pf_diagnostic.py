"""The manual diagnostic must restore configuration on interruption or failure."""
import importlib.util
from pathlib import Path
from subprocess import CompletedProcess
import tempfile

import pytest

_spec = importlib.util.spec_from_file_location('pf_diagnostic', Path(__file__).parents[1] / 'test_pf.py')
diagnostic = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(diagnostic)


@pytest.mark.parametrize('failure', [KeyboardInterrupt, RuntimeError])
def test_interrupted_diagnostic_restores_original_file_and_live_rules(tmp_path, monkeypatch, failure):
    conf = tmp_path / 'pf.conf'
    original = b'# original rules\npass all\n'
    conf.write_bytes(original)
    monkeypatch.setattr(diagnostic, 'PF_CONF', conf)
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    loaded = []

    def command(argv):
        if argv[0] == 'ping':
            raise failure()
        if argv[:2] == ['pfctl', '-f']:
            loaded.append(conf.read_bytes())
        return CompletedProcess(argv, 0, '', '')

    monkeypatch.setattr(diagnostic, 'cmd', command)
    with pytest.raises(failure):
        diagnostic.main()
    assert loaded[0] != original
    assert loaded[-1] == original
    assert conf.read_bytes() == original
    assert list(tmp_path.iterdir()) == [conf]


def test_failed_firewall_restore_keeps_private_recovery_copy(tmp_path, monkeypatch):
    conf = tmp_path / 'pf.conf'
    original = b'# original\n'
    conf.write_bytes(original)
    monkeypatch.setattr(diagnostic, 'PF_CONF', conf)
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    monkeypatch.setattr(diagnostic, 'cmd', lambda argv: CompletedProcess(argv, 1, '', 'failed'))
    with pytest.raises(RuntimeError, match='reload original'):
        diagnostic.main()
    recovery = list(tmp_path.glob('arpcut-pf-*.conf'))
    assert len(recovery) == 1
    assert recovery[0].read_bytes() == original
    assert conf.read_bytes() == original
