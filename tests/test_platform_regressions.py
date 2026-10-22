"""Persistence and process failures must not corrupt settings or look successful."""
import json
from subprocess import CalledProcessError, TimeoutExpired

import pytest

from tools import utils, utils_gui


@pytest.fixture
def settings_file(tmp_path, monkeypatch):
    destination = tmp_path / 'settings.json'
    monkeypatch.setattr(utils_gui, 'DOCUMENTS_PATH', str(tmp_path))
    monkeypatch.setattr(utils_gui, 'SETTINGS_PATH', str(destination))
    return destination


def test_setting_update_uses_names_not_json_field_order(settings_file):
    settings_file.write_text(json.dumps({'threads': 7, 'dark': False, 'count': 64}))
    utils_gui.set_settings('remember', True)
    saved = json.loads(settings_file.read_text())
    assert saved['threads'] == 7
    assert saved['dark'] is False
    assert saved['count'] == 64
    assert saved['remember'] is True


def test_unknown_settings_survive_updates_and_repair(settings_file):
    settings_file.write_text(json.dumps({'future_setting': {'value': 3}, 'dark': False}))
    utils_gui.set_settings('threads', 8)
    utils_gui.repair_settings()
    saved = utils_gui.import_settings()
    assert saved['future_setting'] == {'value': 3}
    assert saved['dark'] is False
    assert saved['threads'] == 8


@pytest.mark.parametrize('broken', ['[1, 2]', 'null', '42', '{', '\ufffd'])
def test_repair_recovers_non_object_or_corrupt_settings(settings_file, broken):
    settings_file.write_text(broken, encoding='utf-8')
    utils_gui.repair_settings()
    assert utils_gui.get_settings('threads') == 12
    assert utils_gui.get_settings('nicknames') == {}


def test_failed_serialization_preserves_previous_settings(settings_file):
    utils_gui.export_settings({'dark': False})
    previous = settings_file.read_bytes()
    with pytest.raises(TypeError):
        utils_gui.set_settings('nicknames', object())
    assert settings_file.read_bytes() == previous
    assert list(settings_file.parent.iterdir()) == [settings_file]


def test_failed_replace_preserves_previous_settings(settings_file, monkeypatch):
    utils_gui.export_settings({'threads': 6})
    previous = settings_file.read_bytes()

    def fail_replace(*args):
        raise OSError('disk unavailable')

    monkeypatch.setattr(utils_gui.os, 'replace', fail_replace)
    with pytest.raises(OSError):
        utils_gui.set_settings('threads', 10)
    assert settings_file.read_bytes() == previous
    assert list(settings_file.parent.iterdir()) == [settings_file]


def test_terminal_malformed_quoting_does_not_escape_error_handling(monkeypatch):
    def unexpected_command(*args, **kwargs):
        pytest.fail('Malformed input must not launch a process')

    monkeypatch.setattr(utils, 'check_output', unexpected_command)
    monkeypatch.setattr(utils.sys, 'platform', 'linux')
    assert utils.terminal('arp "unterminated') is None


def test_terminal_nonzero_exit_is_failure_even_with_output(monkeypatch):
    def failure(*args, **kwargs):
        raise CalledProcessError(1, ['arp'], output=b'Permission denied')

    monkeypatch.setattr(utils, 'check_output', failure)
    assert utils.terminal(['arp']) is None


def test_terminal_enforces_requested_deadline(monkeypatch):
    def timeout(argv, **kwargs):
        assert kwargs['timeout'] == 2.0
        raise TimeoutExpired(argv, kwargs['timeout'])

    monkeypatch.setattr(utils, 'check_output', timeout)
    assert utils.terminal(['ping', 'example.invalid'], timeout=2.0) is None
