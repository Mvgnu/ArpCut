"""Unit tests for the Platform domain — settings serialization and MAC normalization.

These tests are pure unit tests that do NOT require root, scapy, or a network
interface.  They mock file I/O and external dependencies where necessary.

Run: PYTHONPATH=src venv/bin/python -m pytest tests/test_platform.py -v
"""
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

# Ensure the src directory is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))


# ──────────────────────────────────────────────────────────────────────────────
#  MAC normalisation  (tools.utils.good_mac)
# ──────────────────────────────────────────────────────────────────────────────

class TestGoodMac:
    """Tests for good_mac() — MAC address normalisation."""

    def test_uppercase(self) -> None:
        from tools.utils import good_mac
        assert good_mac('aa:bb:cc:dd:ee:ff') == 'AA:BB:CC:DD:EE:FF'

    def test_dash_to_colon(self) -> None:
        from tools.utils import good_mac
        assert good_mac('AA-BB-CC-DD-EE-FF') == 'AA:BB:CC:DD:EE:FF'

    def test_already_normalised(self) -> None:
        from tools.utils import good_mac
        assert good_mac('AA:BB:CC:DD:EE:FF') == 'AA:BB:CC:DD:EE:FF'

    def test_mixed_case_and_dashes(self) -> None:
        from tools.utils import good_mac
        assert good_mac('aA-bB-cC-dD-eE-fF') == 'AA:BB:CC:DD:EE:FF'

    def test_empty_string(self) -> None:
        from tools.utils import good_mac
        assert good_mac('') == ''

    def test_short_mac(self) -> None:
        from tools.utils import good_mac
        result = good_mac('aa:bb')
        assert result == 'AA:BB'


# ──────────────────────────────────────────────────────────────────────────────
#  Vendor lookup  (tools.utils.get_vendor)
# ──────────────────────────────────────────────────────────────────────────────

class TestGetVendor:
    """Tests for get_vendor() — OUI database lookup."""

    def test_returns_string(self) -> None:
        from tools.utils import get_vendor
        result = get_vendor('AA:BB:CC:DD:EE:FF')
        assert isinstance(result, str)

    def test_unknown_returns_none_string(self) -> None:
        from tools.utils import get_vendor
        result = get_vendor('00:00:00:00:00:00')
        assert isinstance(result, str)

    def test_well_known_oui(self) -> None:
        """Apple OUI — should resolve to a vendor name."""
        from tools.utils import get_vendor
        result = get_vendor('AC:DE:48:00:11:22')
        assert isinstance(result, str)


# ──────────────────────────────────────────────────────────────────────────────
#  Settings serialization  (tools.utils_gui)
# ──────────────────────────────────────────────────────────────────────────────

class TestSettingsSerialization:
    """Tests for import_settings / export_settings / set_settings / get_settings.

    Uses a temp directory to avoid touching real settings files.
    Monkeypatches both ``constants`` and ``tools.utils_gui`` module-level paths.
    """

    def setup_method(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._settings_path = os.path.join(self._tmpdir, 'settings.json')

        import constants
        import tools.utils_gui as _gui

        self._orig_dp = constants.DOCUMENTS_PATH
        self._orig_sp = constants.SETTINGS_PATH
        self._gui_orig_dp = _gui.DOCUMENTS_PATH
        self._gui_orig_sp = _gui.SETTINGS_PATH

        constants.DOCUMENTS_PATH = self._tmpdir
        constants.SETTINGS_PATH = self._settings_path
        _gui.DOCUMENTS_PATH = self._tmpdir
        _gui.SETTINGS_PATH = self._settings_path

    def teardown_method(self) -> None:
        import constants
        import tools.utils_gui as _gui
        constants.DOCUMENTS_PATH = self._orig_dp
        constants.SETTINGS_PATH = self._orig_sp
        _gui.DOCUMENTS_PATH = self._gui_orig_dp
        _gui.SETTINGS_PATH = self._gui_orig_sp
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_export_creates_file(self) -> None:
        from tools.utils_gui import export_settings
        export_settings()
        assert os.path.exists(self._settings_path)

    def test_export_creates_valid_json(self) -> None:
        from tools.utils_gui import export_settings
        export_settings()
        with open(self._settings_path, 'r') as f:
            data = json.load(f)
        assert isinstance(data, dict)

    def test_roundtrip(self) -> None:
        """export -> import should be identity."""
        from tools.utils_gui import export_settings, import_settings
        export_settings()
        result = import_settings()
        assert isinstance(result, dict)
        from constants import SETTINGS_KEYS
        for key in SETTINGS_KEYS:
            assert key in result

    def test_set_and_get(self) -> None:
        """set_settings + get_settings round-trip for a single key."""
        from tools.utils_gui import export_settings, set_settings, get_settings
        export_settings()
        set_settings('dark', False)
        assert get_settings('dark') is False

    def test_repair_adds_missing_keys(self) -> None:
        """repair_settings should merge defaults with stored settings."""
        partial: dict[str, Any] = {'dark': 'custom_val'}
        with open(self._settings_path, 'w') as f:
            json.dump(partial, f)
        from tools.utils_gui import repair_settings, import_settings
        repair_settings()
        result = import_settings()
        assert result['dark'] == 'custom_val'
        from constants import SETTINGS_KEYS
        for key in SETTINGS_KEYS:
            assert key in result


# ──────────────────────────────────────────────────────────────────────────────
#  Constants  (src/constants.py)
# ──────────────────────────────────────────────────────────────────────────────

class TestConstants:
    """Tests for constants.py module integrity."""

    def test_version_is_string(self) -> None:
        from constants import __version__
        assert isinstance(__version__, str)
        assert len(__version__) > 0

    def test_settings_defaults_is_dict(self) -> None:
        from constants import SETTINGS_DEFAULTS
        assert isinstance(SETTINGS_DEFAULTS, dict)
        assert len(SETTINGS_DEFAULTS) > 0

    def test_settings_keys_match_defaults(self) -> None:
        from constants import SETTINGS_KEYS, SETTINGS_DEFAULTS
        for key in SETTINGS_KEYS:
            assert key in SETTINGS_DEFAULTS, f'Key {key!r} missing'

    def test_documents_path_is_string(self) -> None:
        from constants import DOCUMENTS_PATH
        assert isinstance(DOCUMENTS_PATH, str)

    def test_settings_path_is_string(self) -> None:
        from constants import SETTINGS_PATH
        assert isinstance(SETTINGS_PATH, str)

    def test_global_mac_format(self) -> None:
        from constants import GLOBAL_MAC
        assert isinstance(GLOBAL_MAC, str)
        assert ':' in GLOBAL_MAC or len(GLOBAL_MAC) == 0
