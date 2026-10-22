"""Build paths resolve relative to the script, independent of the caller's cwd."""
import importlib.util
from pathlib import Path
from subprocess import CompletedProcess


_spec = importlib.util.spec_from_file_location('arpcut_build', Path(__file__).parents[1] / 'build.py')
build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build)


def test_build_from_another_directory_uses_repository_sources(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(build.platform, 'system', lambda: 'Linux')
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return CompletedProcess(argv, 0)

    monkeypatch.setattr(build.subprocess, 'run', run)
    build.build()
    argv, kwargs = calls[0]
    assert (kwargs['cwd'] / argv[-1]).is_file()
    assert (kwargs['cwd'] / 'exe' / 'manuf').is_file()


def test_dmg_from_another_directory_passes_absolute_bundle_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(build.platform, 'system', lambda: 'Darwin')
    calls = []
    monkeypatch.setattr(build.subprocess, 'run',
                        lambda argv: calls.append(argv) or CompletedProcess(argv, 0))
    build.package_dmg()
    assert Path(calls[0][1]).is_file()
    assert Path(calls[0][2]) == build.REPO_ROOT / 'dist' / f'ArpCut-{build.VERSION}.app'
