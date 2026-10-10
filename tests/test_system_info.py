"""Tests for system information collection."""

from pathlib import Path

from scanner import system_info


def test_collect_system_info_reads_linux_release_fields(monkeypatch, tmp_path: Path):
    release = tmp_path / "os-release"
    release.write_text('NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04 LTS"\nVERSION_ID="24.04"\n')
    monkeypatch.setattr(system_info.platform, "system", lambda: "Linux")
    monkeypatch.setattr(system_info.platform, "release", lambda: "6.8.0")
    monkeypatch.setattr(system_info.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(system_info.platform, "python_version", lambda: "3.12.0")
    monkeypatch.setattr(system_info.platform, "node", lambda: "test-host")
    read_release = system_info._read_os_release
    monkeypatch.setattr(system_info, "_read_os_release", lambda: read_release(release))

    info = system_info.collect_system_info()

    assert info.distribution == "Ubuntu 24.04 LTS"
    assert info.distribution_version == "24.04"
    assert info.kernel_version == "6.8.0"
    assert info.architecture == "x86_64"
    assert info.python_version == "3.12.0"
    assert info.hostname == "test-host"
    assert info.to_dict()["operating_system"] == "Linux"


def test_collect_system_info_handles_missing_release(monkeypatch):
    monkeypatch.setattr(system_info.platform, "system", lambda: "Linux")
    monkeypatch.setattr(system_info, "_read_os_release", lambda: {})
    monkeypatch.setattr(system_info.platform, "node", lambda: "")
    info = system_info.collect_system_info()
    assert info.distribution is None
    assert info.hostname is None


def test_collect_system_info_detects_windows_without_linux_release(monkeypatch):
    monkeypatch.setattr(system_info.platform, "system", lambda: "Windows")
    monkeypatch.setattr(system_info, "_read_os_release", lambda: (_ for _ in ()).throw(AssertionError()))
    info = system_info.collect_system_info()
    assert info.operating_system == "Windows"
    assert info.distribution is None
