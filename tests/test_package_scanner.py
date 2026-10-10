"""Tests for safe Debian package inventory collection."""

import subprocess
from types import SimpleNamespace

from scanner import package_scanner as scanner


def test_parse_dpkg_output():
    assert scanner.parse_dpkg_output("bash\t5.2-2\nlibc6:amd64\t2.36-9\n\n") == [
        scanner.Package("bash", "5.2-2"), scanner.Package("libc6:amd64", "2.36-9")
    ]


def test_empty_output_is_successful_empty_inventory(monkeypatch):
    monkeypatch.setattr(scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scanner, "_os_release_ids", lambda: {"ubuntu"})
    monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=""))
    result = scanner.scan_installed_packages()
    assert result.success
    assert result.packages == []


def test_unsupported_system_does_not_run_command(monkeypatch):
    monkeypatch.setattr(scanner.platform, "system", lambda: "Windows")
    monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(AssertionError()))
    result = scanner.scan_installed_packages()
    assert not result.success
    assert result.packages == []
    assert "only on Debian/Ubuntu/Kali" in result.error


def test_missing_dpkg_query_is_reported(monkeypatch):
    monkeypatch.setattr(scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scanner, "_os_release_ids", lambda: {"debian"})
    monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError()))
    assert "not found" in scanner.scan_installed_packages().error


def test_dpkg_query_failure_is_reported(monkeypatch):
    monkeypatch.setattr(scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scanner, "_os_release_ids", lambda: {"debian"})
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0], stderr="database unavailable")
    monkeypatch.setattr(scanner.subprocess, "run", fail)
    result = scanner.scan_installed_packages()
    assert not result.success
    assert "database unavailable" in result.error


def test_unsupported_linux_distribution(monkeypatch):
    monkeypatch.setattr(scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scanner, "_os_release_ids", lambda: {"fedora"})
    result = scanner.scan_installed_packages()
    assert not result.success
    assert "Unsupported distribution 'fedora'" in result.error


def test_supported_distributions_use_dpkg_query(monkeypatch):
    for distro_id in ("kali", "ubuntu", "debian"):
        monkeypatch.setattr(scanner.platform, "system", lambda: "Linux")
        monkeypatch.setattr(scanner, "_os_release_ids", lambda distro_id=distro_id: {distro_id})
        calls = []
        monkeypatch.setattr(
            scanner.subprocess,
            "run",
            lambda *args, **kwargs: (calls.append((args, kwargs)) or SimpleNamespace(stdout="pkg\t1.0\n")),
        )

        result = scanner.scan_installed_packages()

        assert result.success
        assert result.packages == [scanner.Package("pkg", "1.0")]
        assert calls[0][0][0][0] == "dpkg-query"


def test_id_like_does_not_make_unknown_distribution_supported(monkeypatch):
    monkeypatch.setattr(scanner.platform, "system", lambda: "Linux")
    # ID-like fields are compatibility hints; an unknown primary ID is unsupported.
    monkeypatch.setattr(scanner, "_os_release_ids", lambda: {"unknown-linux"})
    result = scanner.scan_installed_packages()
    assert not result.success
    assert "Unsupported distribution 'unknown-linux'" in result.error
