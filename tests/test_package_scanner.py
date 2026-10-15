"""Tests for safe Debian package inventory collection."""

import subprocess
from types import SimpleNamespace

import pytest

from scanner import package_scanner as scanner


def test_parse_dpkg_output():
    assert scanner.parse_dpkg_output("bash\t5.2-2\nlibc6:amd64\t2.36-9\n\n") == [
        scanner.Package("bash", "5.2-2"), scanner.Package("libc6:amd64", "2.36-9")
    ]


@pytest.mark.parametrize(
    "row",
    [
        "\t1.0",  # Missing package name.
        "package\t",  # Missing package version.
        "package-only",  # Too few fields to contain both identity values.
    ],
)
def test_parse_dpkg_output_counts_malformed_identity_rows(row):
    packages, malformed_rows = scanner._parse_dpkg_output(row)

    assert packages == []
    assert malformed_rows == 1


def test_parse_dpkg_source_metadata_and_policy_defined_fallback():
    packages = scanner.parse_dpkg_output(
        "libopenssh-server\t1:9.2p1-2+deb12u2\topenssh (1:9.2p1-2+deb12u2)\n"
        "same-name\t2.0-1\t\n"
        "legacy\t3.0-1\n"
        "bad-source\t4.0-1\tinvalid source field!\n"
    )
    assert packages[0].source_name == "openssh"
    assert packages[0].source_version == "1:9.2p1-2+deb12u2"
    # An omitted Source field is defined by Debian Policy as same source and
    # binary name/version; old two-column data does not establish that.
    assert packages[1].source_name == "same-name"
    assert packages[1].source_version == "2.0-1"
    assert packages[2].source_name is None
    assert packages[2].source_version is None
    assert packages[3].source_name is None
    assert packages[3].source_version is None


def test_internal_source_metadata_does_not_change_package_inventory_schema():
    result = scanner.PackageScanResult([
        scanner.Package("binary", "1.0", "source", "1.0")
    ])
    assert result.to_dict()["packages"] == [{"name": "binary", "version": "1.0"}]


def test_empty_output_is_successful_empty_inventory(monkeypatch):
    monkeypatch.setattr(scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scanner, "_os_release_ids", lambda: {"ubuntu"})
    monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=""))
    result = scanner.scan_installed_packages()
    assert result.success
    assert result.packages == []


def test_malformed_identity_rows_fail_scan_but_keep_valid_packages(monkeypatch):
    monkeypatch.setattr(scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scanner, "_os_release_ids", lambda: {"debian"})
    output = "valid-package\t1.0\n\t2.0\nmissing-version\t\npackage-only\n"
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=output),
    )

    result = scanner.scan_installed_packages()

    assert not result.success
    assert result.packages == [scanner.Package("valid-package", "1.0")]
    assert "3 malformed package identity rows" in result.error
    assert "inventory may be incomplete" in result.error


def test_malformed_source_metadata_does_not_fail_package_scan(monkeypatch):
    monkeypatch.setattr(scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scanner, "_os_release_ids", lambda: {"debian"})
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="binary-package\t1.0\tinvalid source field!\n"
        ),
    )

    result = scanner.scan_installed_packages()

    assert result.success
    assert result.packages == [
        scanner.Package("binary-package", "1.0", None, None)
    ]


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
        assert calls[0][0][0][2] == "-f=${binary:Package}\\t${Version}\\t${Source}\\n"


def test_id_like_does_not_make_unknown_distribution_supported(monkeypatch):
    monkeypatch.setattr(scanner.platform, "system", lambda: "Linux")
    # ID-like fields are compatibility hints; an unknown primary ID is unsupported.
    monkeypatch.setattr(scanner, "_os_release_ids", lambda: {"unknown-linux"})
    result = scanner.scan_installed_packages()
    assert not result.success
    assert "Unsupported distribution 'unknown-linux'" in result.error
