"""Tests for read-only prerequisite diagnostics."""

from __future__ import annotations

import subprocess
from pathlib import Path

from scanner.diagnostics import collect_diagnostics


def _commands(tmp_path):
    commands = {}
    for name in ("apt-get", "apt-config", "dpkg-query", "dpkg-deb", "clamscan"):
        path = tmp_path / name
        path.write_text("fixture executable placeholder")
        path.chmod(0o755)
        commands[name] = (str(path), ["dump"] if name == "apt-config" else ["--version"])
    return commands


def test_diagnostics_summarize_tools_and_count_hooks_without_exposing_values(tmp_path):
    release = tmp_path / "os-release"
    release.write_text('ID=debian\nPRETTY_NAME="Debian Test"\nVERSION_ID="12"\n')
    commands = _commands(tmp_path)
    invocations = []

    def runner(command, **kwargs):
        invocations.append((command, kwargs))
        if command[0] == commands["apt-config"][0]:
            output = (
                'APT::Get::Proxy "http://user:password@example.invalid";\n'
                'DPkg::Pre-Install-Pkgs:: "/usr/bin/review-hook";\n'
                'DPkg::Pre-Install-Pkgs:: "/usr/bin/another-hook";\n'
                'DPkg::Pre-Invoke:: "/usr/bin/pre-invoke";\n'
            )
        else:
            output = f"{Path(command[0]).name} 1.2.3\n"
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    report = collect_diagnostics(
        runner=runner,
        system_name="Linux",
        os_release_path=release,
        python_version=(3, 12),
        command_paths=commands,
    )

    assert report["status"] == "supported_host"
    assert report["package_inventory_ready"] is True
    assert report["deb_scan_prerequisites_available"] is True
    assert report["apt_hook_prerequisites_available"] is True
    assert report["apt_pre_install_hook_count"] == 2
    assert report["apt_pre_invoke_hook_count"] == 1
    assert report["commands"]["clamscan"]["version"] == "clamscan 1.2.3"
    assert "password" not in str(report)
    assert all("http://user" not in str(item) for item in report.values())
    assert all(call[1]["timeout"] == 5 for call in invocations)
    assert all(call[1]["env"]["LC_ALL"] == "C" for call in invocations)


def test_diagnostics_do_not_support_unknown_id_like_distribution(tmp_path):
    release = tmp_path / "os-release"
    release.write_text('ID=custom\nID_LIKE="debian"\nPRETTY_NAME="Custom OS"\n')
    report = collect_diagnostics(
        system_name="Linux",
        os_release_path=release,
        python_version=(3, 12),
        command_paths={},
    )
    assert report["status"] == "unsupported_host"
    assert report["package_inventory_ready"] is False
    assert report["apt_hook_prerequisites_available"] is False


def test_diagnostics_report_missing_tools_without_invoking_them(tmp_path):
    release = tmp_path / "os-release"
    release.write_text('ID=ubuntu\n')
    calls = []
    report = collect_diagnostics(
        runner=lambda *args, **kwargs: calls.append(args),
        system_name="Linux",
        os_release_path=release,
        python_version=(3, 9),
        command_paths={name: (str(tmp_path / name), ["--version"])
                       for name in ("apt-get", "dpkg-query", "dpkg-deb", "clamscan")},
    )
    assert report["status"] == "supported_host"
    assert report["python_supported"] is False
    assert report["package_inventory_ready"] is False
    assert report["deb_scan_prerequisites_available"] is False
    assert report["apt_hook_prerequisites_available"] is False
    assert not calls


def test_diagnostics_reject_python_310_after_end_of_life(tmp_path):
    release = tmp_path / "os-release"
    release.write_text("ID=debian\n")
    report = collect_diagnostics(
        system_name="Linux",
        os_release_path=release,
        python_version=(3, 10),
        command_paths={},
    )
    assert report["python_supported"] is False


def test_diagnostics_accept_python_311_minimum(tmp_path):
    release = tmp_path / "os-release"
    release.write_text("ID=debian\n")
    report = collect_diagnostics(
        system_name="Linux",
        os_release_path=release,
        python_version=(3, 11),
        command_paths={},
    )
    assert report["python_supported"] is True


def test_diagnostics_report_tool_timeout_without_failing(tmp_path):
    release = tmp_path / "os-release"
    release.write_text('ID=kali\n')
    commands = _commands(tmp_path)

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    report = collect_diagnostics(
        runner=timeout,
        system_name="Linux",
        os_release_path=release,
        python_version=(3, 12),
        command_paths=commands,
    )
    assert report["commands"]["clamscan"]["check"] == "timeout"
    assert report["apt_pre_install_hook_count"] is None
    assert any("hook counts are unavailable" in item for item in report["limitations"])
