"""CLI formatting and JSON output tests."""

import json
from io import StringIO
from types import SimpleNamespace

import pytest

import main
from scanner.package_scanner import Package, PackageScanResult
from scanner.malware_scanner import MalwareAssessment, MalwareDetection
from scanner import repository_scanner
from scanner.repository_malware_scanner import (
    RepositoryMalwareAssessment,
    RepositoryMalwareDetection,
)
from scanner.system_info import SystemInfo
from scanner.vulnerability_assessment import (
    PackageAssessment,
    VulnerabilityFinding,
    VulnerabilityAssessmentReport,
)


def test_json_output_format(monkeypatch):
    monkeypatch.setattr(main, "build_result", lambda: {
        "system_info": {"operating_system": "Linux"},
        "package_scan": {"success": True, "error": None, "packages": [{"name": "bash", "version": "1"}]},
    })
    output = StringIO()
    assert main.main(["--json"], stdout=output) == 0
    assert json.loads(output.getvalue())["package_scan"]["packages"][0]["name"] == "bash"


def test_scan_deb_cli_keeps_malware_report_separate_and_serializes_json(monkeypatch):
    monkeypatch.setattr(
        main,
        "scan_deb",
        lambda path: MalwareAssessment(
            status="detected",
            scanner="ClamAV clamscan",
            package={"name": "demo", "version": "1.2-3"},
            detections=[MalwareDetection("Test.Signature", "payload/usr/bin/demo")],
            coverage_complete=True,
        ),
    )
    output = StringIO()

    exit_code = main.main(["--scan-deb", "demo.deb", "--json"], stdout=output)

    report = json.loads(output.getvalue())
    assert exit_code == 1
    assert report["status"] == "detected"
    assert report["package"]["name"] == "demo"
    assert report["detections"][0] == {
        "name": "Test.Signature", "path": "payload/usr/bin/demo",
    }
    assert "vulnerability_assessment" not in report


def test_scan_deb_text_report_explains_status_and_safety_limit(monkeypatch):
    monkeypatch.setattr(
        main,
        "scan_deb",
        lambda path: MalwareAssessment(
            status="incomplete",
            scanner="ClamAV clamscan",
            package={"name": "demo", "version": "1.2-3", "architecture": "all"},
            error=None,
            limitations=["A symbolic link was skipped."],
        ),
    )
    output = StringIO()

    exit_code = main.main(["--scan-deb", "demo.deb"], stdout=output)

    text = output.getvalue()
    assert exit_code == 1
    assert "Package: demo 1.2-3" in text
    assert "Status: incomplete" in text
    assert "Scanner: ClamAV clamscan" in text
    assert "Coverage limitation: A symbolic link was skipped." in text
    assert "No detection does not guarantee" in text


def _prepare_preinstall(monkeypatch, tmp_path, *, status="no_detection", coverage=True):
    package_path = tmp_path / "downloaded package.deb"
    package_path.write_bytes(b"fixture package bytes")
    monkeypatch.setattr(main.tempfile, "tempdir", str(tmp_path), raising=False)
    monkeypatch.setattr(main, "_preinstall_temp_parent", lambda: str(tmp_path))
    assessment = MalwareAssessment(
        status=status,
        scanner="ClamAV clamscan",
        package={"name": "demo", "version": "1.0"},
        detections=(
            [MalwareDetection("Test.Signature", "payload/usr/bin/demo")]
            if status == "detected" else []
        ),
        error="Mock provider error" if status == "error" else None,
        limitations=["Mock incomplete coverage"] if status == "incomplete" else [],
        coverage_complete=coverage,
    )
    monkeypatch.setattr(main, "scan_deb", lambda path: assessment)
    tools = {
        "apt-get": "/usr/bin/apt-get",
        "sudo": "/usr/bin/sudo",
        "chgrp": "/usr/bin/chgrp",
        "chmod": "/usr/bin/chmod",
    }
    monkeypatch.setattr(main, "_find_system_command", lambda name: tools.get(name))
    monkeypatch.setattr(main, "_is_effective_root", lambda: False)
    monkeypatch.setattr(main, "_apt_sandbox_gid", lambda: 123)
    return package_path, assessment


def test_preinstall_deb_requires_explicit_confirmation_and_keeps_json_stdout_clean(
    monkeypatch, tmp_path, capsys,
):
    package_path, assessment = _prepare_preinstall(monkeypatch, tmp_path)
    monkeypatch.setattr(main.sys, "stdin", StringIO("INSTALL\n"))
    commands = []
    scanned_paths = []

    def scan(path):
        scanned_paths.append(main.Path(path))
        assert scanned_paths[-1].read_bytes() == b"fixture package bytes"
        return assessment

    monkeypatch.setattr(main, "scan_deb", scan)

    def install(command, **kwargs):
        commands.append((command, kwargs))
        assert kwargs["shell"] is False
        if any(main.Path(part).name == "apt-get" for part in command):
            assert scanned_paths
            assert main.Path(command[-1]) == scanned_paths[0]
            assert main.Path(command[-1]).read_bytes() == b"fixture package bytes"
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(main.subprocess, "run", install)
    stdout = StringIO()

    exit_code = main.main(
        ["--preinstall-deb", str(package_path), "--json"], stdout=stdout,
    )

    report = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert report["malware_assessment"]["status"] == "no_detection"
    assert report["installation"]["status"] == "installed"
    assert "does not guarantee safety" in capsys.readouterr().err
    assert len(commands) == 5
    assert commands[0][0] == ["/usr/bin/sudo", "-v"]
    assert commands[1][0] == [
        "/usr/bin/sudo", "/usr/bin/chgrp", "--", "123",
        str(scanned_paths[0].parent), str(scanned_paths[0]),
    ]
    assert commands[2][0] == [
        "/usr/bin/sudo", "/usr/bin/chmod", "0710", "--",
        str(scanned_paths[0].parent),
    ]
    assert commands[3][0] == [
        "/usr/bin/sudo", "/usr/bin/chmod", "0640", "--", str(scanned_paths[0]),
    ]
    command, options = commands[4]
    assert command == [
        "/usr/bin/sudo", "/usr/bin/apt-get", "install", "--no-remove", "--",
        str(scanned_paths[0]),
    ]
    assert scanned_paths[0] != package_path.resolve()
    assert not scanned_paths[0].exists()
    assert options["shell"] is False
    assert options["stdin"] is None
    assert options["stdout"] is main.sys.stderr
    assert options["stderr"] is main.sys.stderr


@pytest.mark.parametrize("confirmation", ["no\n", "install\n", "INSTALL \n"])
def test_preinstall_deb_requires_exact_confirmation_and_does_not_start_apt(
    monkeypatch, tmp_path, capsys, confirmation,
):
    package_path, _ = _prepare_preinstall(monkeypatch, tmp_path)
    monkeypatch.setattr(main.sys, "stdin", StringIO(confirmation))
    monkeypatch.setattr(
        main.subprocess, "run", lambda *args, **kwargs: pytest.fail("APT must not run"),
    )
    stdout = StringIO()

    exit_code = main.main(["--preinstall-deb", str(package_path)], stdout=stdout)

    assert exit_code == 1
    assert "No known malware detection was found" in stdout.getvalue()
    assert "Installation: cancelled" in stdout.getvalue()
    assert "Type INSTALL" in capsys.readouterr().err


def test_preinstall_deb_missing_sudo_is_reported_after_approval_without_apt(
    monkeypatch, tmp_path,
):
    package_path, _ = _prepare_preinstall(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "_find_system_command", lambda name: (
        "/usr/bin/apt-get" if name == "apt-get" else None
    ))
    monkeypatch.setattr(main.sys, "stdin", StringIO("INSTALL\n"))
    monkeypatch.setattr(
        main.subprocess, "run", lambda *args, **kwargs: pytest.fail("APT must not run"),
    )
    stdout = StringIO()

    exit_code = main.main(
        ["--preinstall-deb", str(package_path), "--json"], stdout=stdout,
    )

    report = json.loads(stdout.getvalue())
    assert exit_code == 1
    assert report["installation"]["status"] == "unavailable"
    assert "sudo is unavailable" in report["installation"]["message"]


def test_preinstall_deb_denied_sudo_authorization_does_not_start_apt(
    monkeypatch, tmp_path,
):
    package_path, _ = _prepare_preinstall(monkeypatch, tmp_path)
    monkeypatch.setattr(main.sys, "stdin", StringIO("INSTALL\n"))
    commands = []

    def deny_authorization(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(main.subprocess, "run", deny_authorization)
    stdout = StringIO()

    exit_code = main.main(
        ["--preinstall-deb", str(package_path), "--json"], stdout=stdout,
    )

    report = json.loads(stdout.getvalue())
    assert exit_code == 1
    assert commands == [["/usr/bin/sudo", "-v"]]
    assert report["installation"]["status"] == "failed"
    assert report["installation"]["returncode"] == 1
    assert "authorization was not granted" in report["installation"]["message"]


def test_preinstall_deb_blocks_when_apt_sandbox_permissions_cannot_be_set(
    monkeypatch, tmp_path,
):
    package_path, _ = _prepare_preinstall(monkeypatch, tmp_path)
    monkeypatch.setattr(main.sys, "stdin", StringIO("INSTALL\n"))
    commands = []

    def fail_permission_setup(command, **kwargs):
        commands.append(command)
        if command == ["/usr/bin/sudo", "-v"]:
            return SimpleNamespace(returncode=0)
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(main.subprocess, "run", fail_permission_setup)
    stdout = StringIO()

    exit_code = main.main(
        ["--preinstall-deb", str(package_path), "--json"], stdout=stdout,
    )

    report = json.loads(stdout.getvalue())
    assert exit_code == 1
    assert len(commands) == 2
    assert "apt-get" not in " ".join(commands[-1])
    assert report["installation"]["status"] == "failed"
    assert "not attempted" in report["installation"]["message"]


def test_preinstall_deb_json_report_file_stays_parseable_on_cancellation(
    monkeypatch, tmp_path, capsys,
):
    package_path, _ = _prepare_preinstall(monkeypatch, tmp_path)
    report_path = tmp_path / "preinstall-report.json"
    monkeypatch.setattr(main.sys, "stdin", StringIO("cancel\n"))
    monkeypatch.setattr(
        main.subprocess, "run", lambda *args, **kwargs: pytest.fail("APT must not run"),
    )
    stdout = StringIO()

    exit_code = main.main(
        ["--preinstall-deb", str(package_path), "--json", "--output", str(report_path)],
        stdout=stdout,
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert report["installation"]["status"] == "cancelled"
    assert "Type INSTALL" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("status", "coverage"),
    [("detected", True), ("incomplete", False), ("error", False),
     ("unavailable", False), ("no_detection", False)],
)
def test_preinstall_deb_blocks_nonclean_or_incomplete_assessments(
    monkeypatch, tmp_path, capsys, status, coverage,
):
    package_path, _ = _prepare_preinstall(
        monkeypatch, tmp_path, status=status, coverage=coverage,
    )
    monkeypatch.setattr(main.sys, "stdin", StringIO("INSTALL\n"))
    monkeypatch.setattr(
        main.subprocess, "run", lambda *args, **kwargs: pytest.fail("APT must be blocked"),
    )
    stdout = StringIO()

    exit_code = main.main(
        ["--preinstall-deb", str(package_path), "--json"], stdout=stdout,
    )

    report = json.loads(stdout.getvalue())
    assert exit_code == 1
    assert report["malware_assessment"]["status"] == status
    assert report["installation"]["status"] == "blocked"
    assert "Type INSTALL" not in capsys.readouterr().err


def test_preinstall_deb_missing_apt_tool_is_reported_without_prompt(
    monkeypatch, tmp_path, capsys,
):
    package_path, _ = _prepare_preinstall(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "_find_system_command", lambda name: None)
    monkeypatch.setattr(main.sys, "stdin", StringIO("INSTALL\n"))
    stdout = StringIO()

    exit_code = main.main(["--preinstall-deb", str(package_path), "--json"], stdout=stdout)

    report = json.loads(stdout.getvalue())
    assert exit_code == 1
    assert report["installation"]["status"] == "unavailable"
    assert "apt-get is unavailable" in report["installation"]["message"]
    assert "Type INSTALL" not in capsys.readouterr().err


@pytest.mark.parametrize("bad_name", ["missing.deb", "not-a-package.txt"])
def test_preinstall_deb_invalid_paths_are_reported_without_scanning(
    monkeypatch, tmp_path, bad_name,
):
    monkeypatch.setattr(
        main, "scan_deb", lambda path: pytest.fail("invalid path must not be scanned"),
    )
    stdout = StringIO()

    exit_code = main.main(
        ["--preinstall-deb", str(tmp_path / bad_name), "--json"], stdout=stdout,
    )

    report = json.loads(stdout.getvalue())
    assert exit_code == 1
    assert report["malware_assessment"]["status"] == "error"
    assert report["installation"]["status"] == "blocked"


def test_preinstall_deb_apt_failure_is_reported(monkeypatch, tmp_path):
    package_path, _ = _prepare_preinstall(monkeypatch, tmp_path)
    monkeypatch.setattr(main.sys, "stdin", StringIO("INSTALL\n"))

    def fail_apt(command, **kwargs):
        is_apt = any(main.Path(part).name == "apt-get" for part in command)
        return SimpleNamespace(returncode=100 if is_apt else 0)

    monkeypatch.setattr(main.subprocess, "run", fail_apt)
    stdout = StringIO()

    exit_code = main.main(
        ["--preinstall-deb", str(package_path), "--json"], stdout=stdout,
    )

    report = json.loads(stdout.getvalue())
    assert exit_code == 1
    assert report["installation"]["status"] == "failed"
    assert report["installation"]["returncode"] == 100
    assert "review its output" in report["installation"]["message"]


def test_preinstall_deb_permission_error_is_reported(monkeypatch, tmp_path):
    package_path, _ = _prepare_preinstall(monkeypatch, tmp_path)
    monkeypatch.setattr(main.sys, "stdin", StringIO("INSTALL\n"))

    def permission_error(*args, **kwargs):
        raise PermissionError("administrator privileges are required")

    monkeypatch.setattr(main.subprocess, "run", permission_error)
    stdout = StringIO()

    exit_code = main.main(
        ["--preinstall-deb", str(package_path), "--json"], stdout=stdout,
    )

    report = json.loads(stdout.getvalue())
    assert exit_code == 1
    assert report["installation"]["status"] == "failed"
    assert "administrator authorization" in report["installation"]["message"]


def test_preinstall_deb_report_cannot_overwrite_package(monkeypatch, tmp_path, capsys):
    package_path, _ = _prepare_preinstall(monkeypatch, tmp_path)
    original_bytes = package_path.read_bytes()
    monkeypatch.setattr(
        main, "scan_deb", lambda path: pytest.fail("must reject output collision first"),
    )
    stdout = StringIO()

    exit_code = main.main(
        ["--preinstall-deb", str(package_path), "--json", "--output", str(package_path)],
        stdout=stdout,
    )

    assert exit_code == 2
    assert package_path.read_bytes() == original_bytes
    assert "over the package being scanned" in capsys.readouterr().err


def test_preinstall_deb_private_snapshot_failure_blocks_install(
    monkeypatch, tmp_path, capsys,
):
    package_path, _ = _prepare_preinstall(monkeypatch, tmp_path)
    monkeypatch.setattr(
        main, "_create_package_snapshot",
        lambda *args: (_ for _ in ()).throw(OSError("snapshot unavailable")),
    )
    monkeypatch.setattr(
        main, "scan_deb", lambda path: pytest.fail("snapshot failure must block scanning"),
    )
    monkeypatch.setattr(main.sys, "stdin", StringIO("INSTALL\n"))
    stdout = StringIO()

    exit_code = main.main(["--preinstall-deb", str(package_path), "--json"], stdout=stdout)

    report = json.loads(stdout.getvalue())
    assert exit_code == 1
    assert report["malware_assessment"]["status"] == "error"
    assert report["installation"]["status"] == "blocked"
    assert "snapshot unavailable" in report["malware_assessment"]["error"]
    assert "Type INSTALL" not in capsys.readouterr().err


def test_preinstall_deb_missing_input_cannot_become_report_output(
    tmp_path, capsys,
):
    package_path = tmp_path / "missing.deb"
    stdout = StringIO()

    exit_code = main.main(
        ["--preinstall-deb", str(package_path), "--json", "--output", str(package_path)],
        stdout=stdout,
    )

    assert exit_code == 2
    assert not package_path.exists()
    assert "over the package being scanned" in capsys.readouterr().err


def test_malware_text_escapes_package_and_detection_terminal_controls():
    report = {
        "status": "detected",
        "scanner": "ClamAV",
        "package": {"name": "demo\x1b[31m\nforged", "version": "1.0\rhidden"},
        "detections": [{
            "name": "Test.Signature",
            "path": "payload/evil\x1b[2J\r\nforged",
        }],
        "error": None,
        "limitations": [],
    }

    text = main._render_malware_text(report)

    assert "demo\\x1b[31m\\nforged" in text
    assert "1.0\\rhidden" in text
    assert "payload/evil\\x1b[2J\\r\\nforged" in text
    assert "\x1b" not in text
    assert "\r" not in text


def test_scan_repo_cli_text_displays_separate_inventory_and_malware_results(
    tmp_path, monkeypatch
):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    (root / "app.py").write_text("print('not executed')\n", encoding="utf-8")
    monkeypatch.setattr(
        main,
        "scan_repository_malware",
        lambda path: RepositoryMalwareAssessment(
            status="no_detection", scanner="ClamAV clamscan",
            repository_path=str(path), files_scanned=2, bytes_scanned=30,
            coverage_complete=True,
        ),
    )
    output = StringIO()

    exit_code = main.main(["--scan-repo", str(root)], stdout=output)

    report = output.getvalue()
    assert exit_code == 0
    assert "repository inventory" in report
    assert "Status: completed" in report
    assert "Regular files inventoried: 2" in report
    assert "pyproject.toml: pyproject.toml" in report
    assert "Inventory only" in report
    assert "Repository malware assessment:" in report
    assert "Status: no_detection" in report
    assert "No detection does not guarantee" in report
    assert "malware" in report
    assert "not executed" not in report


def test_scan_repo_cli_json_writes_parseable_report_file(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "go.mod").write_text("module example\n", encoding="utf-8")
    report_path = tmp_path / "repository.json"

    monkeypatch.setattr(
        main,
        "scan_repository_malware",
        lambda path: RepositoryMalwareAssessment(
            status="no_detection", repository_path=str(path),
            files_scanned=1, bytes_scanned=12, coverage_complete=True,
        ),
    )
    exit_code = main.main([
        "--scan-repo", str(root), "--json", "--output", str(report_path),
    ], stdout=StringIO())

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert report["status"] == "completed"
    assert report["coverage_complete"] is True
    assert report["files_scanned"] == 1
    assert report["manifests"] == [{"name": "go.mod", "path": "go.mod"}]
    assert report["malware_assessment"]["status"] == "no_detection"
    assert report["malware_assessment"]["coverage_complete"] is True
    assert "vulnerability_assessment" not in report
    assert "malware" in report["note"]


def test_scan_repo_cli_output_write_failure_returns_two(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("example", encoding="utf-8")
    monkeypatch.setattr(
        main.Path,
        "write_text",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("mocked disk full")),
    )

    exit_code = main.main([
        "--scan-repo", str(root), "--json", "--output", str(tmp_path / "report.json"),
    ], stdout=StringIO())

    assert exit_code == 2
    assert "Could not write JSON output:" in capsys.readouterr().err


def test_scan_repo_refuses_report_path_inside_repository(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.txt").write_text("source", encoding="utf-8")
    report_path = root / "report.json"
    monkeypatch.setattr(
        main,
        "scan_repository_malware",
        lambda path: pytest.fail("must reject repository output before scanning"),
    )

    exit_code = main.main([
        "--scan-repo", str(root), "--json", "--output", str(report_path),
    ], stdout=StringIO())

    assert exit_code == 2
    assert not report_path.exists()
    assert "inside the repository" in capsys.readouterr().err


def test_scan_repo_cli_returns_one_for_incomplete_inventory(monkeypatch, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "one.txt").write_text("1", encoding="utf-8")
    monkeypatch.setattr(repository_scanner, "MAX_FILES", 0)
    monkeypatch.setattr(
        main,
        "scan_repository_malware",
        lambda path: RepositoryMalwareAssessment(
            status="no_detection", repository_path=str(path), coverage_complete=True,
        ),
    )
    output = StringIO()

    exit_code = main.main(["--scan-repo", str(root), "--json"], stdout=output)

    report = json.loads(output.getvalue())
    assert exit_code == 1
    assert report["status"] == "incomplete"
    assert report["coverage_complete"] is False
    assert report["files_scanned"] == 0
    assert report["limitations"]


@pytest.mark.parametrize("status", ["detected", "incomplete", "error", "unavailable"])
def test_scan_repo_cli_nonclean_malware_status_returns_one(monkeypatch, tmp_path, status):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "file.txt").write_text("sample", encoding="utf-8")
    monkeypatch.setattr(
        main,
        "scan_repository_malware",
        lambda path: RepositoryMalwareAssessment(
            status=status, repository_path=str(path), coverage_complete=False,
            detections=([RepositoryMalwareDetection("Test.Signature", "file.txt")]
                        if status == "detected" else []),
            errors=(["mocked scanner issue"] if status in {"error", "unavailable"} else []),
            limitations=(["mocked incomplete coverage"] if status == "incomplete" else []),
        ),
    )
    output = StringIO()

    exit_code = main.main(["--scan-repo", str(root), "--json"], stdout=output)

    report = json.loads(output.getvalue())
    assert exit_code == 1
    assert report["malware_assessment"]["status"] == status


def test_scan_repo_text_escapes_control_characters_in_malware_paths_and_errors():
    assessment = {
        "status": "detected",
        "scanner": "ClamAV",
        "coverage_complete": False,
        "files_scanned": 1,
        "bytes_scanned": 2,
        "detections": [{"name": "Test.Signature", "path": "src/a\x1b[2J\r\nforge.py"}],
        "errors": ["bad\x1b[31m\r\nmessage"],
        "limitations": [],
        "note": "No detection does not guarantee safety.",
    }

    rendered = main._render_repository_malware_text(assessment)

    assert "src/a\\x1b[2J\\r\\nforge.py" in rendered
    assert "bad\\x1b[31m\\r\\nmessage" in rendered
    assert "\x1b" not in rendered
    assert "\r" not in rendered


def test_scan_repo_json_preserves_detection_path_as_encoded_data(monkeypatch, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "sample.txt").write_text("sample", encoding="utf-8")
    unusual_path = "src/résumé [draft]\nfile.txt"
    monkeypatch.setattr(
        main,
        "scan_repository_malware",
        lambda path: RepositoryMalwareAssessment(
            status="detected", repository_path=str(path),
            detections=[RepositoryMalwareDetection("Test.Signature", unusual_path)],
            coverage_complete=True,
        ),
    )
    output = StringIO()

    exit_code = main.main(["--scan-repo", str(root), "--json"], stdout=output)

    report = json.loads(output.getvalue())
    assert exit_code == 1
    assert report["malware_assessment"]["detections"][0]["path"] == unusual_path


def test_scan_repo_cli_reports_missing_path_in_text(tmp_path):
    output = StringIO()

    exit_code = main.main(["--scan-repo", str(tmp_path / "missing")], stdout=output)

    assert exit_code == 1
    assert "Status: error" in output.getvalue()
    assert "not a readable directory" in output.getvalue()


def test_repository_text_escapes_untrusted_manifest_path_controls():
    result = {
        "status": "completed",
        "repository_path": "repo\x1b[2J\r\nforged",
        "files_observed": 1,
        "files_scanned": 1,
        "files_skipped": 0,
        "bytes_scanned": 10,
        "file_types": {".json\x1b[31m": 1},
        "manifests": [{"name": "package.json", "path": "dir\nname/package.json"}],
        "limitations": [],
        "errors": [],
        "coverage_complete": True,
        "note": "Inventory only.",
    }

    text = main._render_repository_text(result)

    assert "repo\\x1b[2J\\r\\nforged" in text
    assert "dir\\nname/package.json" in text
    assert "\\x1b[31m" in text
    assert "\x1b" not in text
    assert "\r" not in text


def test_json_output_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(main, "build_result", lambda diagnostic=None: {
        "system_info": {}, "package_scan": {"success": True, "error": None, "packages": []},
    })
    output_file = tmp_path / "scan.json"
    assert main.main(
        ["--json", "--output", str(output_file), "--diagnostics"], stdout=StringIO()
    ) == 0
    assert json.loads(output_file.read_text())["package_scan"]["success"] is True
    stderr = capsys.readouterr().err
    assert "[diagnostic] Report serialization completed in" in stderr
    assert "[diagnostic] Report writing completed in" in stderr


def test_cli_json_output_file_write_failure_returns_two(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        main,
        "collect_system_info",
        lambda: SystemInfo(
            operating_system="Linux",
            distribution="Debian GNU/Linux 12",
            distribution_version="12",
            kernel_version="6.1.0-test",
            architecture="x86_64",
            python_version="3.12.0",
            hostname="test-host",
        ),
    )
    monkeypatch.setattr(
        main,
        "scan_installed_packages",
        lambda: PackageScanResult([], "mock inventory failure"),
    )
    output_file = tmp_path / "scan.json"
    attempted_paths = []

    def fail_write_text(path, data, *args, **kwargs):
        attempted_paths.append(path)
        raise OSError("mocked disk full")

    monkeypatch.setattr(main.Path, "write_text", fail_write_text)
    stdout = StringIO()

    exit_code = main.main(
        ["--json", "--output", str(output_file)], stdout=stdout
    )

    stderr = capsys.readouterr().err
    assert exit_code == 2
    assert attempted_paths == [output_file]
    assert "Could not write JSON output:" in stderr
    assert "mocked disk full" in stderr
    assert "Traceback" not in stderr
    assert stdout.getvalue() == ""


def test_diagnostics_stay_on_stderr_and_preserve_json_stdout(monkeypatch, capsys):
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {"assessment_status": "no_known_match", "packages": []},
    }

    def fake_build_result(diagnostic=None):
        diagnostic("mock assessment stage completed in 0.001s.")
        return report

    monkeypatch.setattr(main, "build_result", fake_build_result)
    stdout = StringIO()

    assert main.main(["--json", "--diagnostics"], stdout=stdout) == 0

    assert json.loads(stdout.getvalue()) == report
    stderr = capsys.readouterr().err
    assert "[diagnostic] mock assessment stage" in stderr
    assert "[diagnostic] Report serialization completed in" in stderr
    assert "[diagnostic] Report writing to stdout completed in" in stderr
    assert "[diagnostic]" not in stdout.getvalue()


def test_cli_json_diagnostics_runs_real_build_result_end_to_end(monkeypatch, capsys):
    system_info = SystemInfo(
        operating_system="Linux",
        distribution="Ubuntu 24.04 LTS",
        distribution_version="24.04",
        kernel_version="6.8.0-test",
        architecture="x86_64",
        python_version="3.12.0",
        hostname="test-host",
    )
    package = Package("bash", "5.2.21-2ubuntu4", "bash", "5.2.21-2ubuntu4")
    monkeypatch.setattr(main, "collect_system_info", lambda: system_info)
    monkeypatch.setattr(main, "scan_installed_packages", lambda: PackageScanResult([package]))
    assessment_calls = {}

    def fake_assess_packages(packages, distribution, release, *, diagnostic=None):
        assessment_calls["packages"] = packages
        assessment_calls["distribution"] = distribution
        assessment_calls["release"] = release
        assessment_calls["diagnostic"] = diagnostic
        return VulnerabilityAssessmentReport(
            assessment_status="requires_review",
            distribution=distribution,
            release=release,
            source="mocked assessment source",
            error=None,
            packages=[PackageAssessment(
                package_name="bash",
                installed_version="5.2.21-2ubuntu4",
                assessment_status="requires_review",
                explanation="Mocked package assessment for CLI workflow coverage.",
                findings=[],
            )],
        )

    monkeypatch.setattr(main, "assess_packages", fake_assess_packages)
    stdout = StringIO()

    exit_code = main.main(["--json", "--diagnostics"], stdout=stdout)

    captured = capsys.readouterr()
    report = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert report["system_info"] == system_info.to_dict()
    assert report["package_scan"] == {
        "success": True,
        "error": None,
        "packages": [{"name": "bash", "version": "5.2.21-2ubuntu4"}],
    }
    assessment = report["vulnerability_assessment"]
    assert assessment["summary"]["total_assessed_packages"] == 1
    assert assessment["summary"]["status_counts"] == {"requires_review": 1}
    assert assessment["packages"][0]["package_name"] == "bash"
    assert assessment["packages"][0]["assessment_status"] == "requires_review"
    assert assessment_calls["packages"] == [package]
    assert assessment_calls["distribution"] == "Ubuntu 24.04 LTS"
    assert assessment_calls["release"] == "24.04"
    assert assessment_calls["diagnostic"] is not None
    assert "[diagnostic] System information collection started." in captured.err
    assert "[diagnostic] Package inventory started." in captured.err
    assert "[diagnostic] Report serialization completed in" in captured.err
    assert "[diagnostic] Report writing to stdout completed in" in captured.err
    assert "[diagnostic]" not in stdout.getvalue()


def test_cli_json_serializes_debian_review_finding_with_source_evidence(monkeypatch):
    system_info = SystemInfo(
        operating_system="Linux",
        distribution="Debian GNU/Linux 12",
        distribution_version="12",
        kernel_version="6.1.0-test",
        architecture="x86_64",
        python_version="3.12.0",
        hostname="test-host",
    )
    package = Package("openssh-server", "1:9.2p1-2+deb12u2", "openssh", "1:9.2p1-2+deb12u2")
    explanation = "The matching advisory has incomplete version-range data and requires review."
    finding = VulnerabilityFinding(
        advisory_id="DEBIAN-CVE-2024-9998",
        package_name=package.name,
        installed_version=package.version,
        source_reference="https://security-tracker.debian.org/tracker/CVE-2024-9998",
        severity=None,
        assessment_status="requires_review",
        explanation=explanation,
        source_package_name="openssh",
        source_version="1:9.2p1-2+deb12u2",
    )
    assessment = VulnerabilityAssessmentReport(
        assessment_status="requires_review",
        distribution="Debian GNU/Linux 12",
        release="12",
        source="Debian OSV via osv.dev",
        error=None,
        packages=[PackageAssessment(
            package_name=package.name,
            installed_version=package.version,
            assessment_status="requires_review",
            explanation=explanation,
            findings=[finding],
        )],
    )
    monkeypatch.setattr(main, "collect_system_info", lambda: system_info)
    monkeypatch.setattr(main, "scan_installed_packages", lambda: PackageScanResult([package]))
    monkeypatch.setattr(main, "assess_packages", lambda packages, distribution, release: assessment)
    stdout = StringIO()

    exit_code = main.main(["--json"], stdout=stdout)

    report = json.loads(stdout.getvalue())
    assessment_json = report["vulnerability_assessment"]
    assert exit_code == 0
    assert report["package_scan"]["success"] is True
    assert report["package_scan"]["packages"] == [
        {"name": "openssh-server", "version": "1:9.2p1-2+deb12u2"}
    ]
    assert assessment_json["summary"]["total_assessed_packages"] == 1
    assert assessment_json["summary"]["status_counts"] == {"requires_review": 1}
    serialized_finding = assessment_json["packages"][0]["findings"][0]
    assert serialized_finding["assessment_status"] == "requires_review"
    assert serialized_finding["advisory_id"] == "DEBIAN-CVE-2024-9998"
    assert serialized_finding["explanation"] == explanation
    assert serialized_finding["source_package_name"] == "openssh"
    assert serialized_finding["source_version"] == "1:9.2p1-2+deb12u2"


def test_build_result_reports_osv_error_when_inventory_succeeds(monkeypatch):
    system_info = SystemInfo(
        operating_system="Linux",
        distribution="Ubuntu 24.04 LTS",
        distribution_version="24.04",
        kernel_version="6.8.0-test",
        architecture="x86_64",
        python_version="3.12.0",
        hostname="test-host",
    )
    package = Package("bash", "5.2-2ubuntu1", "bash", "5.2-2ubuntu1")
    provider_error = "OSV query failed: offline"
    monkeypatch.setattr(main, "collect_system_info", lambda: system_info)
    monkeypatch.setattr(main, "scan_installed_packages", lambda: PackageScanResult([package]))

    def failed_assessment(packages, distribution, release):
        assert packages == [package]
        return VulnerabilityAssessmentReport(
            assessment_status="error",
            distribution=distribution,
            release=release,
            source="Ubuntu OSV via osv.dev",
            error=provider_error,
            packages=[PackageAssessment(
                package_name=package.name,
                installed_version=package.version,
                assessment_status="error",
                explanation=provider_error,
                findings=[],
            )],
        )

    monkeypatch.setattr(main, "assess_packages", failed_assessment)

    result = main.build_result()
    report = json.loads(json.dumps(result))
    assessment = report["vulnerability_assessment"]
    text = main._render_text(report)

    assert report["package_scan"]["success"] is True
    assert assessment["assessment_status"] == "error"
    assert assessment["source"] == "Ubuntu OSV via osv.dev"
    assert assessment["error"] == provider_error
    assert assessment["summary"]["total_assessed_packages"] == 1
    assert assessment["summary"]["status_counts"] == {"error": 1}
    assert assessment["packages"] == [{
        "package_name": "bash",
        "installed_version": "5.2-2ubuntu1",
        "assessment_status": "error",
        "explanation": provider_error,
        "findings": [],
    }]
    assert "Status: error" in text
    assert "Source: Ubuntu OSV via osv.dev" in text
    assert f"Details: {provider_error}" in text
    assert "Note: no_known_match means" not in text


def test_inventory_exception_is_diagnosed_and_propagated(monkeypatch):
    monkeypatch.setattr(
        main, "collect_system_info", lambda: type("Info", (), {"to_dict": lambda self: {
            "distribution": "Debian GNU/Linux 12", "distribution_version": "12",
        }})(),
    )

    def fail_inventory():
        raise RuntimeError("mock dpkg-query exception")

    monkeypatch.setattr(main, "scan_installed_packages", fail_inventory)
    messages = []

    with pytest.raises(RuntimeError, match="mock dpkg-query exception"):
        main.build_result(diagnostic=messages.append)

    assert any("Package inventory started" in message for message in messages)
    assert any("Package inventory failed in" in message for message in messages)
    assert any("RuntimeError" in message for message in messages)
    assert any("System information collection started" in message for message in messages)
    assert any("System information collection completed in" in message for message in messages)


def test_text_reports_scan_failure(monkeypatch):
    monkeypatch.setattr(main, "build_result", lambda: {
        "system_info": {}, "package_scan": {"success": False, "error": "unsupported", "packages": []},
    })
    output = StringIO()
    assert main.main([], stdout=output) == 1
    assert "Operating system: Unavailable" in output.getvalue()
    assert "Scan failed: unsupported" in output.getvalue()
    assert "Partial inventory:" not in output.getvalue()


def test_text_reports_retained_packages_as_partial_inventory():
    packages = [
        {"name": f"package-{index:02d}", "version": f"{index}.0"}
        for index in range(1, 13)
    ]
    report = {
        "system_info": {},
        "package_scan": {
            "success": False,
            "error": "dpkg-query returned 1 malformed package identity row; the inventory may be incomplete.",
            "packages": packages,
        },
    }

    text = main._render_text(report)

    assert "Scan failed: dpkg-query returned 1 malformed package identity row" in text
    assert "Partial inventory: 12 package(s) retained; this is not a complete inventory." in text
    for package in packages[:10]:
        assert f"  {package['name']} {package['version']}" in text
    assert "  package-11 11.0" not in text
    assert "  package-12 12.0" not in text
    assert "… and 2 more" in text


def test_successful_inventory_text_format_is_unchanged():
    report = {
        "system_info": {},
        "package_scan": {
            "success": True,
            "error": None,
            "packages": [
                {"name": "bash", "version": "5.2-2"},
                {"name": "libc6", "version": "2.36-9"},
            ],
        },
    }

    text = main._render_text(report)

    assert "Total packages found: 2" in text
    assert "  bash 5.2-2" in text
    assert "  libc6 2.36-9" in text
    assert "Partial inventory:" not in text
    assert "Scan failed:" not in text


def test_text_includes_vulnerability_assessment_when_available():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "no_known_match", "error": None,
            "packages": [], "explanation": "No matching record was found.",
        },
    }
    text = main._render_text(report)
    assert "Vulnerability assessment:" in text
    assert "Status: no_known_match" in text


def test_text_reports_assessment_summary_and_context():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "mixed", "distribution": "Debian GNU/Linux 12",
            "release": "12", "source": "Debian OSV via osv.dev", "error": None,
            "explanation": "Assessment completed.",
            "summary": {
                "total_assessed_packages": 2,
                "status_counts": {"fixed": 1, "no_known_match": 1},
                "no_known_match_note": "no_known_match is not proof that a package is safe.",
            },
            "packages": [
                {"assessment_status": "fixed", "findings": []},
                {"assessment_status": "no_known_match", "findings": []},
            ],
        },
    }
    text = main._render_text(report)
    assert "Distribution: Debian GNU/Linux 12" in text
    assert "Release: 12" in text
    assert "Source: Debian OSV via osv.dev" in text
    assert "Total assessed package entries: 2" in text
    assert "fixed: 1" in text
    assert "no_known_match: 1" in text
    assert "not proof that a package is safe" in text


def test_text_omits_no_match_warning_for_empty_assessment():
    assessment = VulnerabilityAssessmentReport(
        assessment_status="no_known_match",
        distribution="Debian GNU/Linux 12",
        release="12",
        source="Debian OSV via osv.dev",
        error=None,
        packages=[],
    ).to_dict()
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": assessment,
    }

    text = main._render_text(report)

    assert "Status: no_known_match" in text
    assert "Total assessed package entries: 0" in text
    assert "Note: " not in text


def test_text_renders_advisory_context_and_truncates_long_details():
    long_details = "Security advisory details. " * 30
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "vulnerable", "error": None,
            "advisory_context": {"DEBIAN-CVE-2024-6387": {
                "summary": "OpenSSH issue summary",
                "details": long_details,
                "references": [{"type": "REPORT", "url": "https://example.test/advisory"}],
            }},
            "packages": [{"assessment_status": "vulnerable", "findings": [{
                "advisory_id": "DEBIAN-CVE-2024-6387", "package_name": "openssh-server",
                "installed_version": "1", "severity": None,
                "assessment_status": "vulnerable", "urgency": "high",
                "source_package_name": "openssh",
                "source_version": "1:9.2p1-2+deb12u2",
            }]}],
        },
    }

    finding = report["vulnerability_assessment"]["packages"][0]["findings"][0]
    finding["severity"] = "High"
    finding["explanation"] = "The installed source version is below the advisory's fixed version."

    text = main._render_text(report)

    assert "Severity: High" in text
    assert "Explanation: The installed source version is below the advisory's fixed version." in text
    assert "Summary: OpenSSH issue summary" in text
    assert "Debian urgency: high" in text
    assert "Source package: openssh 1:9.2p1-2+deb12u2" in text
    assert "Advisory reference: https://example.test/advisory" in text
    detail_line = next(line for line in text.splitlines() if "    Details:" in line)
    rendered_details = detail_line.removeprefix("    Details: ")
    assert len(rendered_details) <= main.DETAILS_PREVIEW_LIMIT
    assert rendered_details.endswith("…")


def test_text_omits_missing_advisory_context_fields_without_error():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "vulnerable", "error": None,
            "advisory_context": {"CVE-2024-0001": {"references": [None, {}]}},
            "packages": [{"findings": [{
                "advisory_id": "CVE-2024-0001", "assessment_status": "vulnerable",
            }]}],
        },
    }

    text = main._render_text(report)

    assert "CVE-2024-0001" in text
    assert "Summary:" not in text
    assert "    Details:" not in text
    assert "Advisory reference:" not in text


def test_text_skips_malformed_null_findings_without_changing_package_counts():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "requires_review",
            "error": None,
            "packages": [{
                "assessment_status": "requires_review",
                "findings": None,
            }],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 1" in text
    assert "requires_review: 1" in text
    assert "CVE-" not in text


def test_text_renders_legacy_findings_without_advisory_context():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "vulnerable", "error": None,
            "packages": [{"findings": [{
                "advisory_id": "CVE-2024-0001", "package_name": "bash",
                "installed_version": "5.0", "assessment_status": "vulnerable",
            }]}],
        },
    }

    text = main._render_text(report)

    assert "vulnerable: CVE-2024-0001 — bash 5.0" in text
    assert "Source package:" not in text
    assert "Severity:" not in text
    assert "Explanation:" not in text


@pytest.mark.parametrize("severity, explanation", [(None, None), ("", "  ")])
def test_text_omits_unavailable_or_empty_finding_fields(severity, explanation):
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "requires_review", "error": None,
            "packages": [{"assessment_status": "requires_review", "findings": [{
                "advisory_id": "DEBIAN-CVE-2024-0001",
                "package_name": "openssl",
                "installed_version": "3.0.0",
                "assessment_status": "requires_review",
                "severity": severity,
                "explanation": explanation,
            }]}],
        },
    }

    text = main._render_text(report)

    assert "DEBIAN-CVE-2024-0001" in text
    assert "Severity:" not in text
    assert "Explanation:" not in text


def test_serialized_assessment_summary_matches_terminal_counts():
    assessment = VulnerabilityAssessmentReport(
        assessment_status="vulnerable",
        distribution="Debian GNU/Linux 12",
        release="12",
        source="Debian OSV via osv.dev",
        error=None,
        packages=[
            PackageAssessment("openssl", "1.0", "vulnerable", "Affected", []),
            PackageAssessment("bash", "2.0", "no_known_match", "No match", []),
            PackageAssessment("curl", "3.0", "vulnerable", "Affected", []),
        ],
    ).to_dict()
    result = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": assessment,
    }

    serialized = json.loads(json.dumps(assessment))
    text = main._render_text(result)

    assert serialized["summary"]["total_assessed_packages"] == 3
    assert serialized["summary"]["status_counts"] == {
        "vulnerable": 2,
        "no_known_match": 1,
    }
    assert "Status: vulnerable" in text
    assert "Total assessed package entries: 3" in text
    assert "vulnerable: 2" in text
    assert "no_known_match: 1" in text


def test_text_falls_back_to_empty_summary_for_unsupported_assessment():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "unsupported", "distribution": "Kali GNU/Linux Rolling",
            "release": "2025.1", "source": None, "error": "Unsupported for Kali.",
            "packages": [],
        },
    }
    text = main._render_text(report)
    assert "Status: unsupported" in text
    assert "Distribution: Kali GNU/Linux Rolling" in text
    assert "Details: Unsupported for Kali." in text
    assert "Total assessed package entries: 0" in text
    assert "Package assessment counts:\n    None" in text


def test_text_derives_counts_for_legacy_report_without_summary():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "requires_review", "error": None,
            "packages": [
                {"package_name": "openssl", "assessment_status": "no_known_match", "findings": []},
                {"package_name": "bash", "assessment_status": "requires_review", "findings": []},
                {"package_name": "curl", "assessment_status": "no_known_match", "findings": []},
            ],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 3" in text
    assert "no_known_match: 2" in text
    assert "requires_review: 1" in text


def test_text_uses_package_entries_when_supplied_summary_counts_are_incorrect():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "mixed", "error": None,
            "summary": {
                "total_assessed_packages": 99,
                "status_counts": {"fixed": 99},
                "no_known_match_note": "No known match is not proof of safety.",
            },
            "packages": [
                {"assessment_status": "vulnerable"},
                {"assessment_status": "no_known_match"},
            ],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 2" in text
    assert "vulnerable: 1" in text
    assert "no_known_match: 1" in text
    assert "fixed: 99" not in text
    assert "No known match is not proof of safety." in text


def test_text_ignores_nonzero_supplied_summary_for_empty_package_list():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "no_known_match", "error": None,
            "summary": {
                "total_assessed_packages": 4,
                "status_counts": {"no_known_match": 4},
            },
            "packages": [],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 0" in text
    assert "Package assessment counts:\n    None" in text
    assert "no_known_match: 4" not in text


def test_text_counts_package_with_missing_status_as_unknown():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "requires_review", "error": None,
            "summary": {
                "total_assessed_packages": 0,
                "status_counts": {},
            },
            "packages": [
                {"package_name": "legacy-package"},
                {"package_name": "known-package", "assessment_status": "fixed"},
            ],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 2" in text
    assert "fixed: 1" in text
    assert "unknown: 1" in text


def test_text_counts_malformed_package_entries_as_unknown():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "requires_review", "error": None,
            "packages": [
                {"package_name": "bash", "assessment_status": "vulnerable"},
                "malformed entry",
                None,
                {"package_name": "curl", "assessment_status": "fixed"},
            ],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 4" in text
    assert "vulnerable: 1" in text
    assert "fixed: 1" in text
    assert "unknown: 2" in text
    counts_section = text.split("Package assessment counts:\n", 1)[1].split("\n", 4)
    displayed_counts = [int(line.rsplit(": ", 1)[1]) for line in counts_section if ": " in line]
    assert sum(displayed_counts) == 4


def test_build_result_preserves_package_inventory_failure_in_json(monkeypatch):
    monkeypatch.setattr(
        main, "collect_system_info", lambda: type("Info", (), {"to_dict": lambda self: {
            "operating_system": "Linux", "distribution": "Debian GNU/Linux 12",
            "distribution_version": "12",
        }})(),
    )
    monkeypatch.setattr(
        main, "scan_installed_packages",
        lambda: PackageScanResult([], "dpkg-query failed: database unavailable"),
    )

    messages = []
    result = main.build_result(diagnostic=messages.append)
    serialized = json.loads(json.dumps(result))
    assessment = serialized["vulnerability_assessment"]

    assert serialized["package_scan"]["success"] is False
    assert serialized["package_scan"]["error"] == "dpkg-query failed: database unavailable"
    assert assessment["assessment_status"] == "error"
    assert assessment["summary"]["total_assessed_packages"] == 0
    assert assessment["summary"]["status_counts"] == {}
    assert any("Package inventory result: success=False" in message for message in messages)
    assert any("Package inventory started" in message for message in messages)
    assert any("Package inventory completed in" in message for message in messages)
    assert "Note: no_known_match means" not in main._render_text(serialized)


def test_cli_json_package_inventory_failure_exits_one_and_reports_error(monkeypatch):
    inventory_error = "dpkg-query failed: database unavailable"
    monkeypatch.setattr(
        main,
        "collect_system_info",
        lambda: SystemInfo(
            operating_system="Linux",
            distribution="Debian GNU/Linux 12",
            distribution_version="12",
            kernel_version="6.1.0-test",
            architecture="x86_64",
            python_version="3.12.0",
            hostname="test-host",
        ),
    )
    monkeypatch.setattr(
        main,
        "scan_installed_packages",
        lambda: PackageScanResult([], inventory_error),
    )
    stdout = StringIO()

    exit_code = main.main(["--json"], stdout=stdout)

    report = json.loads(stdout.getvalue())
    assessment = report["vulnerability_assessment"]
    assert exit_code == 1
    assert report["package_scan"] == {
        "success": False,
        "error": inventory_error,
        "packages": [],
    }
    assert assessment["assessment_status"] == "error"
    assert assessment["error"] == "Vulnerability assessment was not run because package inventory failed."
    assert assessment["summary"]["total_assessed_packages"] == 0
    assert assessment["summary"]["status_counts"] == {}


def test_build_result_uses_internal_source_metadata_without_changing_inventory_json(monkeypatch):
    package = Package("openssh-server", "1:9.2p1-2", "openssh", "1:9.2p1-2")
    monkeypatch.setattr(
        main, "collect_system_info", lambda: type("Info", (), {"to_dict": lambda self: {
            "operating_system": "Linux", "distribution": "Debian 12", "distribution_version": "12",
        }})(),
    )
    monkeypatch.setattr(main, "scan_installed_packages", lambda: PackageScanResult([package]))
    received = {}

    class Assessment:
        def to_dict(self):
            return {"assessment_status": "no_known_match", "packages": []}

    def assess(packages, distribution, release):
        received["package"] = packages[0]
        return Assessment()

    monkeypatch.setattr(main, "assess_packages", assess)
    result = main.build_result()
    assert received["package"].source_name == "openssh"
    assert received["package"].source_version == "1:9.2p1-2"
    assert result["package_scan"]["packages"] == [
        {"name": "openssh-server", "version": "1:9.2p1-2"}
    ]
