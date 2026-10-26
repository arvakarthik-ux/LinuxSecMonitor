"""Offline tests for repository static review heuristics and safe walking."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner import repository_security_scanner as scanner


def _analyze(path: str, content: bytes):
    findings = []
    seen = set()
    error = scanner._analyze_file(path, content, findings, seen)
    return findings, error


def test_file_metadata_comparison_detects_mode_change_without_ctime_change():
    before = SimpleNamespace(
        st_dev=1, st_ino=2, st_mode=0o100644, st_uid=1000, st_gid=1000,
        st_size=12, st_mtime_ns=100, st_ctime_ns=200,
    )
    after = SimpleNamespace(
        st_dev=1, st_ino=2, st_mode=0o100600, st_uid=1000, st_gid=1000,
        st_size=12, st_mtime_ns=100, st_ctime_ns=200,
    )

    assert not scanner._same_file_metadata(before, after)


def test_add_once_deduplicates_repeated_coverage_limitations():
    limitations = []

    scanner._add_once(limitations, "Generated cache path excluded.")
    scanner._add_once(limitations, "Generated cache path excluded.")

    assert limitations == ["Generated cache path excluded."]


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        (b"[core]\nhooksPath = /tmp/custom-hooks\n", (True, False, False)),
        (b'[includeIf "gitdir:~/work/"]\npath = ../shared-config\n', (False, True, False)),
        (b"[]\n", (False, False, True)),
        (b"core.hooksPath = hooks\n", (False, False, True)),
    ],
)
def test_git_hook_config_parser_reports_redirects_and_malformed_data(config, expected):
    assert scanner._git_hook_config_state(config) == expected


@pytest.mark.parametrize(
    ("path", "is_directory", "expected"),
    [
        ("tests/__pycache__", True, True),
        (".pytest_cache", True, True),
        ("src/module.pyc", False, True),
        ("src/module.pyo", False, True),
        ("tests/test_module.py", False, False),
        ("src/__pycache__.py", False, False),
    ],
)
def test_generated_python_cache_classification(path, is_directory, expected):
    assert scanner._is_generated_python_cache(path, is_directory) is expected


def test_package_lifecycle_script_is_reviewed_without_echoing_command():
    command = bytes.fromhex(
        "6375726c2068747470733a2f2f6578616d706c652e696e76616c69642f78207c207368"
    )
    findings, error = _analyze(
        "package.json",
        b'{"scripts":{"postinstall":"' + command + b'"}}',
    )

    assert error is None
    ids = {finding.rule_id for finding in findings}
    assert "package-lifecycle-script" in ids
    assert "download-piped-to-shell" in ids
    assert all("curl https" not in finding.evidence for finding in findings)


def test_secret_indicators_are_redacted_from_report():
    token = bytes.fromhex("6768705f" + "41" * 35)
    private_key_header = bytes.fromhex(
        "2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d"
    )
    findings, _ = _analyze(
        "src/config.py",
        b"first line\n" + private_key_header + b"\n" + token,
    )

    assert {finding.rule_id for finding in findings} == {
        "private-key-material", "token-like-value",
    }
    serialized = " ".join(finding.evidence for finding in findings)
    assert token.decode() not in serialized
    assert "redacted" in serialized
    assert {finding.line_number for finding in findings} == {2, 3}


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
    fake_key = bytes.fromhex("414b4941" + "31" * 16).decode()
    (root / ".git" / "credential.txt").write_text(fake_key, encoding="utf-8")
    (root / "untracked.sh").write_text("#!/bin/sh\necho ordinary\n", encoding="utf-8")
    (root / "package.json").write_text(
        '{"scripts":{"install":"node setup.js"}}', encoding="utf-8",
    )

    result = scanner.scan_repository_security(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert result.files_inspected == 2
    assert any(item.rule_id == "package-lifecycle-script" for item in result.findings)
    assert all(".git/" not in item.path for item in result.findings)
    assert any("global" in item for item in result.limitations)


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_repository_scan_reviews_active_default_git_hooks_but_not_other_git_internals(tmp_path):
    root = tmp_path / "repo"
    hooks = root / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (root / ".git" / "config").write_text("[core]\n\trepositoryformatversion = 0\n", encoding="utf-8")
    (root / ".git" / "credential.txt").write_text("ordinary private metadata\n", encoding="utf-8")
    hook = hooks / "pre-commit"
    hook.write_text("#!/bin/sh\necho review-me\n", encoding="utf-8")
    hook.chmod(0o755)

    result = scanner.scan_repository_security(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    active_hooks = [finding for finding in result.findings if finding.rule_id == "active-git-hook"]
    assert len(active_hooks) == 1
    assert active_hooks[0].path == ".git/hooks/pre-commit"
    assert "did not execute" in active_hooks[0].explanation
    assert all("credential.txt" not in finding.path for finding in result.findings)


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_repository_scan_reports_custom_or_unparseable_git_hook_configuration(tmp_path):
    root = tmp_path / "repo"
    git = root / ".git"
    git.mkdir(parents=True)
    (git / "config").write_text("[core]\nhooksPath = /tmp/external-hooks\n[]\n", encoding="utf-8")

    result = scanner.scan_repository_security(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert any("custom core.hooksPath" in item for item in result.limitations)
    assert any("malformed or unsupported syntax" in item for item in result.limitations)


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_repository_scan_does_not_follow_symlinked_git_hook(tmp_path):
    root = tmp_path / "repo"
    hooks = root / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (root / ".git" / "config").write_text("[core]\nrepositoryformatversion = 0\n", encoding="utf-8")
    outside = tmp_path / "outside-hook"
    outside.write_text("#!/bin/sh\n", encoding="utf-8")
    outside.chmod(0o755)
    try:
        (hooks / "pre-commit").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")

    result = scanner.scan_repository_security(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert not any(finding.rule_id == "active-git-hook" for finding in result.findings)
    assert any("non-regular entries were skipped" in item for item in result.limitations)


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_repository_scan_reports_nested_git_metadata_as_uninspected(tmp_path):
    root = tmp_path / "repo"
    nested_git = root / "vendor" / ".git"
    (nested_git / "hooks").mkdir(parents=True)
    nested_hook = nested_git / "hooks" / "pre-commit"
    nested_hook.write_text("#!/bin/sh\n", encoding="utf-8")
    nested_hook.chmod(0o755)

    result = scanner.scan_repository_security(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert not any(finding.path == "vendor/.git/hooks/pre-commit" for finding in result.findings)
    assert any("Nested Git metadata" in item for item in result.limitations)


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


def test_static_scanner_fixture_source_has_no_embedded_detection_samples():
    findings, error = _analyze(__file__, Path(__file__).read_bytes())

    assert error is None
    assert not findings


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_generated_python_caches_are_excluded_from_static_review_by_default(tmp_path):
    root = tmp_path / "repo"
    cache = root / "tests" / "__pycache__"
    cache.mkdir(parents=True)
    (root / "src.py").write_text("ordinary source\n", encoding="utf-8")
    (cache / "compiled.pyc").write_bytes(bytes.fromhex(
        "2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d"
    ))
    (root / "standalone.pyo").write_bytes(b"generated bytecode")

    result = scanner.scan_repository_security(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert result.files_inspected == 1
    assert result.generated_paths_excluded == 2
    assert result.include_generated is False
    assert not result.findings
    assert any("excluded from static review" in item for item in result.limitations)
    assert "ClamAV scan is not affected" in result.note


@pytest.mark.skipif(os.name != "posix", reason="safe directory-descriptor walk requires POSIX")
def test_generated_python_caches_can_be_included_in_static_review(tmp_path):
    root = tmp_path / "repo"
    cache = root / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "compiled.pyc").write_bytes(bytes.fromhex(
        "2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d"
    ))

    result = scanner.scan_repository_security(root, include_generated=True)

    assert result.status == "requires_review"
    assert result.coverage_complete is True
    assert result.files_inspected == 1
    assert result.generated_paths_excluded == 0
    assert result.include_generated is True
    assert result.findings[0].rule_id == "private-key-material"
    assert "key material redacted" in result.findings[0].evidence
