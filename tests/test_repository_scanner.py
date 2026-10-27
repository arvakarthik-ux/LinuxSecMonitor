"""Offline tests for safe, read-only repository inventory."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from scanner import repository_scanner as scanner


def test_repository_scan_result_keeps_existing_positional_field_order():
    result = scanner.RepositoryScanResult("completed", "repo", 1, 2, 3, 4)

    assert result.files_observed == 1
    assert result.files_scanned == 2
    assert result.files_skipped == 3
    assert result.bytes_scanned == 4
    assert result.skipped_entry_details == []


def test_reparse_point_attribute_is_treated_as_a_junction(monkeypatch):
    class Entry:
        path = "mock-junction"

        @staticmethod
        def is_symlink():
            return False

    monkeypatch.setattr(scanner.os.path, "isjunction", lambda path: False, raising=False)
    monkeypatch.setattr(
        scanner.os,
        "stat",
        lambda path, follow_symlinks=False: SimpleNamespace(st_file_attributes=0x0400),
    )

    assert scanner._is_symlink_or_junction("mock-junction", Entry()) is True


def test_scan_repository_inventories_files_and_manifests_without_running_them(tmp_path):
    root = tmp_path / "repo"
    nested = root / "src"
    nested.mkdir(parents=True)
    (root / "package.json").write_text('{"scripts":{"postinstall":"bad"}}', encoding="utf-8")
    (root / "README.md").write_text("documentation", encoding="utf-8")
    (nested / "requirements.txt").write_text("example==1.0\n", encoding="utf-8")
    marker = tmp_path / "executed.txt"
    (nested / "build.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    git_dir = root / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("internal", encoding="utf-8")

    result = scanner.scan_repository(root)

    assert result.status == "completed"
    assert result.coverage_complete is True
    assert result.files_scanned == 4
    assert result.files_skipped == 0
    assert result.bytes_scanned == sum(
        path.stat().st_size for path in (root / "package.json", root / "README.md",
                                         nested / "requirements.txt", nested / "build.py")
    )
    assert result.file_types == {".json": 1, ".md": 1, ".py": 1, ".txt": 1}
    assert result.manifests == [
        {"name": "package.json", "path": "package.json"},
        {"name": "requirements.txt", "path": "src/requirements.txt"},
    ]
    assert not marker.exists()
    assert all(".git" not in item["path"].split("/") for item in result.manifests)


@pytest.mark.parametrize("path_kind", ["missing", "file", "symlink"])
def test_scan_repository_rejects_invalid_root_paths(tmp_path, path_kind):
    if path_kind == "missing":
        root = tmp_path / "missing"
    elif path_kind == "file":
        root = tmp_path / "not-a-directory"
        root.write_text("data", encoding="utf-8")
    else:
        target = tmp_path / "target"
        target.mkdir()
        root = tmp_path / "root-link"
        try:
            root.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"directory symlinks are unavailable: {exc}")

    result = scanner.scan_repository(root)

    assert result.status == "error"
    assert result.coverage_complete is False
    assert result.errors


def test_scan_repository_reports_unreadable_root(monkeypatch, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    real_scandir = os.scandir

    def fail_root(path):
        if scanner.Path(path) == root:
            raise PermissionError("access denied in test")
        return real_scandir(path)

    monkeypatch.setattr(scanner.os, "scandir", fail_root)

    result = scanner.scan_repository(root)

    assert result.status == "error"
    assert result.files_scanned == 0
    assert any("access denied in test" in error for error in result.errors)


def test_scan_repository_does_not_follow_symlinks(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "package.json"
    target.write_text("{}", encoding="utf-8")
    try:
        (root / "linked-file.json").symlink_to(target)
        (root / "linked-dir").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"file or directory symlinks are unavailable: {exc}")

    result = scanner.scan_repository(root)

    assert result.status == "incomplete"
    assert result.files_scanned == 0
    assert result.files_observed == 2
    assert result.files_skipped == 2
    assert result.manifests == []
    assert {(item["path"], item["reason"]) for item in result.skipped_entry_details} == {
        ("linked-file.json", "symlink_or_junction"),
        ("linked-dir", "symlink_or_junction"),
    }
    assert any("Symbolic links and junctions were skipped" in item
               for item in result.limitations)


@pytest.mark.parametrize(
    ("limit_name", "limit_value", "file_sizes", "expected_scanned"),
    [
        ("MAX_FILES", 1, [2, 3], 1),
        ("MAX_FILE_BYTES", 2, [3, 1], 1),
        ("MAX_TOTAL_BYTES", 3, [2, 2], 1),
    ],
)
def test_scan_repository_limits_return_incomplete_coverage(
    monkeypatch, tmp_path, limit_name, limit_value, file_sizes, expected_scanned
):
    root = tmp_path / "repo"
    root.mkdir()
    for index, size in enumerate(file_sizes):
        (root / f"file-{index}.bin").write_bytes(b"x" * size)
    monkeypatch.setattr(scanner, limit_name, limit_value)

    result = scanner.scan_repository(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert result.files_scanned == expected_scanned
    assert result.files_skipped >= 1
    assert result.limitations


def test_scan_repository_time_limit_is_incomplete(monkeypatch, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "file.txt").write_text("data", encoding="utf-8")
    ticks = iter((0.0, 2.0))
    monkeypatch.setattr(scanner.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(scanner, "MAX_SCAN_SECONDS", 1.0)

    result = scanner.scan_repository(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert any("time limit" in item for item in result.limitations)


def test_scan_repository_file_count_limit_includes_oversized_skipped_files(
    monkeypatch, tmp_path
):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "large-a.bin").write_bytes(b"large")
    (root / "large-b.bin").write_bytes(b"also large")
    monkeypatch.setattr(scanner, "MAX_FILES", 1)
    monkeypatch.setattr(scanner, "MAX_FILE_BYTES", 1)

    result = scanner.scan_repository(root)

    assert result.status == "incomplete"
    assert result.coverage_complete is False
    assert result.files_scanned == 0
    assert result.files_observed == 2
    assert result.files_skipped == 2
    assert any("File count limit" in item for item in result.limitations)
    assert result.skipped_entry_details
    assert all(item["reason"] in {"individual_file_size_limit", "file_count_limit"}
               for item in result.skipped_entry_details)


def test_scan_repository_bounds_skipped_entry_details(monkeypatch, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "large-a.bin").write_bytes(b"large")
    (root / "large-b.bin").write_bytes(b"also large")
    monkeypatch.setattr(scanner, "MAX_SKIPPED_ENTRY_DETAILS", 1)
    monkeypatch.setattr(scanner, "MAX_FILE_BYTES", 1)

    result = scanner.scan_repository(root)
    report = result.to_dict()

    assert result.files_skipped == 2
    assert len(report["skipped_entry_details"]) == 1
    assert report["skipped_entry_details_omitted"] == 1
    assert result.files_skipped == (
        len(report["skipped_entry_details"])
        + report["skipped_entry_details_omitted"]
    )


def test_scan_repository_records_path_for_file_inventory_error(monkeypatch, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    class Entry:
        name = "unreadable.bin"
        path = str(root / name)

        @staticmethod
        def is_symlink():
            return False

        @staticmethod
        def is_dir(*, follow_symlinks):
            return False

        @staticmethod
        def is_file(*, follow_symlinks):
            return True

        @staticmethod
        def stat(*, follow_symlinks):
            raise PermissionError("read denied in test")

    class Entries:
        def __enter__(self):
            return self

        @staticmethod
        def __exit__(*_args):
            return False

        @staticmethod
        def __iter__():
            return iter((Entry(),))

    monkeypatch.setattr(scanner.os, "scandir", lambda _path: Entries())
    monkeypatch.setattr(scanner, "_is_symlink_or_junction", lambda *_args: False)

    result = scanner.scan_repository(root)

    assert result.status == "incomplete"
    assert result.files_skipped == 1
    assert result.skipped_entry_details == [{
        "path": "unreadable.bin", "reason": "inventory_error",
    }]
    assert any("read denied in test" in error for error in result.errors)


def test_scan_repository_handles_unusual_unicode_filename(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    unusual = root / "résumé [draft].PY"
    unusual.write_text("data", encoding="utf-8")

    result = scanner.scan_repository(root)

    assert result.status == "completed"
    assert result.file_types == {".py": 1}
    assert result.files_scanned == 1
