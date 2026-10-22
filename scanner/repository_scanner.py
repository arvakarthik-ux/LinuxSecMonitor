"""Read-only inventory for a local source-code repository.

This module lists filesystem metadata only. It never opens file contents or
executes repository-provided code, and it excludes Git internals by default.
"""

from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILES = 100_000
MAX_DIRECTORIES = 20_000
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_SCAN_SECONDS = 30.0
TEXT_MANIFEST_PREVIEW_LIMIT = 20

MANIFEST_NAMES = {
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
}


@dataclass
class RepositoryScanResult:
    """Structured result from a repository file inventory."""

    status: str
    repository_path: str
    files_observed: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    file_types: dict[str, int] = field(default_factory=dict)
    manifests: list[dict[str, str]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    coverage_complete: bool = False
    note: str = (
        "Inventory only: file contents were not analyzed for malware, secrets, "
        "vulnerabilities, or overall security. .git internals are excluded."
    )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready copy of the inventory result."""
        return {
            "status": self.status,
            "repository_path": self.repository_path,
            "files_observed": self.files_observed,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "file_types": dict(self.file_types),
            "manifests": [dict(manifest) for manifest in self.manifests],
            "limitations": list(self.limitations),
            "errors": list(self.errors),
            "coverage_complete": self.coverage_complete,
            "note": self.note,
        }


def _add_once(items: list[str], message: str) -> None:
    """Avoid repeating the same limitation for every matching entry."""
    if message not in items:
        items.append(message)


def _failure(path: str, message: str) -> RepositoryScanResult:
    """Create an explicit failed result for path validation errors."""
    return RepositoryScanResult(
        status="error",
        repository_path=path,
        errors=[message],
    )


def _is_symlink_or_junction(path: str | Path, entry=None) -> bool:
    """Recognize ordinary symlinks and Windows directory junctions."""
    if entry is not None and entry.is_symlink():
        return True
    if entry is None and Path(path).is_symlink():
        return True
    is_junction = getattr(os.path, "isjunction", None)
    if is_junction is not None and is_junction(path):
        return True
    try:
        file_stat = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    # Python exposes isjunction only from 3.12. Windows marks junctions and
    # other reparse points in st_file_attributes, so older supported runtimes
    # can still skip them rather than treating them as ordinary directories.
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    return bool(getattr(file_stat, "st_file_attributes", 0) & reparse_flag)


def scan_repository(repository_path: str | Path) -> RepositoryScanResult:
    """Inventory a directory without following links or reading file contents.

    ``bytes_scanned`` is the sum of regular-file sizes recorded from file
    metadata. File contents are not read. Limits make an interrupted inventory
    explicit rather than presenting partial data as complete.
    """
    try:
        root = Path(repository_path).expanduser().absolute()
        display_path = str(root)
        if _is_symlink_or_junction(root):
            return _failure(
                display_path,
                "Repository path must not be a symbolic link or directory junction.",
            )
        if not root.is_dir():
            return _failure(display_path, "Repository path is not a readable directory.")
    except (OSError, TypeError, ValueError) as exc:
        return _failure(str(repository_path), f"Could not inspect repository path: {exc}")

    result = RepositoryScanResult(status="completed", repository_path=display_path)
    started = time.monotonic()
    pending = [root]
    directories_observed = 0
    stop_scan = False
    root_read_error = False

    def observe_file_entry() -> bool:
        """Count every file-like entry against the traversal file limit."""
        result.files_observed += 1
        if result.files_observed > MAX_FILES:
            result.files_skipped += 1
            _add_once(result.limitations, "File count limit reached.")
            return False
        return True

    while pending and not stop_scan:
        if time.monotonic() - started >= MAX_SCAN_SECONDS:
            _add_once(result.limitations, "Repository scan time limit reached.")
            break
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError as exc:
            result.errors.append(f"Could not read directory {directory}: {exc}")
            if directory == root:
                root_read_error = True
            continue

        try:
            with entries:
                for entry in entries:
                    if time.monotonic() - started >= MAX_SCAN_SECONDS:
                        _add_once(result.limitations, "Repository scan time limit reached.")
                        stop_scan = True
                        break
                    if entry.name == ".git":
                        continue
                    try:
                        if _is_symlink_or_junction(entry.path, entry):
                            if not observe_file_entry():
                                stop_scan = True
                                break
                            result.files_skipped += 1
                            _add_once(
                                result.limitations,
                                "Symbolic links and junctions were skipped and not followed.",
                            )
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            directories_observed += 1
                            if directories_observed > MAX_DIRECTORIES:
                                _add_once(result.limitations, "Directory count limit reached.")
                                stop_scan = True
                                break
                            pending.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            if not observe_file_entry():
                                stop_scan = True
                                break
                            result.files_skipped += 1
                            _add_once(
                                result.limitations,
                                "Non-regular filesystem entries were skipped.",
                            )
                            continue

                        if not observe_file_entry():
                            stop_scan = True
                            break

                        file_stat = entry.stat(follow_symlinks=False)
                        size = file_stat.st_size
                        if size < 0:
                            result.files_skipped += 1
                            result.errors.append(f"File has an invalid size: {entry.path}")
                            continue
                        if size > MAX_FILE_BYTES:
                            result.files_skipped += 1
                            _add_once(
                                result.limitations,
                                "One or more files exceeded the individual file-size limit.",
                            )
                            continue
                        if result.bytes_scanned + size > MAX_TOTAL_BYTES:
                            result.files_skipped += 1
                            _add_once(result.limitations, "Total file-size limit reached.")
                            stop_scan = True
                            break

                        result.files_scanned += 1
                        result.bytes_scanned += size
                        suffix = Path(entry.name).suffix.lower() or "[no extension]"
                        result.file_types[suffix] = result.file_types.get(suffix, 0) + 1
                        if entry.name in MANIFEST_NAMES:
                            relative_path = Path(entry.path).relative_to(root).as_posix()
                            result.manifests.append({
                                "name": entry.name,
                                "path": relative_path,
                            })
                    except OSError as exc:
                        result.files_skipped += 1
                        result.errors.append(f"Could not inventory {entry.path}: {exc}")
        except OSError as exc:
            result.errors.append(f"Could not continue reading directory {directory}: {exc}")
            if directory == root:
                root_read_error = True

    if root_read_error and result.files_scanned == 0:
        result.status = "error"
    elif result.errors or result.limitations:
        result.status = "incomplete"
    else:
        result.status = "completed"
        result.coverage_complete = True

    result.file_types = dict(sorted(result.file_types.items()))
    result.manifests.sort(key=lambda item: item["path"])
    return result
