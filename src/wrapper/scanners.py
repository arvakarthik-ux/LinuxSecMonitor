"""Parallel, bounded orchestration for repository scanners."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path
from typing import Callable

from scanner.repository_malware_scanner import scan_repository_malware
from scanner.repository_scanner import scan_repository
from scanner.repository_security_scanner import scan_repository_security

MAX_CONCURRENT_SCANNERS = 3


def repository_content_hash(repository: str | Path) -> str:
    """Return a deterministic hash of repository worktree content."""
    root = Path(repository).expanduser().resolve(strict=False)
    hasher = hashlib.sha256()
    try:
        entries = sorted(
            (
                entry for entry in root.rglob("*")
                if entry.is_file() and not entry.is_symlink()
                and ".git" not in entry.relative_to(root).parts
            ),
            key=lambda entry: entry.relative_to(root).as_posix(),
        )
    except (OSError, RuntimeError):
        hasher.update(b"TRAVERSAL_ERROR")
        return hasher.hexdigest()

    for entry in entries:
        try:
            relative = entry.relative_to(root).as_posix()
            data = entry.read_bytes()
            hasher.update(relative.encode("utf-8", "surrogateescape"))
            hasher.update(b"\0")
            hasher.update(str(len(data)).encode("ascii"))
            hasher.update(b"\0")
            hasher.update(data)
        except (OSError, RuntimeError):
            hasher.update(b"READ_ERROR\0")
            hasher.update(relative.encode("utf-8", "surrogateescape"))
    return hasher.hexdigest()


def _snapshot_repository(repository: Path, destination: Path) -> None:
    """Copy regular repository worktree content into an isolated snapshot."""
    destination.mkdir(mode=0o700)
    for source in repository.rglob("*"):
        try:
            relative = source.relative_to(repository)
        except ValueError:
            continue
        if ".git" in relative.parts:
            continue
        target = destination / relative
        if source.is_symlink() or source.is_file():
            continue
        if source.is_dir():
            target.mkdir(mode=0o700, exist_ok=True)
    for source in repository.rglob("*"):
        try:
            relative = source.relative_to(repository)
        except ValueError:
            continue
        if ".git" in relative.parts or source.is_symlink() or not source.is_file():
            continue
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def _serialize(value: object) -> dict[str, object]:
    if hasattr(value, "to_dict"):
        serialized = value.to_dict()
        if isinstance(serialized, dict):
            return serialized
    if isinstance(value, dict):
        return dict(value)
    raise TypeError(f"Scanner returned unsupported result type: {type(value).__name__}")


def _run_bounded(operation: Callable[[], object], timeout: float) -> tuple[object | None, dict[str, object]]:
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(operation)
    try:
        return future.result(timeout=timeout), {}
    except FuturesTimeoutError:
        future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        return None, {"status": "timeout", "coverage_complete": False,
                      "errors": ["Scanner timed out."], "limitations": ["Scanner coverage incomplete due to timeout."]}
    except Exception as exc:
        executor.shutdown(wait=False, cancel_futures=True)
        return None, {"status": "error", "coverage_complete": False,
                      "errors": [f"Scanner failed: {type(exc).__name__}."],
                      "limitations": ["Scanner coverage incomplete due to an error."]}
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


class ScannerOrchestrator:
    """Run the three repository scanners against one private snapshot."""

    def __init__(
        self,
        *,
        max_workers: int = MAX_CONCURRENT_SCANNERS,
        timeout_seconds: float = 120.0,
        inventory_scanner: Callable = scan_repository,
        malware_scanner: Callable = scan_repository_malware,
        security_scanner: Callable = scan_repository_security,
    ):
        self.max_workers = min(max_workers, MAX_CONCURRENT_SCANNERS)
        self.timeout_seconds = timeout_seconds
        self.inventory_scanner = inventory_scanner
        self.malware_scanner = malware_scanner
        self.security_scanner = security_scanner

    def scan(self, repository: str | Path) -> dict[str, object]:
        root = Path(repository).expanduser().resolve(strict=False)
        started = time.monotonic()
        initial_hash = repository_content_hash(root)
        if not root.is_dir():
            return self._failed_result(root, initial_hash, started, ["Repository is not a readable directory."])

        with tempfile.TemporaryDirectory(prefix="linuxsecmonitor-wrapper-") as temporary:
            snapshot = Path(temporary) / "repository"
            try:
                _snapshot_repository(root, snapshot)
            except (OSError, shutil.Error) as exc:
                return self._failed_result(root, initial_hash, started,
                                           [f"Repository snapshot failed: {type(exc).__name__}."])

            snapshot_hash = repository_content_hash(snapshot)
            # A snapshot must describe the same worktree that was assessed.
            if snapshot_hash != initial_hash and repository_content_hash(root) != initial_hash:
                return self._failed_result(root, initial_hash, started,
                                           ["Repository changed while creating the scan snapshot."])

            operations = {
                "inventory": lambda: self.inventory_scanner(snapshot),
                "malware": lambda: self.malware_scanner(snapshot),
                "security": lambda: self.security_scanner(snapshot),
            }
            results: dict[str, dict[str, object]] = {}
            pool = ThreadPoolExecutor(max_workers=self.max_workers)
            try:
                futures = {name: pool.submit(_run_bounded, operation, self.timeout_seconds)
                           for name, operation in operations.items()}
                for name, future in futures.items():
                    value, error = future.result()
                    if error:
                        results[name] = error
                    else:
                        try:
                            results[name] = _serialize(value)
                        except Exception as exc:
                            results[name] = {
                                "status": "error",
                                "coverage_complete": False,
                                "errors": [f"Scanner result invalid: {type(exc).__name__}."],
                            }
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

        current_hash = repository_content_hash(root)
        changed = current_hash != initial_hash or current_hash != snapshot_hash
        duration = round(time.monotonic() - started, 3)
        coverage_complete = not changed and all(
            result.get("coverage_complete") is True for result in results.values()
        )
        if changed:
            for result in results.values():
                result["coverage_complete"] = False
            coverage_complete = False

        return {
            "repository": str(root),
            "repository_content_hash": initial_hash if not changed else None,
            "snapshot_hash": snapshot_hash,
            "coverage_complete": coverage_complete,
            "repository_changed_during_scan": changed,
            "scan_duration_seconds": duration,
            "scanner_versions": {
                "inventory": "repository_scanner",
                "malware": "repository_malware_scanner",
                "security": "repository_security_scanner",
            },
            "inventory": results["inventory"],
            "malware": results["malware"],
            "security": results["security"],
        }

    @staticmethod
    def _failed_result(root: Path, content_hash: str, started: float, errors: list[str]) -> dict[str, object]:
        def failed(name: str) -> dict[str, object]:
            return {"status": "error", "coverage_complete": False,
                    "errors": errors, "limitations": [f"{name} was not run due to snapshot failure."]}
        return {
            "repository": str(root),
            "repository_content_hash": content_hash,
            "snapshot_hash": None,
            "coverage_complete": False,
            "repository_changed_during_scan": False,
            "scan_duration_seconds": round(time.monotonic() - started, 3),
            "inventory": failed("Inventory"),
            "malware": failed("Malware"),
            "security": failed("Security"),
        }
