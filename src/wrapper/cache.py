"""Content-bound scan result cache for wrapper framework."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from threading import Lock


@dataclass(frozen=True)
class CacheKey:
    """Content-based cache key for scan results."""

    repo_content_hash: str
    config_hash: str
    scanner_version: str
    malware_db_version: str
    scan_scope: str = "full"

    @classmethod
    def from_repository(
        cls,
        repo_root: Path,
        config_hash: str,
        scanner_version: str,
        malware_db_version: str,
        scan_scope: str = "full",
    ) -> CacheKey:
        """Create cache key from repository content hash."""
        content_hash = cls._compute_repo_content_hash(repo_root)
        return cls(
            repo_content_hash=content_hash,
            config_hash=config_hash,
            scanner_version=scanner_version,
            malware_db_version=malware_db_version,
            scan_scope=scan_scope,
        )

    @staticmethod
    def _compute_repo_content_hash(repo_root: Path) -> str:
        """Compute deterministic hash of repository content."""
        hasher = hashlib.sha256()

        try:
            entries: list[Path] = []
            for entry in repo_root.rglob("*"):
                if entry.is_file() and not entry.is_symlink():
                    try:
                        rel = entry.relative_to(repo_root)
                        if ".git" not in rel.parts:
                            entries.append(entry)
                    except ValueError:
                        continue

            entries.sort(key=lambda p: str(p.relative_to(repo_root)))

            for entry in entries:
                try:
                    stat_info = entry.stat()
                    hasher.update(str(entry.relative_to(repo_root)).encode())
                    hasher.update(str(stat_info.st_size).encode())
                    hasher.update(str(int(stat_info.st_mtime_ns)).encode())

                    # Always hash file content regardless of size for security
                    # Reading in chunks to handle large files efficiently
                    with entry.open("rb") as f:
                        while chunk := f.read(64 * 1024):
                            hasher.update(chunk)
                except (OSError, IOError) as e:
                    # File read failure must not be silently ignored
                    # Include error indicator in hash to prevent stale cache hits
                    hasher.update(b"READ_ERROR:")
                    hasher.update(str(entry.relative_to(repo_root)).encode())
                    hasher.update(str(e).encode())

        except (OSError, RuntimeError) as e:
            # Directory traversal failure must not produce empty hash
            hasher.update(b"TRAVERSAL_ERROR:")
            hasher.update(str(e).encode())

        return hasher.hexdigest()[:32]

    def to_string(self) -> str:
        """Serialize cache key to string."""
        return f"{self.repo_content_hash}:{self.config_hash}:{self.scanner_version}:{self.malware_db_version}:{self.scan_scope}"

    @classmethod
    def from_string(cls, s: str) -> CacheKey:
        """Deserialize cache key from string."""
        parts = s.split(":")
        if len(parts) != 5:
            raise ValueError(f"Invalid cache key format: {s}")
        return cls(
            repo_content_hash=parts[0],
            config_hash=parts[1],
            scanner_version=parts[2],
            malware_db_version=parts[3],
            scan_scope=parts[4],
        )


@dataclass
class CacheEntry:
    """Cached scan result entry."""

    key: CacheKey
    result: dict[str, Any]
    created_at: float
    expires_at: float
    access_count: int = 0

    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        return time.time() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for storage."""
        return {
            "key": self.key.to_string(),
            "result": self.result,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "access_count": self.access_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CacheEntry:
        """Deserialize from dictionary."""
        return cls(
            key=CacheKey.from_string(data["key"]),
            result=data["result"],
            created_at=data["created_at"],
            expires_at=data["expires_at"],
            access_count=data.get("access_count", 0),
        )


class ScanCache:
    """Thread-safe scan result cache with content-based invalidation."""

    DEFAULT_TTL_SECONDS = 300
    MAX_ENTRIES = 1000
    MAX_SIZE_BYTES = 50 * 1024 * 1024

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_entries: int = MAX_ENTRIES,
        max_size_bytes: int = MAX_SIZE_BYTES,
    ):
        """
        Initialize the scan cache.

        Args:
            cache_dir: Directory for persistent cache (None for in-memory only)
            ttl_seconds: Time-to-live for cache entries
            max_entries: Maximum number of cache entries
            max_size_bytes: Maximum cache size in bytes
        """
        self.cache_dir = cache_dir
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.max_size_bytes = max_size_bytes
        self._memory_cache: dict[str, CacheEntry] = {}
        self._lock = Lock()

        if cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(cache_dir, 0o700)
            self._load_from_disk()

    def _load_from_disk(self) -> None:
        """Load cache entries from disk."""
        if not self.cache_dir:
            return

        try:
            for cache_file in self.cache_dir.glob("*.cache"):
                try:
                    with cache_file.open("r", encoding="utf-8") as f:
                        data = json.load(f)
                    entry = CacheEntry.from_dict(data)
                    if not entry.is_expired():
                        self._memory_cache[entry.key.to_string()] = entry
                except (json.JSONDecodeError, KeyError, ValueError, OSError):
                    continue
        except OSError:
            pass

    def _save_to_disk(self, key_str: str, entry: CacheEntry) -> None:
        """Save cache entry to disk atomically."""
        if not self.cache_dir:
            return

        cache_file = self.cache_dir / f"{key_str}.cache"
        temp_file = self.cache_dir / f".{key_str}.cache.tmp"

        try:
            with temp_file.open("w", encoding="utf-8") as f:
                json.dump(entry.to_dict(), f)
            temp_file.chmod(0o600)
            temp_file.replace(cache_file)
        except (OSError, IOError):
            try:
                temp_file.unlink(missing_ok=True)
            except OSError:
                pass

    def _evict_if_needed(self) -> None:
        """Evict expired or excess entries."""
        now = time.time()
        expired_keys = [
            k for k, v in self._memory_cache.items()
            if v.expires_at <= now
        ]
        for k in expired_keys:
            del self._memory_cache[k]

        if len(self._memory_cache) >= self.max_entries:
            sorted_entries = sorted(
                self._memory_cache.items(),
                key=lambda kv: (kv[1].access_count, kv[1].created_at)
            )
            to_remove = len(self._memory_cache) - self.max_entries + 1
            for k, _ in sorted_entries[:to_remove]:
                del self._memory_cache[k]

    def get(self, key: CacheKey) -> Optional[dict[str, Any]]:
        """
        Get cached scan result if valid.

        Args:
            key: Cache key to look up

        Returns:
            Cached result dictionary or None if not found/expired
        """
        key_str = key.to_string()

        with self._lock:
            entry = self._memory_cache.get(key_str)
            if entry is None:
                return None

            if entry.is_expired():
                del self._memory_cache[key_str]
                return None

            entry.access_count += 1
            return entry.result

    def set(self, key: CacheKey, result: dict[str, Any]) -> None:
        """
        Store scan result in cache.

        Args:
            key: Cache key
            result: Scan result to cache
        """
        key_str = key.to_string()
        now = time.time()

        entry = CacheEntry(
            key=key,
            result=result,
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )

        with self._lock:
            self._evict_if_needed()
            self._memory_cache[key_str] = entry
            self._save_to_disk(key_str, entry)

    def invalidate(self, key: CacheKey) -> bool:
        """
        Invalidate a specific cache entry.

        Args:
            key: Cache key to invalidate

        Returns:
            True if entry was found and removed
        """
        key_str = key.to_string()

        with self._lock:
            if key_str in self._memory_cache:
                del self._memory_cache[key_str]
                if self.cache_dir:
                    cache_file = self.cache_dir / f"{key_str}.cache"
                    try:
                        cache_file.unlink(missing_ok=True)
                    except OSError:
                        pass
                return True
            return False

    def invalidate_repository(self, repo_root: Path) -> int:
        """
        Invalidate all cache entries for a repository.

        Args:
            repo_root: Repository root path

        Returns:
            Number of entries invalidated
        """
        content_hash = CacheKey._compute_repo_content_hash(repo_root)
        count = 0

        with self._lock:
            keys_to_remove = [
                k for k, v in self._memory_cache.items()
                if v.key.repo_content_hash == content_hash
            ]
            for k in keys_to_remove:
                del self._memory_cache[k]
                count += 1

            if self.cache_dir:
                for cache_file in self.cache_dir.glob("*.cache"):
                    try:
                        if cache_file.name.startswith(content_hash):
                            cache_file.unlink(missing_ok=True)
                    except OSError:
                        pass

        return count

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._memory_cache.clear()
            if self.cache_dir:
                for cache_file in self.cache_dir.glob("*.cache"):
                    try:
                        cache_file.unlink(missing_ok=True)
                    except OSError:
                        pass

    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            now = time.time()
            expired = sum(1 for v in self._memory_cache.values() if v.expires_at <= now)
            total_size = sum(
                len(json.dumps(v.to_dict()).encode())
                for v in self._memory_cache.values()
            )
            return {
                "entries": len(self._memory_cache),
                "expired": expired,
                "total_size_bytes": total_size,
                "max_entries": self.max_entries,
                "max_size_bytes": self.max_size_bytes,
                "ttl_seconds": self.ttl_seconds,
            }