"""Repository context detection for wrapper framework."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class DetectionMethod(Enum):
    """Method used to detect the repository."""

    GIT_DIR = "git_dir"
    GIT_FILE = "git_file"
    GIT_WORKTREE = "git_worktree"
    GIT_SUBMODULE = "git_submodule"
    NONE = "none"


class RepositoryType(Enum):
    """Type of repository detected."""

    GIT = "git"
    NONE = "none"


@dataclass(frozen=True)
class RepositoryInfo:
    """Structured repository detection result."""

    root: Path
    working_directory: Path
    repository_type: RepositoryType
    detection_method: DetectionMethod
    confidence: float
    errors: tuple[str, ...] = field(default_factory=tuple)
    limitations: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_repository(self) -> bool:
        """Whether a repository was detected."""
        return self.repository_type != RepositoryType.NONE


class RepositoryDetector:
    """Detects repository context from a working directory."""

    def __init__(self, max_depth: int = 256):
        """
        Initialize the detector.

        Args:
            max_depth: Maximum directory traversal depth to prevent infinite loops
        """
        self.max_depth = max_depth

    def detect(self, start_path: Path) -> RepositoryInfo:
        """
        Detect repository context from a starting path.

        Args:
            start_path: Path to start detection from (typically current working directory)

        Returns:
            RepositoryInfo with detection results
        """
        try:
            resolved_start = start_path.resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as exc:
            return RepositoryInfo(
                root=start_path,
                working_directory=start_path,
                repository_type=RepositoryType.NONE,
                detection_method=DetectionMethod.NONE,
                confidence=0.0,
                errors=(f"Could not resolve start path: {exc}",),
            )

        if not resolved_start.exists():
            return RepositoryInfo(
                root=resolved_start,
                working_directory=resolved_start,
                repository_type=RepositoryType.NONE,
                detection_method=DetectionMethod.NONE,
                confidence=0.0,
                errors=(f"Start path does not exist: {resolved_start}",),
            )

        return self._walk_up(resolved_start)

    def _walk_up(self, path: Path) -> RepositoryInfo:
        """Walk up the directory tree looking for repository markers."""
        current = path
        depth = 0
        visited: set[Path] = set()

        while depth < self.max_depth:
            try:
                current_resolved = current.resolve(strict=False)
            except (OSError, RuntimeError, ValueError):
                break

            if current_resolved in visited:
                break
            visited.add(current_resolved)

            git_result = self._check_git_repository(current_resolved)
            if git_result:
                return git_result

            parent = current_resolved.parent
            if parent == current_resolved:
                break
            current = parent
            depth += 1

        return RepositoryInfo(
            root=path,
            working_directory=path,
            repository_type=RepositoryType.NONE,
            detection_method=DetectionMethod.NONE,
            confidence=0.0,
            limitations=("No repository found in parent directories",),
        )

    def _check_git_repository(self, path: Path) -> Optional[RepositoryInfo]:
        """Check if path is a Git repository root."""
        try:
            git_dir = path / ".git"
            if not git_dir.exists():
                return None

            if git_dir.is_symlink():
                target = git_dir.readlink()
                return self._handle_symlink_git(path, git_dir, target)

            if git_dir.is_file():
                return self._handle_git_file(path, git_dir)

            if git_dir.is_dir():
                return self._handle_git_dir(path, git_dir)

        except (OSError, RuntimeError, ValueError) as exc:
            return RepositoryInfo(
                root=path,
                working_directory=path,
                repository_type=RepositoryType.NONE,
                detection_method=DetectionMethod.NONE,
                confidence=0.0,
                errors=(f"Error checking Git repository: {exc}",),
            )

        return None

    def _handle_git_dir(self, path: Path, git_dir: Path) -> RepositoryInfo:
        """Handle standard .git directory."""
        if self._verify_git_dir(git_dir):
            return RepositoryInfo(
                root=path,
                working_directory=path,
                repository_type=RepositoryType.GIT,
                detection_method=DetectionMethod.GIT_DIR,
                confidence=1.0,
            )
        return RepositoryInfo(
            root=path,
            working_directory=path,
            repository_type=RepositoryType.NONE,
            detection_method=DetectionMethod.NONE,
            confidence=0.0,
            limitations=(".git directory exists but appears invalid",),
        )

    def _handle_git_file(self, path: Path, git_file: Path) -> RepositoryInfo:
        """Handle .git file (worktree or submodule)."""
        try:
            content = git_file.read_text(encoding="utf-8").strip()
            if not content.startswith("gitdir: "):
                return RepositoryInfo(
                    root=path,
                    working_directory=path,
                    repository_type=RepositoryType.NONE,
                    detection_method=DetectionMethod.NONE,
                    confidence=0.0,
                    limitations=(".git file does not contain gitdir directive",),
                )

            gitdir_path = content[8:].strip()
            gitdir = (path / gitdir_path).resolve(strict=False)

            if not gitdir.exists() or not gitdir.is_dir():
                return RepositoryInfo(
                    root=path,
                    working_directory=path,
                    repository_type=RepositoryType.NONE,
                    detection_method=DetectionMethod.NONE,
                    confidence=0.0,
                    limitations=(f"Referenced gitdir does not exist: {gitdir}",),
                )

            if not self._verify_git_dir(gitdir):
                return RepositoryInfo(
                    root=path,
                    working_directory=path,
                    repository_type=RepositoryType.NONE,
                    detection_method=DetectionMethod.NONE,
                    confidence=0.0,
                    limitations=("Referenced gitdir appears invalid",),
                )

            if "worktrees" in gitdir_path:
                return RepositoryInfo(
                    root=path,
                    working_directory=path,
                    repository_type=RepositoryType.GIT,
                    detection_method=DetectionMethod.GIT_WORKTREE,
                    confidence=0.95,
                    limitations=("Worktree detected; some operations may affect linked repository",),
                )

            return RepositoryInfo(
                root=path,
                working_directory=path,
                repository_type=RepositoryType.GIT,
                detection_method=DetectionMethod.GIT_SUBMODULE,
                confidence=0.9,
                limitations=("Submodule detected; parent repository not inspected",),
            )

        except (OSError, RuntimeError, ValueError) as exc:
            return RepositoryInfo(
                root=path,
                working_directory=path,
                repository_type=RepositoryType.NONE,
                detection_method=DetectionMethod.NONE,
                confidence=0.0,
                errors=(f"Error reading .git file: {exc}",),
            )

    def _handle_symlink_git(self, path: Path, git_dir: Path, target: Path) -> RepositoryInfo:
        """Handle .git as a symlink."""
        try:
            resolved_target = git_dir.resolve(strict=False)
            if resolved_target.is_dir() and self._verify_git_dir(resolved_target):
                return RepositoryInfo(
                    root=path,
                    working_directory=path,
                    repository_type=RepositoryType.GIT,
                    detection_method=DetectionMethod.GIT_DIR,
                    confidence=0.9,
                    limitations=(".git is a symlink; target verified",),
                )
        except (OSError, RuntimeError, ValueError):
            pass

        return RepositoryInfo(
            root=path,
            working_directory=path,
            repository_type=RepositoryType.NONE,
            detection_method=DetectionMethod.NONE,
            confidence=0.0,
            limitations=(".git symlink target invalid or inaccessible",),
        )

    def _verify_git_dir(self, git_dir: Path) -> bool:
        """Verify that a directory is a valid Git repository."""
        try:
            required = ["HEAD", "config", "objects", "refs"]
            for item in required:
                if not (git_dir / item).exists():
                    return False
            return True
        except (OSError, RuntimeError, ValueError):
            return False

    def find_repository_root(self, start_path: Path) -> Optional[Path]:
        """
        Find the repository root from a starting path.

        Args:
            start_path: Path to start from

        Returns:
            Repository root path or None if not found
        """
        info = self.detect(start_path)
        if info.is_repository:
            return info.root
        return None