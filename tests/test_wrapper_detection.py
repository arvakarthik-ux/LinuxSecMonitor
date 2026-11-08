"""Tests for repository detection logic."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from src.wrapper.detection import (
    RepositoryDetector,
    RepositoryInfo,
    RepositoryType,
    DetectionMethod,
)


class TestNormalGitRepository:
    """Tests for normal Git repository detection."""

    def setup_method(self):
        self.detector = RepositoryDetector()

    def test_normal_git_repo(self, tmp_path):
        """Test detection in a standard Git repository."""
        repo = tmp_path / "repo"
        repo.mkdir()
        git_dir = repo / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main")
        (git_dir / "config").write_text("[core]\n")
        (git_dir / "objects").mkdir()
        (git_dir / "refs").mkdir()

        info = self.detector.detect(repo)
        assert info.is_repository
        assert info.repository_type == RepositoryType.GIT
        assert info.detection_method == DetectionMethod.GIT_DIR
        assert info.root == repo
        assert info.confidence == 1.0

    def test_git_repo_from_subdirectory(self, tmp_path):
        """Test detection from a subdirectory."""
        repo = tmp_path / "repo"
        repo.mkdir()
        git_dir = repo / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main")
        (git_dir / "config").write_text("[core]\n")
        (git_dir / "objects").mkdir()
        (git_dir / "refs").mkdir()

        subdir = repo / "src" / "module"
        subdir.mkdir(parents=True)

        info = self.detector.detect(subdir)
        assert info.is_repository
        assert info.root == repo


class TestNestedRepository:
    """Tests for nested repository detection."""

    def setup_method(self):
        self.detector = RepositoryDetector()

    def test_nested_repo_picks_nearest(self, tmp_path):
        """Test that nearest repository is picked in nested case."""
        outer = tmp_path / "outer"
        outer.mkdir()
        (outer / ".git").mkdir()
        (outer / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (outer / ".git" / "config").write_text("[core]\n")
        (outer / ".git" / "objects").mkdir()
        (outer / ".git" / "refs").mkdir()

        inner = outer / "inner"
        inner.mkdir()
        (inner / ".git").mkdir()
        (inner / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (inner / ".git" / "config").write_text("[core]\n")
        (inner / ".git" / "objects").mkdir()
        (inner / ".git" / "refs").mkdir()

        info = self.detector.detect(inner)
        assert info.is_repository
        assert info.root == inner

    def test_outer_repo_detected_from_between(self, tmp_path):
        """Test outer repo detected when between nested repos."""
        outer = tmp_path / "outer"
        outer.mkdir()
        (outer / ".git").mkdir()
        (outer / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (outer / ".git" / "config").write_text("[core]\n")
        (outer / ".git" / "objects").mkdir()
        (outer / ".git" / "refs").mkdir()

        inner = outer / "inner"
        inner.mkdir()
        (inner / ".git").mkdir()
        (inner / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (inner / ".git" / "config").write_text("[core]\n")
        (inner / ".git" / "objects").mkdir()
        (inner / ".git" / "refs").mkdir()

        between = outer / "between"
        between.mkdir()

        info = self.detector.detect(between)
        assert info.is_repository
        assert info.root == outer


class TestWorktreeDetection:
    """Tests for Git worktree detection."""

    def setup_method(self):
        self.detector = RepositoryDetector()

    def test_worktree_git_file(self, tmp_path):
        """Test detection of Git worktree via .git file."""
        main_repo = tmp_path / "main"
        main_repo.mkdir()
        (main_repo / ".git").mkdir()
        (main_repo / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (main_repo / ".git" / "config").write_text("[core]\n")
        (main_repo / ".git" / "objects").mkdir()
        (main_repo / ".git" / "refs").mkdir()

        worktree = tmp_path / "worktree"
        worktree.mkdir()
        git_file = worktree / ".git"
        git_file.write_text("gitdir: ../main/.git/worktrees/worktree")

        worktree_git = main_repo / ".git" / "worktrees" / "worktree"
        worktree_git.mkdir(parents=True)
        (worktree_git / "HEAD").write_text("ref: refs/heads/feature")
        (worktree_git / "config").write_text("[core]\n")
        (worktree_git / "objects").mkdir()
        (worktree_git / "refs").mkdir()

        info = self.detector.detect(worktree)
        assert info.is_repository
        assert info.detection_method == DetectionMethod.GIT_WORKTREE
        assert info.confidence == 0.95
        assert any("Worktree detected" in lim for lim in info.limitations)


class TestSubmoduleDetection:
    """Tests for Git submodule detection."""

    def setup_method(self):
        self.detector = RepositoryDetector()

    def test_submodule_git_file(self, tmp_path):
        """Test detection of Git submodule via .git file."""
        parent = tmp_path / "parent"
        parent.mkdir()
        (parent / ".git").mkdir()
        (parent / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (parent / ".git" / "config").write_text("[core]\n")
        (parent / ".git" / "objects").mkdir()
        (parent / ".git" / "refs").mkdir()

        submodule = parent / "submodule"
        submodule.mkdir()
        git_file = submodule / ".git"
        git_file.write_text("gitdir: ../.git/modules/submodule")

        submodule_git = parent / ".git" / "modules" / "submodule"
        submodule_git.mkdir(parents=True)
        (submodule_git / "HEAD").write_text("ref: refs/heads/main")
        (submodule_git / "config").write_text("[core]\n")
        (submodule_git / "objects").mkdir()
        (submodule_git / "refs").mkdir()

        info = self.detector.detect(submodule)
        assert info.is_repository
        assert info.detection_method == DetectionMethod.GIT_SUBMODULE
        assert info.confidence == 0.9
        assert any("Submodule detected" in lim for lim in info.limitations)


class TestSymlinkHandling:
    """Tests for symlink handling in repository detection."""

    def setup_method(self):
        self.detector = RepositoryDetector()

    def test_symlink_git_dir_valid(self, tmp_path):
        """Test valid symlink to .git directory."""
        real_repo = tmp_path / "real_repo"
        real_repo.mkdir()
        (real_repo / ".git").mkdir()
        (real_repo / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (real_repo / ".git" / "config").write_text("[core]\n")
        (real_repo / ".git" / "objects").mkdir()
        (real_repo / ".git" / "refs").mkdir()

        linked = tmp_path / "linked"
        linked.mkdir()
        git_link = linked / ".git"
        git_link.symlink_to(real_repo / ".git")

        info = self.detector.detect(linked)
        assert info.is_repository
        assert info.detection_method == DetectionMethod.GIT_DIR
        assert info.confidence == 0.9
        assert any(".git is a symlink" in lim for lim in info.limitations)

    def test_symlink_git_dir_invalid(self, tmp_path):
        """Test invalid symlink to .git directory."""
        linked = tmp_path / "linked"
        linked.mkdir()
        git_link = linked / ".git"
        git_link.symlink_to(tmp_path / "nonexistent")

        info = self.detector.detect(linked)
        assert not info.is_repository


class TestNonRepositoryDirectories:
    """Tests for non-repository directory handling."""

    def setup_method(self):
        self.detector = RepositoryDetector()

    def test_generic_project_directory(self, tmp_path):
        """Test generic project directory without .git."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "README.md").write_text("# Project")
        (project / "src").mkdir()
        (project / "src" / "main.py").write_text("print('hello')")

        info = self.detector.detect(project)
        assert not info.is_repository

    def test_empty_directory(self, tmp_path):
        """Test empty directory."""
        empty = tmp_path / "empty"
        empty.mkdir()

        info = self.detector.detect(empty)
        assert not info.is_repository

    def test_nonexistent_path(self, tmp_path):
        """Test nonexistent path."""
        nonexistent = tmp_path / "nonexistent"

        info = self.detector.detect(nonexistent)
        assert not info.is_repository
        assert info.errors

    def test_invalid_git_dir(self, tmp_path):
        """Test directory with incomplete .git."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        # Missing HEAD, config, objects, refs

        info = self.detector.detect(repo)
        assert not info.is_repository


class TestFilesystemErrors:
    """Tests for filesystem error handling."""

    def setup_method(self):
        self.detector = RepositoryDetector()

    def test_permission_error_handling(self, tmp_path, monkeypatch):
        """Test handling of permission errors."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main")

        def mock_resolve(path, strict=False):
            raise PermissionError("Permission denied")

        monkeypatch.setattr(Path, "resolve", mock_resolve)

        info = self.detector.detect(repo)
        assert not info.is_repository
        assert info.errors


class TestFindRepositoryRoot:
    """Tests for find_repository_root method."""

    def setup_method(self):
        self.detector = RepositoryDetector()

    def test_find_root_in_repo(self, tmp_path):
        """Test finding root from within repository."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (repo / ".git" / "config").write_text("[core]\n")
        (repo / ".git" / "objects").mkdir()
        (repo / ".git" / "refs").mkdir()

        subdir = repo / "src"
        subdir.mkdir()

        root = self.detector.find_repository_root(subdir)
        assert root == repo

    def test_find_root_none_outside(self, tmp_path):
        """Test finding root returns None outside repo."""
        outside = tmp_path / "outside"
        outside.mkdir()

        root = self.detector.find_repository_root(outside)
        assert root is None


class TestBypassDetection:
    """Tests for bypass detection in repository context."""

    def setup_method(self):
        self.detector = RepositoryDetector()

    def test_no_false_positive_parent_repo(self, tmp_path):
        """Test that parent directory is not falsely identified as repo."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (repo / ".git" / "config").write_text("[core]\n")
        (repo / ".git" / "objects").mkdir()
        (repo / ".git" / "refs").mkdir()

        outside = tmp_path / "outside"
        outside.mkdir()

        info = self.detector.detect(outside)
        assert not info.is_repository


if __name__ == "__main__":
    pytest.main([__file__, "-v"])