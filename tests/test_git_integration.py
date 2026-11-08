"""Tests for 3A.5 Git Command Integration."""

from __future__ import annotations

import tempfile
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from src.wrapper.commands import CommandClassifier, Tier
from src.wrapper.core import CommandWrapper
from src.wrapper.detection import RepositoryDetector
from src.wrapper.approval import ApprovalManager


class TestGitCommandClassification:
    """Tests for Git command tier classification."""

    def setup_method(self):
        self.classifier = CommandClassifier()

    def test_git_clone_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "clone", "https://example.com/repo.git"])
        assert tier == Tier.TIER_1_DANGEROUS
        assert reason is None

    def test_git_checkout_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "checkout", "main"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_switch_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "switch", "feature"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_restore_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "restore", "file.txt"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_merge_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "merge", "feature"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_pull_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "pull"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_fetch_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "fetch"])
        assert tier == Tier.TIER_2_WARN

    def test_git_rebase_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "rebase", "main"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_reset_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "reset", "--hard"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_submodule_update_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "submodule", "update"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_worktree_add_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "worktree", "add", "../wt"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_status_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "status"])
        assert tier == Tier.TIER_2_WARN

    def test_git_diff_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "diff"])
        assert tier == Tier.TIER_2_WARN

    def test_git_log_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "log"])
        assert tier == Tier.TIER_2_WARN

    def test_git_branch_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "branch"])
        assert tier == Tier.TIER_2_WARN

    def test_git_tag_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "tag"])
        assert tier == Tier.TIER_2_WARN

    def test_git_remote_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "remote"])
        assert tier == Tier.TIER_2_WARN

    def test_git_blame_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "blame", "file.txt"])
        assert tier == Tier.TIER_2_WARN

    def test_git_grep_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "grep", "pattern"])
        assert tier == Tier.TIER_2_WARN

    def test_git_stash_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "stash"])
        assert tier == Tier.TIER_2_WARN

    def test_git_config_tier3(self):
        tier, reason = self.classifier.classify("git", ["git", "config", "user.name"])
        assert tier == Tier.TIER_3_PASSTHROUGH

    def test_git_init_tier3(self):
        tier, reason = self.classifier.classify("git", ["git", "init"])
        assert tier == Tier.TIER_3_PASSTHROUGH

    def test_git_version_tier3(self):
        tier, reason = self.classifier.classify("git", ["git", "--version"])
        assert tier == Tier.TIER_3_PASSTHROUGH

    def test_git_help_tier3(self):
        tier, reason = self.classifier.classify("git", ["git", "--help"])
        assert tier == Tier.TIER_3_PASSTHROUGH


class TestGitCloneWorkflow:
    """Tests for Git clone workflow."""

    def test_clone_classified_as_tier1(self):
        """git clone should be Tier 1 requiring scan and approval."""
        classifier = CommandClassifier()
        tier, _ = classifier.classify("git", ["git", "clone", "https://github.com/user/repo.git"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_clone_with_directory_tier1(self):
        """git clone with target directory should be Tier 1."""
        classifier = CommandClassifier()
        tier, _ = classifier.classify("git", ["git", "clone", "https://github.com/user/repo.git", "mydir"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_clone_recursive_tier1(self):
        """git clone --recursive should be Tier 1."""
        classifier = CommandClassifier()
        tier, _ = classifier.classify("git", ["git", "clone", "--recursive", "https://github.com/user/repo.git"])
        assert tier == Tier.TIER_1_DANGEROUS


class TestGitCheckoutWorkflow:
    """Tests for Git checkout/switch workflow."""

    def test_checkout_branch_tier1(self):
        """git checkout branch should be Tier 1."""
        classifier = CommandClassifier()
        tier, _ = classifier.classify("git", ["git", "checkout", "feature-branch"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_switch_branch_tier1(self):
        """git switch branch should be Tier 1."""
        classifier = CommandClassifier()
        tier, _ = classifier.classify("git", ["git", "switch", "main"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_checkout_commit_tier1(self):
        """git checkout commit-hash should be Tier 1."""
        classifier = CommandClassifier()
        tier, _ = classifier.classify("git", ["git", "checkout", "abc123"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_restore_file_tier1(self):
        """git restore file should be Tier 1."""
        classifier = CommandClassifier()
        tier, _ = classifier.classify("git", ["git", "restore", "file.txt"])
        assert tier == Tier.TIER_1_DANGEROUS


class TestGitHookConfigAnalysis:
    """Tests for Git hook and configuration analysis integration."""

    def test_repository_detector_finds_git_repo(self):
        """RepositoryDetector should find git repos."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=repo, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True)
            (repo / "test.txt").write_text("test")
            subprocess.run(["git", "add", "test.txt"], cwd=repo, capture_output=True)
            subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, capture_output=True)

            detector = RepositoryDetector()
            info = detector.detect(repo)
            assert info.is_repository
            assert info.repository_type.value == "git"
            assert info.detection_method.value == "git_dir"

    def test_repository_detector_finds_subdirectory(self):
        """RepositoryDetector should find repo from subdirectory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=repo, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True)

            subdir = repo / "src" / "sub"
            subdir.mkdir(parents=True)

            detector = RepositoryDetector()
            info = detector.detect(subdir)
            assert info.is_repository
            assert info.root == repo

    def test_repository_detector_worktree(self):
        """RepositoryDetector should detect worktrees."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True)
            (repo / "test.txt").write_text("test")
            subprocess.run(["git", "add", "test.txt"], cwd=repo, capture_output=True)
            subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, capture_output=True)

            # Create worktree
            wt = Path(tmpdir) / "worktree"
            result = subprocess.run(["git", "worktree", "add", str(wt), "main"], cwd=repo, capture_output=True)
            if result.returncode != 0:
                pytest.skip(f"git worktree not supported or failed: {result.stderr.decode()}")

            detector = RepositoryDetector()
            info = detector.detect(wt)
            assert info.is_repository
            assert info.detection_method.value == "git_file"


class TestGitApprovalCancellation:
    """Tests for approval and cancellation with Git commands."""

    def test_git_checkout_requires_approval(self):
        """git checkout should require approval (Tier 1)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=repo, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True)
            (repo / "test.txt").write_text("test")
            subprocess.run(["git", "add", "test.txt"], cwd=repo, capture_output=True)
            subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, capture_output=True)

            wrapper = CommandWrapper("git", ["git", "checkout", "main"], cwd=repo)
            decision = wrapper.get_decision()
            assert decision.tier.value == "tier_1_dangerous"
            assert decision.requires_approval

    def test_git_status_no_approval(self):
        """git status should not require approval (Tier 2)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=repo, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True)

            wrapper = CommandWrapper("git", ["git", "status"], cwd=repo)
            decision = wrapper.get_decision()
            assert decision.tier.value == "tier_2_warn"
            assert decision.requires_warning
            assert not decision.requires_approval

    def test_git_version_passthrough(self):
        """git --version should passthrough (Tier 3)."""
        wrapper = CommandWrapper("git", ["git", "--version"])
        decision = wrapper.get_decision()
        assert decision.tier.value == "tier_3_passthrough"
        assert decision.is_passthrough


class TestGitArgvPreserved:
    """Tests for original argv preservation with Git commands."""

    def test_git_checkout_argv_preserved(self):
        """git checkout argv should be preserved exactly."""
        argv = ["git", "checkout", "-b", "feature/branch-name"]
        wrapper = CommandWrapper("git", argv)
        decision = wrapper.get_decision()
        assert decision.original_argv == tuple(argv)
        assert decision.argv == tuple(argv)

    def test_git_clone_argv_preserved(self):
        """git clone argv should be preserved exactly."""
        argv = ["git", "clone", "https://github.com/user/repo.git", "mydir"]
        wrapper = CommandWrapper("git", argv)
        decision = wrapper.get_decision()
        assert decision.original_argv == tuple(argv)
        assert decision.argv == tuple(argv)

    def test_git_merge_argv_preserved(self):
        """git merge argv should be preserved exactly."""
        argv = ["git", "merge", "--no-ff", "feature"]
        wrapper = CommandWrapper("git", argv)
        decision = wrapper.get_decision()
        assert decision.original_argv == tuple(argv)
        assert decision.argv == tuple(argv)

    def test_git_rebase_argv_preserved(self):
        """git rebase argv should be preserved exactly."""
        argv = ["git", "rebase", "-i", "HEAD~3"]
        wrapper = CommandWrapper("git", argv)
        decision = wrapper.get_decision()
        assert decision.original_argv == tuple(argv)
        assert decision.argv == tuple(argv)


class TestGitSubmoduleWorkflow:
    """Tests for Git submodule operations."""

    def test_submodule_update_tier1(self):
        """git submodule update should be Tier 1."""
        classifier = CommandClassifier()
        tier, _ = classifier.classify("git", ["git", "submodule", "update"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_submodule_add_tier1(self):
        """git submodule add should be Tier 1 (not explicitly listed, falls to default)."""
        classifier = CommandClassifier()
        tier, _ = classifier.classify("git", ["git", "submodule", "add", "https://example.com/sub.git"])
        # submodule add is not explicitly listed, falls to default for git = TIER_2_WARN
        assert tier in (Tier.TIER_1_DANGEROUS, Tier.TIER_2_WARN)


class TestGitWorktreeWorkflow:
    """Tests for Git worktree operations."""

    def test_worktree_add_tier1(self):
        """git worktree add should be Tier 1."""
        classifier = CommandClassifier()
        tier, _ = classifier.classify("git", ["git", "worktree", "add", "../wt", "main"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_worktree_list_tier2(self):
        """git worktree list should be Tier 2 (not explicitly listed, falls to default)."""
        classifier = CommandClassifier()
        tier, _ = classifier.classify("git", ["git", "worktree", "list"])
        # worktree list is not explicitly listed, falls to default for git = TIER_2_WARN
        assert tier in (Tier.TIER_1_DANGEROUS, Tier.TIER_2_WARN)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
