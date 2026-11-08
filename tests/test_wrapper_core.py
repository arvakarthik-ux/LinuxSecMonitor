"""Tests for wrapper core functionality."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.wrapper.core import CommandWrapper, WrapperDecision, WrapperTier
from src.wrapper.commands import CommandClassifier, Tier
from src.wrapper.detection import RepositoryDetector, RepositoryInfo, RepositoryType, DetectionMethod
from src.wrapper.cache import ScanCache, CacheKey


class TestCommandIdentification:
    """Tests for command identification."""

    def test_command_name_extraction(self):
        """Test that command name is correctly extracted."""
        wrapper = CommandWrapper("git", ["git", "checkout", "main"])
        assert wrapper.command_name == "git"

    def test_argv_preservation(self):
        """Test that original argv is preserved exactly."""
        argv = ["git", "checkout", "-b", "feature"]
        wrapper = CommandWrapper("git", argv)
        assert wrapper.argv == tuple(argv)

    def test_absolute_path_command(self):
        """Test command with absolute path."""
        wrapper = CommandWrapper("/usr/bin/git", ["/usr/bin/git", "status"])
        assert wrapper.command_name == "/usr/bin/git"


class TestRepoRootDetection:
    """Tests for repository root detection."""

    def test_repo_detection_in_git_repo(self, tmp_path):
        """Test detection in a normal Git repository."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (repo / ".git" / "config").write_text("[core]\n")
        (repo / ".git" / "objects").mkdir()
        (repo / ".git" / "refs").mkdir()

        wrapper = CommandWrapper("git", ["git", "status"], cwd=repo)
        decision = wrapper.get_decision()

        assert decision.repository is not None
        assert decision.repository.is_repository
        assert decision.repository.repository_type == RepositoryType.GIT
        assert decision.repository.root == repo

    def test_repo_detection_in_subdirectory(self, tmp_path):
        """Test detection from a subdirectory of a Git repository."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (repo / ".git" / "config").write_text("[core]\n")
        (repo / ".git" / "objects").mkdir()
        (repo / ".git" / "refs").mkdir()

        subdir = repo / "src" / "subdir"
        subdir.mkdir(parents=True)

        wrapper = CommandWrapper("git", ["git", "status"], cwd=subdir)
        decision = wrapper.get_decision()

        assert decision.repository is not None
        assert decision.repository.is_repository
        assert decision.repository.root == repo

    def test_no_repo_detection_outside_repo(self, tmp_path):
        """Test no repository detected outside Git repo."""
        outside = tmp_path / "outside"
        outside.mkdir()

        wrapper = CommandWrapper("git", ["git", "status"], cwd=outside)
        decision = wrapper.get_decision()

        assert decision.repository is not None
        assert not decision.repository.is_repository

    def test_nested_repo_detection(self, tmp_path):
        """Test detection picks nearest repository in nested case."""
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

        wrapper = CommandWrapper("git", ["git", "status"], cwd=inner)
        decision = wrapper.get_decision()

        assert decision.repository is not None
        assert decision.repository.is_repository
        assert decision.repository.root == inner


class TestTierSelection:
    """Tests for tier selection."""

    def test_tier1_classification(self):
        """Test Tier 1 (dangerous) classification."""
        wrapper = CommandWrapper("git", ["git", "checkout", "main"])
        decision = wrapper.get_decision()
        assert decision.tier == WrapperTier.TIER_1_DANGEROUS
        assert decision.requires_approval

    def test_tier2_classification(self):
        """Test Tier 2 (warn) classification."""
        wrapper = CommandWrapper("git", ["git", "status"])
        decision = wrapper.get_decision()
        assert decision.tier == WrapperTier.TIER_2_WARN
        assert decision.requires_warning

    def test_tier3_classification(self):
        """Test Tier 3 (passthrough) classification."""
        wrapper = CommandWrapper("git", ["git", "--version"])
        decision = wrapper.get_decision()
        assert decision.tier == WrapperTier.TIER_3_PASSTHROUGH
        assert decision.is_passthrough

    def test_bypass_absolute_path(self):
        """Test bypass for absolute path commands."""
        wrapper = CommandWrapper("/usr/bin/git", ["/usr/bin/git", "checkout", "main"])
        decision = wrapper.get_decision()
        assert decision.tier == WrapperTier.BYPASS
        assert decision.bypass_reason == "absolute_path"
        assert decision.is_passthrough

    def test_bypass_shell_builtin(self):
        """Test bypass for shell builtins."""
        wrapper = CommandWrapper("source", ["source", "script.sh"])
        decision = wrapper.get_decision()
        assert decision.tier == WrapperTier.BYPASS
        assert decision.bypass_reason == "shell_builtin"

    def test_bypass_inline_interpreter(self):
        """Test bypass for inline interpreter."""
        wrapper = CommandWrapper("bash", ["bash", "-c", "echo hello"])
        decision = wrapper.get_decision()
        assert decision.tier == WrapperTier.BYPASS
        assert decision.bypass_reason == "inline_interpreter"

    def test_bypass_sudo(self):
        """Test bypass for sudo commands."""
        wrapper = CommandWrapper("sudo", ["sudo", "npm", "install"])
        decision = wrapper.get_decision()
        assert decision.tier == WrapperTier.BYPASS
        assert decision.bypass_reason == "sudo_environment"


class TestUnknownCommands:
    """Tests for unknown command handling."""

    def test_unknown_command_defaults_to_tier3(self):
        """Test unknown benign command defaults to Tier 3 (passthrough)."""
        wrapper = CommandWrapper("unknown_tool", ["unknown_tool", "dangerous"])
        decision = wrapper.get_decision()
        assert decision.tier == WrapperTier.TIER_3_PASSTHROUGH

    def test_invalid_arguments(self):
        """Test handling of empty argv preserves command name."""
        wrapper = CommandWrapper("git", [])
        decision = wrapper.get_decision()
        assert decision.argv == ("git",)


class TestScannerIntegration:
    """Tests for scanner integration."""

    @patch("src.wrapper.core.CommandWrapper._run_command")
    @patch("src.wrapper.scanners.ScannerOrchestrator.scan")
    @patch("src.wrapper.report.build_unified_report")
    @patch("src.wrapper.approval.ApprovalManager.request_approval")
    @patch("src.wrapper.approval.ApprovalManager.consume")
    def test_tier1_calls_scanners(self, mock_consume, mock_request, mock_report, mock_scan, mock_run):
        """Test Tier 1 execution calls scanner orchestration."""
        mock_scan.return_value = {
            "coverage_complete": True,
            "repository_content_hash": "abc123",
            "scanner_versions": {},
        }
        mock_report.return_value = {
            "coverage_complete": True,
            "repository_content_hash": "abc123",
            "malware_findings": [],
            "repository_changed_during_scan": False,
            "findings": [],
        }
        mock_request.return_value = object()  # non-None approval record
        mock_consume.return_value = True
        mock_run.return_value = 0

        wrapper = CommandWrapper("git", ["git", "checkout", "main"])
        result = wrapper.execute()

        mock_scan.assert_called_once()
        mock_report.assert_called_once()
        mock_request.assert_called_once()
        mock_consume.assert_called_once()
        mock_run.assert_called_once()
        assert result == 0

    @patch("src.wrapper.core.CommandWrapper._run_command")
    @patch("src.wrapper.scanners.ScannerOrchestrator.scan")
    @patch("src.wrapper.report.build_unified_report")
    def test_tier2_runs_scans(self, mock_report, mock_scan, mock_run):
        """Test Tier 2 execution runs scanner orchestration."""
        mock_scan.return_value = {
            "coverage_complete": True,
            "repository_content_hash": "abc123",
            "scanner_versions": {},
        }
        mock_report.return_value = {
            "coverage_complete": True,
            "repository_content_hash": "abc123",
            "malware_findings": [],
            "repository_changed_during_scan": False,
            "findings": [],
            "scanner_errors": {},
        }
        mock_run.return_value = 0

        wrapper = CommandWrapper("git", ["git", "status"])
        result = wrapper.execute()

        mock_scan.assert_called_once()
        mock_report.assert_called_once()
        mock_run.assert_called_once()
        assert result == 0


class TestOriginalArgvPreservation:
    """Tests that original argv is preserved when forwarding."""

    def test_argv_preserved_in_decision(self):
        """Test original argv stored in decision."""
        argv = ["git", "checkout", "-b", "feature-branch"]
        wrapper = CommandWrapper("git", argv)
        decision = wrapper.get_decision()
        assert decision.original_argv == tuple(argv)
        assert decision.argv == tuple(argv)


class TestRunCommandChildEnvironment:
    """Tests that the real _run_command path spawns with the explicit policy env."""

    def test_run_command_uses_explicit_child_environment(self, tmp_path, monkeypatch):
        """Real _run_command passes shell=False, explicit env, trusted argv[0]."""
        monkeypatch.setenv("LD_PRELOAD", "/evil.so")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/evil/gitconfig")
        monkeypatch.setenv("PYTHONPATH", "/evil/py")
        monkeypatch.setenv("VIRTUAL_ENV", "/evil/venv")
        monkeypatch.setenv("NODE_PATH", "/evil/node")
        environ_before = dict(os.environ)

        wrapper = CommandWrapper("ls", ["ls", "-la"], cwd=tmp_path)
        captured = {}

        def fake_run(safe_argv, **kwargs):
            captured["argv"] = safe_argv
            captured.update(kwargs)
            return SimpleNamespace(returncode=0)

        with patch(
            "src.wrapper.core.subprocess.run", side_effect=fake_run
        ) as run_mock:
            return_code = wrapper._run_command(wrapper.argv)

        assert return_code == 0
        assert run_mock.call_count == 1

        # argv[0] must be an absolute trusted executable path, argv preserved.
        safe_argv = captured["argv"]
        assert len(safe_argv) == 2
        assert os.path.isabs(safe_argv[0])
        assert safe_argv[0].endswith("/ls")
        assert safe_argv[1:] == ["-la"]

        # No shell, explicit policy-built environment.
        assert captured["shell"] is False
        assert captured["check"] is False
        child_env = captured["env"]
        assert isinstance(child_env, dict)
        for dangerous_key in ("LD_PRELOAD", "GIT_CONFIG_GLOBAL", "PYTHONPATH",
                              "VIRTUAL_ENV", "NODE_PATH"):
            assert dangerous_key not in child_env
        assert child_env["PWD"] == os.path.abspath(os.fspath(tmp_path))
        assert captured["cwd"] == tmp_path

        # Parent environment remains unchanged.
        assert dict(os.environ) == environ_before


if __name__ == "__main__":
    pytest.main([__file__, "-v"])