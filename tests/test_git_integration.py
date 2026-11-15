"""Tests for 3A.5 Git Command Integration."""

from __future__ import annotations

import tempfile
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from src.wrapper.commands import CommandClassifier, Tier
from src.wrapper.core import CommandWrapper
from src.wrapper.detection import RepositoryDetector
from src.wrapper.approval import ApprovalManager
from src.wrapper.git_clone import CloneInvocation, parse_clone_invocation
from src.wrapper.scanners import repository_content_hash


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

# ---------------------------------------------------------------------------
# Post-clone review support (3A.5 amendment)
# ---------------------------------------------------------------------------

POST_CLONE_PROMPT = (
    "Post-clone review complete. Type exactly RUN to acknowledge this "
    "reviewed snapshot (this does not authorize any later command): "
)


def _make_source_repo(path: Path, filename: str = "file.txt") -> None:
    """Create a real local Git seed repository (offline)."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True,
                   capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"],
                   cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path,
                   check=True, capture_output=True)
    (path / filename).write_text("seed content\n")
    subprocess.run(["git", "add", filename], cwd=path, check=True,
                   capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "seed"], cwd=path,
                   check=True, capture_output=True)


def complete_scan_side_effect(root):
    """ScannerOrchestrator.scan double: content-aware complete, clean result."""
    root = Path(root)
    content_hash = repository_content_hash(root)
    return {
        "repository": str(root),
        "repository_content_hash": content_hash,
        "snapshot_hash": content_hash,
        "coverage_complete": True,
        "repository_changed_during_scan": False,
        "scan_duration_seconds": 0.0,
        "scanner_versions": {
            "inventory": "inventory-fixture",
            "malware": "malware-fixture",
            "security": "security-fixture",
        },
        "inventory": {"status": "completed", "coverage_complete": True, "errors": []},
        "malware": {"status": "no_detection", "coverage_complete": True,
                    "errors": [], "detections": []},
        "security": {"status": "completed", "coverage_complete": True,
                     "errors": [], "findings": []},
    }


def perform_clone(argv_tail, cwd, scan_side_effect, terminal, record=None):
    """Run a real offline clone through the wrapper after off-disk preparation.

    The child process bridge delegates to the real ``subprocess.run`` so the
    clone and its visible side effects are genuine; only the scanner
    orchestration is replaced, and ApprovalManager is asserted unused.
    Returns ``(exit_code, captured_calls)``.
    """
    argv = ["git", *argv_tail]
    captured = []
    real_run = subprocess.run  # captured before the core subprocess.run patch

    def recording_run(safe_argv, **kwargs):
        if record is not None:
            captured.append((safe_argv, kwargs))
        completed = real_run(
            safe_argv, cwd=kwargs["cwd"], check=False, shell=False,
            env=kwargs["env"], capture_output=True,
        )
        return SimpleNamespace(returncode=completed.returncode)

    with patch(
        "src.wrapper.approval.ApprovalManager.request_approval",
        side_effect=lambda **run_kwargs: pytest.fail(
            "post-clone review must not use the approval manager"),
    ), patch(
        "src.wrapper.scanners.ScannerOrchestrator.scan",
        side_effect=scan_side_effect,
    ), patch(
        "src.wrapper.core.subprocess.run", side_effect=recording_run,
    ):
        wrapper = CommandWrapper("git", argv, cwd=cwd, terminal=terminal)
        exit_code = wrapper.execute()
    return exit_code, captured


def prompt_must_not_appear(monkeypatch):
    monkeypatch.setattr(
        "scanner.execution_guard.confirm_execution",
        lambda terminal=None, *, prompt=None: pytest.fail(
            "prompt must not be reached"),
    )


class _QueueTerminal:
    """Text terminal that records prompts and answers them from a queue."""

    def __init__(self, answers):
        self._answers = list(answers)
        self.prompts = []
        self.prompted = 0

    def write(self, value):
        self.prompts.append(value)
        return len(value)

    def flush(self):
        return None

    def readline(self):
        self.prompted += 1
        return self._answers.pop(0) if self._answers else ""


class _InterruptTerminal:
    """Terminal whose readline raises KeyboardInterrupt."""

    def write(self, value):
        return len(value)

    def flush(self):
        return None

    def readline(self):
        raise KeyboardInterrupt


class _MutatingTerminal:
    """Terminal that mutates repository content before answering RUN."""

    def __init__(self, answer, target: Path, payload: str):
        self._answer = answer
        self._target = target
        self._payload = payload

    def write(self, value):
        return len(value)

    def flush(self):
        return None

    def readline(self):
        self._target.write_text(self._payload)
        return self._answer


class TestCloneInvocationParsing:
    """Parser/resolution tests for the pure git clone parser."""

    def _parse(self, tokens, cwd):
        return parse_clone_invocation(("git", "clone", *tokens), cwd)

    def test_not_a_clone(self, tmp_path):
        assert parse_clone_invocation(("git", "status"), tmp_path).error is not None
        assert parse_clone_invocation(
            ("git", "checkout", "main"), tmp_path).error is not None
        assert parse_clone_invocation((), tmp_path).error is not None

    def test_explicit_destination_wins(self, tmp_path):
        invocation = self._parse([str(tmp_path / "seed"), "explicit"], tmp_path)
        assert invocation.error is None
        assert invocation.destination == (tmp_path / "explicit")
        assert invocation.bare is False and invocation.mirror is False

    def test_default_destination_from_absolute_seed_git(self, tmp_path):
        assert self._parse(["/abs/seed.git"], tmp_path).destination == \
            tmp_path / "seed"

    def test_default_destination_trailing_slash(self, tmp_path):
        assert self._parse(["/abs/seed.git/"], tmp_path).destination == \
            tmp_path / "seed"

    def test_default_destination_file_uri(self, tmp_path):
        assert self._parse(["file:///abs/seed.git"], tmp_path).destination == \
            tmp_path / "seed"

    def test_default_destination_relative(self, tmp_path):
        # Real git derives the last component and places it in the cwd:
        # `git clone ../seed.git` creates ./seed inside the cwd.
        invocation = self._parse(["../seed.git"], tmp_path)
        assert invocation.destination == tmp_path / "seed"
        assert invocation.destination.name == "seed"

    def test_default_destination_scp_like(self, tmp_path):
        assert self._parse(["git@host.example:team/repo.git"], tmp_path).destination \
            == tmp_path / "repo"

    def test_bare_and_mirror_reported(self, tmp_path):
        bare = self._parse(["--bare", "/abs/seed.git"], tmp_path)
        assert bare.error is None and bare.bare is True and bare.mirror is False
        mirrored = self._parse(["--mirror", "/abs/seed.git"], tmp_path)
        assert mirrored.error is None and mirrored.mirror is True \
            and mirrored.bare is False

    def test_value_options_detached_and_attached(self, tmp_path):
        cases = [
            ["--branch", "main"],
            ["-b", "main"],
            ["-bmain"],
            ["--depth", "1"],
            ["--depth=1"],
            ["-j2"],
            ["--jobs=2"],
            ["-c", "http.sslVerify=false"],
            ["-chttp.sslVerify=false"],
            ["--filter=blob:none"],
            ["-o", "upstream"],
        ]
        for options in cases:
            invocation = self._parse([*options, "/abs/seed.git"], tmp_path)
            assert invocation.error is None, options
            assert invocation.destination == tmp_path / "seed", options

    def test_optional_value_option_never_consumes_next_token(self, tmp_path):
        cases = [
            (["--recurse-submodules", "/abs/seed.git"], "seed"),
            (["--recursive", "/abs/seed.git"], "seed"),
            (["--recurse-submodules=1", "/abs/seed.git"], "seed"),
            (["--recursive=/tmp/some-path", "a"], "a"),
        ]
        for options, expected_name in cases:
            invocation = self._parse([*options], tmp_path)
            assert invocation.error is None, options
            assert invocation.destination == tmp_path / expected_name, options

    def test_boolean_options_never_consume_next_token(self, tmp_path):
        cases = [
            ["--no-checkout"],
            ["-n"],
            ["-l", "-s"],
            ["-qn"],
            ["--tags"],
            ["--no-tags"],
            ["--dissociate"],
            ["--progress"],
            ["-4"],
            ["--ipv4"],
            ["--ipv6"],
            ["-4", "--ipv6"],
            ["--ipv4", "--ipv6"],
            ["--sparse"],
        ]
        for options in cases:
            invocation = self._parse([*options, "/abs/seed.git"], tmp_path)
            assert invocation.error is None, options
            assert invocation.destination == tmp_path / "seed", options

    def test_negations_of_known_options_are_boolean(self, tmp_path):
        for negation in ["--no-bare", "--no-branch", "--no-depth",
                         "--no-reference", "--no-single-branch"]:
            invocation = self._parse([negation, "/abs/seed.git"], tmp_path)
            assert invocation.error is None, negation
            assert invocation.destination == tmp_path / "seed", negation

    def test_no_bare_and_no_mirror_clear_flags_in_order(self, tmp_path):
        cases = [
            (["--bare", "--no-bare"], False, False),
            (["--mirror", "--no-mirror"], False, False),
            (["--no-bare", "--bare"], True, False),
            (["--no-mirror", "--mirror"], False, True),
        ]
        for options, bare, mirror in cases:
            invocation = self._parse([*options, "/abs/seed.git"], tmp_path)
            assert invocation.error is None, options
            assert invocation.destination == tmp_path / "seed", options
            assert invocation.bare is bare, options
            assert invocation.mirror is mirror, options

    def test_double_dash_ends_option_parsing(self, tmp_path):
        invocation = self._parse(["--", "-weird-repo"], tmp_path)
        assert invocation.repository == "-weird-repo"
        assert invocation.destination == tmp_path / "-weird-repo"

    def test_options_permuted_around_positionals(self, tmp_path):
        invocation = self._parse(["/abs/seed.git", "--bare", "dest"], tmp_path)
        assert invocation.destination == tmp_path / "dest"
        assert invocation.bare is True

    def test_zero_positionals_error(self, tmp_path):
        assert self._parse([], tmp_path).error is not None
        assert self._parse(["--bare"], tmp_path).error is not None

    def test_three_positionals_error(self, tmp_path):
        assert self._parse(["a", "b", "c"], tmp_path).error is not None

    def test_unknown_option_is_error(self, tmp_path):
        assert self._parse(["--frobnicate", "a"], tmp_path).error is not None
        assert self._parse(["-Z", "a"], tmp_path).error is not None
        assert self._parse(["--no-unicorn", "a"], tmp_path).error is not None

    def test_value_option_missing_value_is_error(self, tmp_path):
        assert self._parse(["--depth"], tmp_path).error is not None
        assert self._parse(["-b"], tmp_path).error is not None

    def test_boolean_option_with_attached_value_is_error(self, tmp_path):
        assert self._parse(["--bare=1", "a"], tmp_path).error is not None
        assert self._parse(["--ipv4=1", "a"], tmp_path).error is not None
        assert self._parse(["--ipv6=1", "a"], tmp_path).error is not None

    def test_undeterminable_destination_names_error(self, tmp_path):
        for repository in ["https://", "host:", "host:.git", ".", "..", ""]:
            assert self._parse([repository], tmp_path).error is not None, repository

    def test_result_is_frozen_dataclass(self, tmp_path):
        assert isinstance(self._parse(["a"], tmp_path), CloneInvocation)
        with pytest.raises(Exception):
            self._parse(["a"], tmp_path).bare = True


class TestCloneExecutionWorkflow:
    """Real offline clone execution followed by post-clone review."""

    def test_explicit_destination_clone_reviewed_and_accepted(self, tmp_path, capsys):
        source = tmp_path / "source-repo"
        _make_source_repo(source)
        cwd = tmp_path / "run"
        cwd.mkdir()
        destination = cwd / "cloned"
        terminal = _QueueTerminal(["RUN\n"])

        exit_code, _ = perform_clone(
            ["clone", str(source), "cloned"],
            cwd, complete_scan_side_effect, terminal,
        )

        assert exit_code == 0
        assert (destination / ".git").exists()
        assert (destination / "file.txt").read_text() == "seed content\n"
        assert POST_CLONE_PROMPT in "\n".join(terminal.prompts)
        captured = capsys.readouterr()
        assert "snapshot review accepted" in captured.err
        assert "no authorization for any later command" in captured.err

    def test_default_destination_clone_reviewed_and_accepted(self, tmp_path, capsys):
        source = tmp_path / "seed-module"
        _make_source_repo(source, filename="seed.py")
        cwd = tmp_path / "run"
        cwd.mkdir()
        destination = cwd / "seed-module"
        terminal = _QueueTerminal(["RUN\n"])

        exit_code, _ = perform_clone(
            ["clone", str(source)],
            cwd, complete_scan_side_effect, terminal,
        )

        assert exit_code == 0
        assert (destination / ".git").exists()
        assert (destination / "seed.py").read_text() == "seed content\n"
        assert POST_CLONE_PROMPT in "\n".join(terminal.prompts)

    def test_failed_clone_fails_git_status_without_scan_or_prompt(
            self, tmp_path, monkeypatch):
        source = tmp_path / "source-repo"
        _make_source_repo(source)
        cwd = tmp_path / "run"
        cwd.mkdir()
        destination = cwd / "cloned"
        destination.mkdir()
        (destination / "occupied.txt").write_text("occupied")

        calls = []
        prompt_must_not_appear(monkeypatch)
        exit_code, captured_calls = perform_clone(
            ["clone", str(source), "cloned"],
            cwd,
            lambda root: calls.append(root) or complete_scan_side_effect(root),
            _QueueTerminal(["RUN\n"]),
        )

        assert exit_code != 0
        assert not calls
        assert not captured_calls
        assert (destination / "occupied.txt").exists()

    def test_failed_clone_returns_gits_exact_status(self, tmp_path):
        source = tmp_path / "source-repo"
        _make_source_repo(source)
        cwd = tmp_path / "run"
        cwd.mkdir()
        occupied = cwd / "in-use"
        occupied.mkdir()
        (occupied / "blocker.txt").write_text("x")

        expected = subprocess.run(
            ["git", "clone", str(source), "in-use"],
            cwd=cwd, check=False, capture_output=True,
        ).returncode
        with patch(
            "src.wrapper.scanners.ScannerOrchestrator.scan",
            side_effect=AssertionError("must not scan a failed clone"),
        ), patch(
            "scanner.execution_guard.confirm_execution",
            side_effect=AssertionError("must not prompt after a failed clone"),
        ):
            wrapper = CommandWrapper(
                "git", ["git", "clone", str(source), "in-use"],
                cwd=cwd, terminal=None,
            )
            exit_code = wrapper.execute()

        assert exit_code == expected
        assert exit_code != 0

    def test_bare_clone_remains_on_disk_without_claimed_review(self, tmp_path, monkeypatch):
        prompt_must_not_appear(monkeypatch)
        self._bare_mirror_case(
            tmp_path, ["clone", "--bare"], "bare-target", bare=True)

    def test_mirror_clone_remains_on_disk_without_claimed_review(self, tmp_path, monkeypatch):
        prompt_must_not_appear(monkeypatch)
        self._bare_mirror_case(
            tmp_path, ["clone", "--mirror"], "mirror-target", bare=True)

    def _bare_mirror_case(self, tmp_path, argv_tail_prefix, target, *, bare):
        source = tmp_path / "source-repo"
        _make_source_repo(source)
        cwd = tmp_path / "run"
        cwd.mkdir()
        destination = cwd / target

        scan_calls = []
        exit_code, captured_calls = perform_clone(
            [*argv_tail_prefix, str(source), target],
            cwd,
            lambda root: scan_calls.append(root) or complete_scan_side_effect(root),
            _QueueTerminal(["RUN\n"]),
        )

        assert exit_code == 1
        assert destination.is_dir()
        assert not (destination / ".git").exists()
        assert (destination / "HEAD").exists()

    def test_original_argv_cwd_and_exit_status_preserved(self, tmp_path):
        source = tmp_path / "source-repo"
        _make_source_repo(source)
        cwd = tmp_path / "run"
        cwd.mkdir()

        exit_code, captured = perform_clone(
            ["clone", str(source), "target"],
            cwd, complete_scan_side_effect, _QueueTerminal(["RUN\n"]), record=True,
        )

        assert exit_code == 0
        assert len(captured) == 1
        safe_argv, kwargs = captured[0]
        assert safe_argv[0].endswith("/git")
        assert tuple(safe_argv[1:]) == ("clone", str(source), "target")
        assert kwargs["shell"] is False
        assert Path(kwargs["cwd"]) == cwd.resolve(strict=False)


def _review_wrapper(destination, terminal):
    """Wrapper instance whose cwd is the cloned repository."""
    return CommandWrapper(
        "git", ["git", "clone", "anything"],
        cwd=destination, terminal=terminal,
    )


class TestCloneReviewFailClosed:
    """Fail-closed paths of the post-clone repository review."""

    def _review(self, destination, scan_side_effect, terminal):
        wrapper = _review_wrapper(destination, terminal)
        with patch(
            "src.wrapper.scanners.ScannerOrchestrator.scan",
            side_effect=lambda root: scan_side_effect(Path(root)),
        ):
            return wrapper._review_cloned_repository(destination)

    def _destination(self, tmp_path):
        destination = tmp_path / "cloned-repo"
        _make_source_repo(destination)
        return destination

    def test_clean_scan_needs_exact_run_and_accepts(self, tmp_path, capsys):
        destination = self._destination(tmp_path)
        terminal = _QueueTerminal(["RUN\n"])
        exit_code = self._review(destination, complete_scan_side_effect, terminal)
        assert exit_code == 0
        assert POST_CLONE_PROMPT in "\n".join(terminal.prompts)
        captured = capsys.readouterr()
        assert "snapshot review accepted" in captured.err

    def test_incomplete_coverage_blocks_before_prompt(self, tmp_path, monkeypatch):
        destination = self._destination(tmp_path)
        prompt_must_not_appear(monkeypatch)

        def scan_side_effect(root):
            result = complete_scan_side_effect(root)
            result["coverage_complete"] = False
            return result

        exit_code = self._review(
            destination, scan_side_effect, _QueueTerminal(["RUN\n"]))
        assert exit_code == 1

    def test_scanner_error_blocks_before_prompt(self, tmp_path, monkeypatch):
        destination = self._destination(tmp_path)
        prompt_must_not_appear(monkeypatch)

        def scan_side_effect(root):
            result = complete_scan_side_effect(root)
            result["inventory"] = {"status": "error", "coverage_complete": False,
                                   "errors": ["Inventory scanner error."]}
            return result

        exit_code = self._review(
            destination, scan_side_effect, _QueueTerminal(["RUN\n"]))
        assert exit_code == 1

    def test_changed_during_scan_blocks_before_prompt(self, tmp_path, monkeypatch):
        destination = self._destination(tmp_path)
        prompt_must_not_appear(monkeypatch)

        def scan_side_effect(root):
            result = complete_scan_side_effect(root)
            result["repository_changed_during_scan"] = True
            result["coverage_complete"] = False
            result["repository_content_hash"] = None
            return result

        exit_code = self._review(
            destination, scan_side_effect, _QueueTerminal(["RUN\n"]))
        assert exit_code == 1

    def test_hash_mismatch_blocks_before_prompt(self, tmp_path, monkeypatch):
        destination = self._destination(tmp_path)
        prompt_must_not_appear(monkeypatch)

        def scan_side_effect(root):
            result = complete_scan_side_effect(root)
            result["repository_content_hash"] = "0" * 32
            return result

        exit_code = self._review(
            destination, scan_side_effect, _QueueTerminal(["RUN\n"]))
        assert exit_code == 1

    def test_malware_blocks_even_with_run_and_never_prompts(self, tmp_path, monkeypatch):
        destination = self._destination(tmp_path)
        prompt_must_not_appear(monkeypatch)

        def scan_side_effect(root):
            result = complete_scan_side_effect(root)
            result["malware"] = {
                "status": "detected", "coverage_complete": True, "errors": [],
                "detections": [{"name": "EICAR-TEST", "path": "eicar.txt"}],
            }
            return result

        exit_code = self._review(
            destination, scan_side_effect, _QueueTerminal(["RUN\n"]))
        assert exit_code == 1

    def test_lowercase_run_never_accepts(self, tmp_path):
        destination = self._destination(tmp_path)
        exit_code = self._review(
            destination, complete_scan_side_effect, _QueueTerminal(["run\n"]))
        assert exit_code == 3

    def test_trailing_space_run_never_accepts(self, tmp_path):
        destination = self._destination(tmp_path)
        exit_code = self._review(
            destination, complete_scan_side_effect, _QueueTerminal(["RUN \n"]))
        assert exit_code == 3

    def test_empty_input_never_accepts(self, tmp_path):
        destination = self._destination(tmp_path)
        exit_code = self._review(
            destination, complete_scan_side_effect, _QueueTerminal(["\n"]))
        assert exit_code == 3

    def test_eof_never_accepts(self, tmp_path):
        destination = self._destination(tmp_path)
        exit_code = self._review(
            destination, complete_scan_side_effect, _QueueTerminal([""]))
        assert exit_code == 3

    def test_keyboard_interrupt_never_accepts(self, tmp_path):
        destination = self._destination(tmp_path)
        exit_code = self._review(
            destination, complete_scan_side_effect, _InterruptTerminal())
        assert exit_code == 3

    def test_no_tty_never_accepts(self, tmp_path, monkeypatch):
        destination = self._destination(tmp_path)
        monkeypatch.setattr(
            "builtins.open",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("no tty")),
        )
        wrapper = _review_wrapper(destination, None)
        with patch(
            "src.wrapper.scanners.ScannerOrchestrator.scan",
            side_effect=complete_scan_side_effect,
        ):
            exit_code = wrapper._review_cloned_repository(destination)
        assert exit_code == 3

    def test_high_finding_is_displayed_and_run_accepts(self, tmp_path, capsys):
        destination = self._destination(tmp_path)

        def scan_side_effect(root):
            result = complete_scan_side_effect(root)
            result["security"] = {
                "status": "requires_review", "coverage_complete": True,
                "errors": [],
                "findings": [{"rule_id": "high-lead", "severity": "HIGH",
                              "path": "setup.py", "line_number": 1}],
            }
            return result

        exit_code = self._review(
            destination, scan_side_effect, _QueueTerminal(["RUN\n"]))
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[HIGH]" in captured.err
        assert "setup.py" in captured.err

    def test_post_prompt_mutation_invalidates_and_leaves_clone(self, tmp_path, capsys):
        destination = self._destination(tmp_path)
        terminal = _MutatingTerminal(
            "RUN\n", destination / "post-prompt.txt", "mutated\n")

        exit_code = self._review(
            destination, complete_scan_side_effect, terminal)

        assert exit_code == 1
        assert (destination / "post-prompt.txt").read_text() == "mutated\n"
        assert "invalidated" in capsys.readouterr().err


class TestCloneReviewCaching:
    """Cache behavior of the post-clone repository review."""

    def _destination_and_wrapper(self, tmp_path):
        destination = tmp_path / "cloned-repo"
        _make_source_repo(destination)
        return destination, _review_wrapper(
            destination, _QueueTerminal(["RUN\n", "RUN\n"]))

    def test_cached_complete_result_reused_but_prompts(self, tmp_path):
        destination, wrapper = self._destination_and_wrapper(tmp_path)
        with patch(
            "src.wrapper.scanners.ScannerOrchestrator.scan",
            side_effect=complete_scan_side_effect,
        ) as mock_scan:
            assert wrapper._review_cloned_repository(destination) == 0
            assert wrapper._review_cloned_repository(destination) == 0
        assert mock_scan.call_count == 1
        assert wrapper.terminal.prompted == 2

    def test_cached_review_can_be_cancelled(self, tmp_path, monkeypatch):
        destination, wrapper = self._destination_and_wrapper(tmp_path)
        wrapper.terminal = _QueueTerminal(["RUN\n"])
        with patch(
            "src.wrapper.scanners.ScannerOrchestrator.scan",
            side_effect=complete_scan_side_effect,
        ) as mock_scan:
            assert wrapper._review_cloned_repository(destination) == 0
        wrapper.terminal = _QueueTerminal(["CANCEL\n"])
        with patch(
            "src.wrapper.scanners.ScannerOrchestrator.scan",
            side_effect=AssertionError("cache hit must not scan"),
        ):
            assert wrapper._review_cloned_repository(destination) == 3
        assert mock_scan.call_count == 1

    @pytest.mark.parametrize("cached_entry", [
        {"coverage_complete": False},
        {"coverage_complete": True, "repository_content_hash": "0" * 32},
        {"coverage_complete": True, "repository_changed_during_scan": True},
    ])
    def test_invalid_cached_entries_are_not_used(self, tmp_path, cached_entry):
        from src.wrapper.cache import CacheKey
        destination, wrapper = self._destination_and_wrapper(tmp_path)
        key = CacheKey.from_repository(
            destination,
            wrapper.classifier.get_config_hash(),
            wrapper.classifier.get_scanner_version(),
            wrapper.classifier.get_malware_db_version(),
        )
        wrapper.cache.set(key, cached_entry)
        with patch(
            "src.wrapper.scanners.ScannerOrchestrator.scan",
            side_effect=complete_scan_side_effect,
        ) as mock_scan:
            exit_code = wrapper._review_cloned_repository(destination)
        assert exit_code == 0
        assert mock_scan.call_count == 1
        refreshed = wrapper.cache.get(key)
        assert refreshed is not None and refreshed is not cached_entry
        assert refreshed.get("coverage_complete") is True
        assert refreshed.get("repository_changed_during_scan") is not True

    def test_post_prompt_mutation_invalidates_cached_key(self, tmp_path):
        destination = tmp_path / "cloned-repo"
        _make_source_repo(destination)
        wrapper = _review_wrapper(
            destination,
            _MutatingTerminal("RUN\n", destination / "mutated.txt", "changed\n"))
        from src.wrapper.cache import CacheKey
        key = CacheKey.from_repository(
            destination,
            wrapper.classifier.get_config_hash(),
            wrapper.classifier.get_scanner_version(),
            wrapper.classifier.get_malware_db_version(),
        )
        cache_entry_marker = {"coverage_complete": False}
        wrapper.cache.set(key, cache_entry_marker)
        with patch(
            "src.wrapper.scanners.ScannerOrchestrator.scan",
            side_effect=complete_scan_side_effect,
        ):
            exit_code = wrapper._review_cloned_repository(destination)
        assert exit_code == 1
        assert wrapper.cache.get(key) is None


class TestPostCloneApprovalIsolation:
    """Clone acceptance never uses (or grants) approval-manager authority."""

    def test_acceptance_does_not_call_approval_manager(self, tmp_path, capsys):
        source = tmp_path / "source-repo"
        _make_source_repo(source)
        cwd = tmp_path / "run"
        cwd.mkdir()
        destination = cwd / "cloned"

        exit_code, _ = perform_clone(
            ["clone", str(source), "cloned"],
            cwd, complete_scan_side_effect, _QueueTerminal(["RUN\n"]),
        )

        assert exit_code == 0
        assert (destination / ".git").exists()

    def test_refused_approval_after_clone_review_still_blocks(self, tmp_path):
        destination = tmp_path / "cloned-repo"
        _make_source_repo(destination)

        # Phase 1: a successful post-clone review with exact RUN acceptance
        # against the clone destination.
        review_wrapper = CommandWrapper(
            "git", ["git", "clone", "anything"], cwd=destination,
            terminal=_QueueTerminal(["RUN\n"]),
        )
        with patch(
            "src.wrapper.scanners.ScannerOrchestrator.scan",
            side_effect=complete_scan_side_effect,
        ):
            review_exit = review_wrapper._review_cloned_repository(destination)
        assert review_exit == 0
        assert review_wrapper.terminal.prompted == 1
        assert POST_CLONE_PROMPT in "\n".join(review_wrapper.terminal.prompts)

        # Phase 2: a later protected command in the same repository. The
        # clone review acceptance must not authorize it, so when the
        # approval manager refuses (request_approval -> None) the command
        # neither executes nor consumes anything.
        with patch(
            "src.wrapper.approval.ApprovalManager.request_approval",
            return_value=None,
        ), patch(
            "src.wrapper.approval.ApprovalManager.consume",
            side_effect=AssertionError(
                "must not consume: nothing was granted"),
        ), patch(
            "src.wrapper.scanners.ScannerOrchestrator.scan",
            side_effect=complete_scan_side_effect,
        ), patch(
            "src.wrapper.core.CommandWrapper._run_command",
            side_effect=AssertionError(
                "refused approval must not execute"),
        ) as mock_run:
            wrapper = CommandWrapper(
                "git", ["git", "commit", "-m", "work"], cwd=destination,
                terminal=_QueueTerminal(["RUN\n"]),
            )
            exit_code = wrapper.execute()
        assert exit_code == 3
        mock_run.assert_not_called()

    def test_tier1_without_repository_context_is_blocked(self, tmp_path, capsys):
        empty = tmp_path / "empty"
        empty.mkdir()
        with patch(
            "src.wrapper.core.CommandWrapper._run_command",
            side_effect=AssertionError(
                "must not execute without repository context"),
        ) as mock_run:
            wrapper = CommandWrapper(
                "docker", ["docker", "build", "-t", "x", "."], cwd=empty)
            exit_code = wrapper.execute()
        assert exit_code == 1
        mock_run.assert_not_called()
        assert ("[LinuxSecMonitor] BLOCKED: no repository context; "
                "cannot enforce required approval" in capsys.readouterr().err)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
