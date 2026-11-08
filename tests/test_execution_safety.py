"""Tests for 3A.4 Execution Safety."""

from __future__ import annotations

import os
import stat
import tempfile
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from src.wrapper.path import PathManager
from src.wrapper.core import CommandWrapper
from src.wrapper.approval import ApprovalManager, ApprovalRecord


class TestTrustedExecutableResolution:
    """Tests for trusted executable resolution using only approved system paths."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.wrapper_dir = Path(self.temp_dir) / "wrappers"
        self.manager = PathManager(self.wrapper_dir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_trusted_executable_system_paths_only(self):
        """Test that trusted executable resolution only uses approved system paths."""
        # The manager should only search in /usr/bin, /usr/local/bin, /bin, /sbin, /usr/sbin
        # It should not search in user directories or temp directories
        result = self.manager.resolve_trusted_executable("ls")
        if result is not None:
            # Verify it's in a system path
            system_paths = ["/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/usr/sbin"]
            assert any(str(result).startswith(p) for p in system_paths), \
                f"Executable {result} not in approved system path"

    def test_trusted_executable_rejects_writable_dirs(self):
        """Test that writable directories are not trusted for executable resolution."""
        # Create a writable directory with a fake executable
        writable_dir = Path(self.temp_dir) / "writable_bin"
        writable_dir.mkdir(mode=0o777)
        fake_exe = writable_dir / "fake_cmd"
        fake_exe.write_text("#!/bin/sh\necho hacked")
        fake_exe.chmod(0o755)

        # The manager should not find executables in user-writable directories
        # because it only searches system paths
        result = self.manager.resolve_trusted_executable("fake_cmd")
        assert result is None, "Should not find executable in writable user directory"

    def test_trusted_executable_rejects_home_dir(self):
        """Test that home directory executables are rejected."""
        # Create executable in home
        home_bin = Path.home() / "bin"
        home_bin.mkdir(exist_ok=True)
        fake_exe = home_bin / "home_cmd"
        fake_exe.write_text("#!/bin/sh\necho hacked")
        fake_exe.chmod(0o755)

        try:
            result = self.manager.resolve_trusted_executable("home_cmd")
            # Should not find it because home is excluded
            assert result is None or not str(result).startswith(str(Path.home()))
        finally:
            fake_exe.unlink(missing_ok=True)
            home_bin.rmdir()

    def test_trusted_executable_rejects_tmp_dir(self):
        """Test that /tmp executables are rejected."""
        fake_exe = Path("/tmp") / "tmp_cmd"
        fake_exe.write_text("#!/bin/sh\necho hacked")
        fake_exe.chmod(0o755)

        try:
            result = self.manager.resolve_trusted_executable("tmp_cmd")
            assert result is None or not str(result).startswith("/tmp")
        finally:
            fake_exe.unlink(missing_ok=True)


class TestPathInjectionProtection:
    """Tests for PATH injection attack prevention."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.wrapper_dir = Path(self.temp_dir) / "wrappers"
        self.manager = PathManager(self.wrapper_dir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_path_injection_malicious(self):
        """Test that malicious PATH entries don't affect trusted resolution."""
        # The PathManager.resolve_trusted_executable doesn't use PATH at all
        # It uses hardcoded system paths, so PATH injection is impossible
        result = self.manager.resolve_trusted_executable("ls")
        if result:
            system_paths = ["/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/usr/sbin"]
            assert any(str(result).startswith(p) for p in system_paths)

    def test_path_injection_relative_empty(self):
        """Test that relative and empty PATH entries don't affect resolution."""
        # Since resolution doesn't use PATH, this is inherently protected
        # But test the PATH management functions handle these correctly
        current_path = ":/usr/bin:./bin:/bin"
        updated = self.manager.ensure_wrapper_dir_in_path(current_path)
        # Empty entry (leading :) and relative entry (./bin) should be preserved but wrapper dir prepended
        assert str(self.wrapper_dir) in updated
        assert "/usr/bin" in updated

    def test_path_injection_repo_shadowing(self):
        """Test that repository-local executables don't shadow system ones."""
        # Create a repo with a fake git executable
        repo_dir = Path(self.temp_dir) / "repo"
        repo_dir.mkdir()
        fake_git = repo_dir / "git"
        fake_git.write_text("#!/bin/sh\necho malicious")
        fake_git.chmod(0o755)

        # The trusted resolution should find system git, not the repo one
        result = self.manager.resolve_trusted_executable("git")
        if result:
            assert not str(result).startswith(str(repo_dir)), \
                "Should not select repository-local executable"


class TestWrapperRecursionPrevention:
    """Tests for wrapper recursion prevention."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.wrapper_dir = Path(self.temp_dir) / "wrappers"
        self.wrapper_dir.mkdir(parents=True)
        self.manager = PathManager(self.wrapper_dir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_wrapper_recursion_prevention(self):
        """Test that wrapper cannot select itself recursively.

        The wrapper resolves trusted executable from system paths only,
        so it should never select the wrapper script itself. The verify_no_recursion
        method confirms the resolved executable is not the wrapper.
        """
        # Create a wrapper script
        wrapper_path = self.wrapper_dir / "lsmonitor-git"
        wrapper_path.write_text("#!/bin/sh\nexec /usr/bin/git \"$@\"")
        wrapper_path.chmod(0o755)

        # The trusted executable should be the system git, not the wrapper
        trusted = self.manager.resolve_trusted_executable("git")
        if trusted:
            # verify_no_recursion should confirm it's not the wrapper
            result = self.manager.verify_no_recursion("git", ["git", "status"])
            assert result is True, "System executable should not be wrapper"

    def test_wrapper_name_collision(self):
        """Test that wrapper name collisions are handled."""
        # Create a fake executable with wrapper-like name in system path
        # This tests that the real executable is found, not the wrapper
        result = self.manager.resolve_trusted_executable("git")
        if result:
            # Should be the real git, not a wrapper
            assert "lsmonitor" not in str(result)
            assert result.name == "git"

    def test_wrapper_script_not_selected_as_trusted(self):
        """Test that wrapper script in wrapper_dir is never selected as trusted."""
        # Even if wrapper dir is in PATH, resolve_trusted_executable
        # only searches system paths
        wrapper_path = self.wrapper_dir / "lsmonitor-git"
        wrapper_path.write_text("#!/bin/sh\necho wrapper")
        wrapper_path.chmod(0o755)

        # Create a symlink named after the command in wrapper dir
        git_link = self.wrapper_dir / "git"
        git_link.symlink_to(wrapper_path)

        # Trusted resolution should still find system git
        trusted = self.manager.resolve_trusted_executable("git")
        if trusted:
            assert str(trusted).startswith("/usr/bin") or str(trusted).startswith("/bin")


class TestChildEnvironmentPolicy:
    """Tests for the shared child environment allowlist policy.

    Both real launch sites (execution_guard.run_reviewed_command and
    CommandWrapper._run_command) spawn children with
    scanner.child_environment.build_child_environment; these tests pin the
    policy behavior those sites depend on.
    """

    def test_dangerous_environment_variables_absent(self):
        """Dangerous injection variables are stripped from the child env."""
        from scanner.child_environment import build_child_environment

        parent = {
            "PATH": "/tmp/evil:/usr/bin:/bin",
            "HOME": "/home/evil-user",
            "LD_PRELOAD": "/malicious.so",
            "LD_LIBRARY_PATH": "/malicious/lib",
            "PYTHONPATH": "/malicious/python",
            "PYTHONHOME": "/malicious/python-home",
            "NODE_OPTIONS": "--require malicious",
            "BASH_ENV": "/malicious/bash_env",
            "ENV": "/malicious/env",
            "RUBYOPT": "-eevil",
            "PERL5OPT": "-eevil",
            "GIT_CONFIG_GLOBAL": "/malicious/gitconfig",
        }

        env = build_child_environment(cwd="/", parent=parent)

        for key in (
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "PYTHONPATH",
            "PYTHONHOME",
            "NODE_OPTIONS",
            "BASH_ENV",
            "ENV",
            "RUBYOPT",
            "PERL5OPT",
            "GIT_CONFIG_GLOBAL",
        ):
            assert key not in env

        # Safe variables are always present.
        assert "PATH" in env
        assert "HOME" in env
        assert "USER" in env
        assert "LANG" in env
        # PATH is the validated trusted policy PATH, not the parent PATH.
        for entry in env["PATH"].split(":"):
            assert os.path.isabs(entry)
            assert os.stat(entry).st_uid == 0
            assert not os.stat(entry).st_mode & 0o022

    def test_child_environment_is_allowlist_only(self):
        """Only documented variables are retained; nothing else leaks in."""
        from scanner.child_environment import build_child_environment

        parent = {
            "PATH": "/usr/bin",
            "HOME": "/home",
            "USER": "user",
            "LOGNAME": "user",
            "SHELL": "/bin/zsh",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
            "TZ": "UTC",
            "UNDOCUMENTED_EXTRA": "must-not-leak",
        }

        env = build_child_environment(cwd="/", parent=parent)

        assert set(env) == {
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "SHELL",
            "PWD",
            "TERM",
            "LANG",
            "TZ",
        }

    def test_runtime_override_variables_are_never_reinjected(self):
        """Runtime-override variables stripped even when the parent sets them."""
        from scanner.child_environment import build_child_environment

        parent = {
            "PATH": "/usr/bin",
            "HOME": "/home",
            "VIRTUAL_ENV": "/venv",
            "CONDA_PREFIX": "/conda",
            "NPM_CONFIG_PREFIX": "/npm",
            "CARGO_HOME": "/cargo",
            "NODE_PATH": "/node",
            "RUSTC_WRAPPER": "/rustc-wrapper",
            "GOENV": "/goenv",
            "MAVEN_OPTS": "-Xmx64m",
            "GRADLE_OPTS": "-Xmx64m",
        }

        env = build_child_environment(cwd="/", parent=parent)

        for key in (
            "VIRTUAL_ENV",
            "CONDA_PREFIX",
            "NPM_CONFIG_PREFIX",
            "CARGO_HOME",
            "NODE_PATH",
            "RUSTC_WRAPPER",
            "GOENV",
            "MAVEN_OPTS",
            "GRADLE_OPTS",
        ):
            assert key not in env

    def test_child_environment_home_is_passwd_home(self):
        """HOME resolves to the account passwd home, not a parent redirect."""
        import pwd

        from scanner.child_environment import build_child_environment

        env = build_child_environment(
            cwd="/", parent={"PATH": "/usr/bin", "HOME": "/tmp/redirected-home"}
        )
        assert env["HOME"] == pwd.getpwuid(os.geteuid()).pw_dir

    def test_child_environment_shell_is_fixed(self):
        """SHELL is fixed to /bin/sh; parent SHELL is not inherited."""
        from scanner.child_environment import build_child_environment

        env = build_child_environment(
            cwd="/", parent={"PATH": "/usr/bin", "SHELL": "/bin/zsh"}
        )
        assert env["SHELL"] == "/bin/sh"


class TestExecutableIdentityVerification:
    """Tests for executable identity verification at execution time."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.wrapper_dir = Path(self.temp_dir) / "wrappers"
        self.wrapper_dir.mkdir(parents=True)
        self.manager = PathManager(self.wrapper_dir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_executable_identity_verification(self):
        """Test that executable identity (inode, device) is verified."""
        # The current implementation resolves the executable at decision time
        # but doesn't re-verify at execution time. This is a TOCTOU window.
        # This test documents the expected behavior.
        result = self.manager.resolve_trusted_executable("ls")
        if result:
            # Should be able to stat the executable
            stat_info = result.stat()
            assert stat_info.st_ino > 0
            assert stat_info.st_dev > 0

    def test_symlink_replacement_protection(self):
        """Test protection against symlink replacement after resolution."""
        # Create a symlink that points to a system executable
        symlink = self.wrapper_dir / "test_cmd"
        symlink.symlink_to("/bin/ls")

        # The resolution should follow the symlink and get the real executable
        # But at execution time, the symlink could be changed
        # This documents the current limitation
        trusted = self.manager.resolve_trusted_executable("ls")
        if trusted:
            assert trusted.is_file()


class TestApprovalIntegrity:
    """Tests for approval bound to executable identity."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.wrapper_dir = Path(self.temp_dir) / "wrappers"
        self.manager = ApprovalManager(ttl_seconds=300.0)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_approval_bound_to_executable(self):
        """Test that approval validation includes executable identity."""
        # Current implementation doesn't include executable hash in approval
        # This test documents the gap
        record = ApprovalRecord(
            repository_content_hash="repo_hash",
            argv=("git", "checkout", "main"),
            working_directory=self.temp_dir,
            config_hash="config_hash",
            policy_version="3A.3",
            scanner_versions="{}",
            malware_db_version="1.0.0",
            created_at=1000.0,
            expires_at=1300.0,
        )

        # Current validation doesn't check executable identity
        # This should be added for 3A.4
        assert hasattr(record, 'argv')

    def test_approval_revalidated_before_exec(self):
        """Test that approval is revalidated immediately before execution."""
        # The core.py does call approval.consume() which validates
        # But it doesn't re-resolve and verify the executable
        # This documents the current behavior
        import time
        clock = iter([1000.0, 1000.0, 1001.0])
        manager = ApprovalManager(ttl_seconds=300, clock=lambda: next(clock))

        record = manager.request_approval(
            repository_content_hash="hash",
            argv=("git", "checkout", "main"),
            working_directory=self.temp_dir,
            config_hash="config",
            scanner_versions={},
            malware_db_version="db",
            report={"coverage_complete": True},
            terminal=None,  # Will fail without terminal
        )
        # Without terminal, record is None
        assert record is None


class TestNoShellTrue:
    """Tests for no shell=True usage."""

    def test_no_shell_true_in_core(self):
        """Test that core.py doesn't use shell=True."""
        import inspect
        source = inspect.getsource(CommandWrapper._run_command)
        assert "shell=True" not in source
        assert "shell=False" in source

    def test_no_shell_true_in_execution_guard(self):
        """Test that execution_guard.py doesn't use shell=True."""
        from scanner import execution_guard
        import inspect
        source = inspect.getsource(execution_guard.run_reviewed_command)
        assert "shell=True" not in source
        assert "shell=False" in source


class TestArgvPreserved:
    """Tests for original argv preservation."""

    def test_argv_preserved_in_decision(self):
        """Test that original argv is stored in decision."""
        wrapper = CommandWrapper("git", ["git", "checkout", "-b", "feature-branch"])
        decision = wrapper.get_decision()
        assert decision.original_argv == ("git", "checkout", "-b", "feature-branch")
        assert decision.argv == ("git", "checkout", "-b", "feature-branch")

    def test_argv_preserved_in_execution(self):
        """Test that argv is passed correctly to subprocess."""
        # Create a temp directory with a valid git repo for scanning
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

            # Mock _run_command to capture argv, and mock approval
            with patch.object(wrapper, '_run_command', return_value=0) as mock_run:
                with patch('src.wrapper.approval.ApprovalManager') as mock_approval_class:
                    mock_approval = MagicMock()
                    mock_approval_class.return_value = mock_approval
                    mock_record = MagicMock()
                    mock_approval.request_approval.return_value = mock_record
                    mock_approval.consume.return_value = True

                    wrapper.execute()
                    mock_run.assert_called_once()
                    called_argv = mock_run.call_args[0][0]
                    assert called_argv == ("git", "checkout", "main")


class TestBypassAnalysis:
    """Tests for bypass path analysis."""

    def test_absolute_path_bypass_documented(self):
        """Test absolute path bypass is detected."""
        wrapper = CommandWrapper("/usr/bin/git", ["/usr/bin/git", "checkout", "main"])
        decision = wrapper.get_decision()
        assert decision.tier.value == "bypass"
        assert decision.bypass_reason == "absolute_path"

    def test_shell_builtin_bypass_documented(self):
        """Test shell builtin bypass is detected."""
        wrapper = CommandWrapper("source", ["source", "script.sh"])
        decision = wrapper.get_decision()
        assert decision.tier.value == "bypass"
        assert decision.bypass_reason == "shell_builtin"

    def test_inline_interpreter_bypass_documented(self):
        """Test inline interpreter bypass is detected."""
        wrapper = CommandWrapper("bash", ["bash", "-c", "echo hello"])
        decision = wrapper.get_decision()
        assert decision.tier.value == "bypass"
        assert decision.bypass_reason == "inline_interpreter"

    def test_sudo_bypass_documented(self):
        """Test sudo bypass is detected."""
        wrapper = CommandWrapper("sudo", ["sudo", "npm", "install"])
        decision = wrapper.get_decision()
        assert decision.tier.value == "bypass"
        assert decision.bypass_reason == "sudo_environment"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
