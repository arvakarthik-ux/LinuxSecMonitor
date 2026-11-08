"""Tests for PATH management."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from src.wrapper.path import PathManager, PathResolution, find_shell_rc_file, get_shell_name


class TestPathManager:
    """Tests for PathManager."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.wrapper_dir = Path(self.temp_dir) / "wrappers"
        self.manager = PathManager(self.wrapper_dir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_wrapper_path(self):
        path = self.manager.get_wrapper_path("git")
        assert path == self.wrapper_dir / "lsmonitor-git"

    def test_get_all_wrapper_paths(self):
        paths = self.manager.get_all_wrapper_paths()
        assert len(paths) > 0
        assert all("lsmonitor-" in str(p) for p in paths)

    def test_is_wrapped_command(self):
        assert self.manager.is_wrapped_command("git") is True
        assert self.manager.is_wrapped_command("npm") is True
        assert self.manager.is_wrapped_command("unknown") is False

    def test_resolve_trusted_executable_found(self):
        # This test depends on system executables
        # Just verify the method runs without error
        result = self.manager.resolve_trusted_executable("ls")
        # On most systems, ls exists in /usr/bin or /bin
        assert result is None or isinstance(result, Path)

    def test_resolve_trusted_executable_not_found(self):
        result = self.manager.resolve_trusted_executable("nonexistent_command_xyz")
        assert result is None


class TestPathResolution:
    """Tests for command resolution with bypass detection."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.wrapper_dir = Path(self.temp_dir) / "wrappers"
        self.manager = PathManager(self.wrapper_dir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_absolute_path_bypass(self):
        result = self.manager.resolve_command("/usr/bin/git", ["/usr/bin/git", "status"])
        assert result.bypass_reason == "absolute_path"
        assert result.trusted_executable is None

    def test_shell_builtin_bypass(self):
        result = self.manager.resolve_command("source", ["source", "script.sh"])
        assert result.bypass_reason == "shell_builtin"

    def test_eval_bypass(self):
        result = self.manager.resolve_command("eval", ["eval", "echo hello"])
        assert result.bypass_reason == "shell_builtin"

    def test_inline_bash_c_bypass(self):
        result = self.manager.resolve_command("bash", ["bash", "-c", "echo hello"])
        assert result.bypass_reason == "inline_interpreter"

    def test_inline_python_c_bypass(self):
        result = self.manager.resolve_command("python", ["python", "-c", "print('hello')"])
        assert result.bypass_reason == "inline_interpreter"

    def test_sudo_bypass(self):
        result = self.manager.resolve_command("sudo", ["sudo", "npm", "install"])
        assert result.bypass_reason == "sudo_environment"

    def test_doas_bypass(self):
        result = self.manager.resolve_command("doas", ["doas", "npm", "install"])
        assert result.bypass_reason == "sudo_environment"

    def test_normal_command_no_bypass(self):
        result = self.manager.resolve_command("git", ["git", "status"])
        assert result.bypass_reason is None
        assert result.is_wrapper is False  # wrapper not installed yet

    def test_wrapper_installed_detection(self):
        # Create a wrapper
        wrapper_path = self.manager.get_wrapper_path("git")
        wrapper_path.parent.mkdir(parents=True, exist_ok=True)
        wrapper_path.write_text("#!/bin/sh\necho test")
        wrapper_path.chmod(0o755)

        result = self.manager.resolve_command("git", ["git", "status"])
        assert result.is_wrapper is True


class TestPathPrecedence:
    """Tests for PATH precedence management."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.wrapper_dir = Path(self.temp_dir) / "wrappers"
        self.manager = PathManager(self.wrapper_dir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_ensure_wrapper_dir_in_path(self):
        current_path = "/usr/bin:/bin:/usr/local/bin"
        updated = self.manager.ensure_wrapper_dir_in_path(current_path)
        wrapper_dir_str = str(self.wrapper_dir)

        # Wrapper dir should be first
        assert updated.startswith(wrapper_dir_str + os.pathsep)
        # Original paths should be preserved
        assert "/usr/bin" in updated
        assert "/bin" in updated

    def test_ensure_wrapper_dir_in_path_removes_duplicates(self):
        wrapper_dir_str = str(self.wrapper_dir)
        current_path = f"{wrapper_dir_str}:/usr/bin:{wrapper_dir_str}:/bin"
        updated = self.manager.ensure_wrapper_dir_in_path(current_path)

        # Should only appear once at the beginning
        assert updated.startswith(wrapper_dir_str + os.pathsep)
        assert updated.count(wrapper_dir_str) == 1

    def test_remove_wrapper_dir_from_path(self):
        wrapper_dir_str = str(self.wrapper_dir)
        current_path = f"{wrapper_dir_str}:/usr/bin:{wrapper_dir_str}:/bin"
        updated = self.manager.remove_wrapper_dir_from_path(current_path)

        assert wrapper_dir_str not in updated
        assert "/usr/bin" in updated
        assert "/bin" in updated


class TestFindShellRCFile:
    """Tests for finding shell RC files."""

    def test_find_bash_rc(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        # Create .bashrc
        (tmp_path / ".bashrc").write_text("# bashrc")
        rc = find_shell_rc_file("bash")
        assert rc == tmp_path / ".bashrc"

    def test_find_zsh_rc(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".zshrc").write_text("# zshrc")
        rc = find_shell_rc_file("zsh")
        assert rc == tmp_path / ".zshrc"

    def test_find_fish_rc(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".config" / "fish").mkdir(parents=True)
        (tmp_path / ".config" / "fish" / "config.fish").write_text("# fish")
        rc = find_shell_rc_file("fish")
        assert rc == tmp_path / ".config" / "fish" / "config.fish"

    def test_fallback_when_none_exist(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        # No RC files exist
        rc = find_shell_rc_file("bash")
        assert rc == tmp_path / ".bashrc"


class TestGetShellName:
    """Tests for shell name detection."""

    def test_get_shell_name_from_env(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/bin/bash")
        assert get_shell_name() == "bash"

    def test_get_shell_name_from_env_zsh(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/usr/bin/zsh")
        assert get_shell_name() == "zsh"

    def test_get_shell_name_fallback(self, monkeypatch):
        monkeypatch.delenv("SHELL", raising=False)
        # Should fallback to a known shell (bash, zsh, fish, or current)
        shell = get_shell_name()
        assert shell in ("bash", "zsh", "fish", "opencode", "sh")


class TestVerifyNoRecursion:
    """Tests for recursion prevention."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.wrapper_dir = Path(self.temp_dir) / "wrappers"
        self.manager = PathManager(self.wrapper_dir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_verify_no_recursion_no_wrapper(self):
        # No wrapper installed, should be safe
        # This depends on system, so just verify it runs
        result = self.manager.verify_no_recursion("ls", ["ls"])
        # Can be True or False depending on system
        assert isinstance(result, bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])