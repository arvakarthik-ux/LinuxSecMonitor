"""Tests for wrapper installation."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from src.wrapper.install import (
    WrapperInstaller,
    install_wrappers,
    uninstall_wrappers,
    WRAPPER_TEMPLATE,
    BASH_RC_TEMPLATE,
    FISH_RC_TEMPLATE,
    MARKER_START,
    MARKER_END,
)
from src.wrapper.config import WrapperConfig


class TestWrapperTemplate:
    """Tests for wrapper script template."""

    def test_template_has_command_placeholder(self):
        assert "{command}" in WRAPPER_TEMPLATE

    def test_template_imports_command_wrapper(self):
        assert "from src.wrapper.core import CommandWrapper" in WRAPPER_TEMPLATE

    def test_template_executes_wrapper(self):
        assert "wrapper.execute()" in WRAPPER_TEMPLATE


class TestBashRCTemplate:
    """Tests for bash RC template."""

    def test_contains_markers(self):
        assert MARKER_START in BASH_RC_TEMPLATE
        assert MARKER_END in BASH_RC_TEMPLATE

    def test_contains_path_export(self):
        assert "export PATH=" in BASH_RC_TEMPLATE
        assert "{wrapper_dir}" in BASH_RC_TEMPLATE

    def test_contains_hash_refresh(self):
        assert "hash -r" in BASH_RC_TEMPLATE


class TestFishRCTemplate:
    """Tests for fish RC template."""

    def test_contains_markers(self):
        assert MARKER_START in FISH_RC_TEMPLATE
        assert MARKER_END in FISH_RC_TEMPLATE

    def test_contains_path_set(self):
        assert "set -gx PATH" in FISH_RC_TEMPLATE
        assert "{wrapper_dir}" in FISH_RC_TEMPLATE


class TestWrapperInstaller:
    """Tests for WrapperInstaller."""

    def setup_method(self):
        self.temp_home = tempfile.mkdtemp()
        self.temp_wrapper_dir = Path(self.temp_home) / ".local" / "bin"

        # Create minimal config
        self.config = WrapperConfig(
            wrapper_dir=str(self.temp_wrapper_dir),
            config_dir=str(Path(self.temp_home) / ".config" / "linuxsecmonitor"),
            wrapper_commands=["git", "npm", "python"],
            backup_shell_rc=True,
        )

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_home, ignore_errors=True)

    def _mock_home(self, monkeypatch):
        monkeypatch.setenv("HOME", self.temp_home)
        monkeypatch.setenv("SHELL", "/bin/bash")

    def test_install_bash_dry_run(self, monkeypatch):
        self._mock_home(monkeypatch)
        installer = WrapperInstaller(self.config)

        result = installer.install("bash", dry_run=True)

        assert result.success is True
        assert "dry run" in result.message
        # No files should be created in dry run
        assert not self.temp_wrapper_dir.exists()

    def test_install_bash_creates_wrappers(self, monkeypatch):
        self._mock_home(monkeypatch)
        installer = WrapperInstaller(self.config)

        result = installer.install("bash", dry_run=False)

        assert result.success is True
        assert self.temp_wrapper_dir.exists()
        assert (self.temp_wrapper_dir / "lsmonitor-git").exists()
        assert (self.temp_wrapper_dir / "lsmonitor-npm").exists()
        assert (self.temp_wrapper_dir / "lsmonitor-python").exists()

        # Check wrapper content
        git_wrapper = (self.temp_wrapper_dir / "lsmonitor-git").read_text()
        assert "CommandWrapper" in git_wrapper
        assert "git" in git_wrapper

    def test_install_bash_updates_bashrc(self, monkeypatch):
        self._mock_home(monkeypatch)
        # Create .bashrc
        bashrc = Path(self.temp_home) / ".bashrc"
        bashrc.write_text("# existing bashrc\n")

        installer = WrapperInstaller(self.config)
        result = installer.install("bash", dry_run=False)

        assert result.success is True
        content = bashrc.read_text()
        assert MARKER_START in content
        assert MARKER_END in content
        assert str(self.temp_wrapper_dir) in content
        assert "hash -r" in content

    def test_install_zsh_creates_wrappers(self, monkeypatch):
        self._mock_home(monkeypatch)
        installer = WrapperInstaller(self.config)

        result = installer.install("zsh", dry_run=False)

        assert result.success is True
        assert self.temp_wrapper_dir.exists()
        zshrc = Path(self.temp_home) / ".zshrc"
        assert zshrc.exists()
        content = zshrc.read_text()
        assert MARKER_START in content
        assert str(self.temp_wrapper_dir) in content

    def test_install_fish_creates_wrappers(self, monkeypatch):
        self._mock_home(monkeypatch)
        installer = WrapperInstaller(self.config)

        result = installer.install("fish", dry_run=False)

        assert result.success is True
        fish_config = Path(self.temp_home) / ".config" / "fish" / "config.fish"
        assert fish_config.exists()
        content = fish_config.read_text()
        assert MARKER_START in content
        assert str(self.temp_wrapper_dir) in content
        assert "set -gx PATH" in content

    def test_install_idempotent(self, monkeypatch):
        self._mock_home(monkeypatch)
        installer = WrapperInstaller(self.config)

        result1 = installer.install("bash", dry_run=False)
        assert result1.success is True

        result2 = installer.install("bash", dry_run=False)
        assert result2.success is True

        # Should not duplicate RC entries
        bashrc = Path(self.temp_home) / ".bashrc"
        content = bashrc.read_text()
        assert content.count(MARKER_START) == 1
        assert content.count(MARKER_END) == 1

    def test_install_backup_created(self, monkeypatch):
        self._mock_home(monkeypatch)
        bashrc = Path(self.temp_home) / ".bashrc"
        bashrc.write_text("# original bashrc\n")

        installer = WrapperInstaller(self.config)
        result = installer.install("bash", dry_run=False)

        assert result.success is True
        # Check backup was created
        backup_files = list(Path(self.temp_home).glob(".bashrc*.bak"))
        assert len(backup_files) == 1
        assert backup_files[0].read_text() == "# original bashrc\n"

    def test_uninstall_removes_wrappers(self, monkeypatch):
        self._mock_home(monkeypatch)
        installer = WrapperInstaller(self.config)

        # Install first
        installer.install("bash", dry_run=False)
        assert (self.temp_wrapper_dir / "lsmonitor-git").exists()

        # Uninstall
        result = installer.uninstall("bash", dry_run=False)

        assert result.success is True
        assert not (self.temp_wrapper_dir / "lsmonitor-git").exists()
        assert not (self.temp_wrapper_dir / "lsmonitor-npm").exists()
        assert not (self.temp_wrapper_dir / "lsmonitor-python").exists()

    def test_uninstall_removes_rc_config(self, monkeypatch):
        self._mock_home(monkeypatch)
        installer = WrapperInstaller(self.config)

        # Install first
        installer.install("bash", dry_run=False)
        bashrc = Path(self.temp_home) / ".bashrc"
        assert MARKER_START in bashrc.read_text()

        # Uninstall
        result = installer.uninstall("bash", dry_run=False)

        assert result.success is True
        content = bashrc.read_text()
        assert MARKER_START not in content
        assert MARKER_END not in content

    def test_uninstall_preserves_other_content(self, monkeypatch):
        self._mock_home(monkeypatch)
        bashrc = Path(self.temp_home) / ".bashrc"
        bashrc.write_text("# user config\nexport EDITOR=vim\n")

        installer = WrapperInstaller(self.config)
        installer.install("bash", dry_run=False)
        installer.uninstall("bash", dry_run=False)

        content = bashrc.read_text()
        assert "# user config" in content
        assert "export EDITOR=vim" in content

    def test_uninstall_all_shells(self, monkeypatch):
        self._mock_home(monkeypatch)
        installer = WrapperInstaller(self.config)

        # Install for all
        installer.install_all_shells(dry_run=False)

        # Uninstall all
        results = installer.uninstall_all_shells(dry_run=False)

        assert all(r.success for r in results.values())
        # All wrappers should be gone
        assert not list(self.temp_wrapper_dir.glob("lsmonitor-*"))

    def test_status_reports_correctly(self, monkeypatch):
        self._mock_home(monkeypatch)
        installer = WrapperInstaller(self.config)

        # Before install
        status = installer.status("bash")
        assert status["installed_wrappers"] == []
        assert status["missing_wrappers"] == ["git", "npm", "python"]
        assert status["rc_configured"] is False

        # After install
        installer.install("bash", dry_run=False)
        status = installer.status("bash")
        assert set(status["installed_wrappers"]) == {"git", "npm", "python"}
        assert status["missing_wrappers"] == []
        assert status["rc_configured"] is True

    def test_install_unsupported_shell(self, monkeypatch):
        self._mock_home(monkeypatch)
        installer = WrapperInstaller(self.config)

        result = installer.install("csh", dry_run=False)
        assert result.success is False
        assert "Unsupported shell" in result.message


class TestInstallAllShells:
    """Tests for installing all supported shells."""

    def setup_method(self):
        self.temp_home = tempfile.mkdtemp()
        self.temp_wrapper_dir = Path(self.temp_home) / ".local" / "bin"

        self.config = WrapperConfig(
            wrapper_dir=str(self.temp_wrapper_dir),
            wrapper_commands=["git"],
        )

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_home, ignore_errors=True)

    def _mock_home(self, monkeypatch):
        monkeypatch.setenv("HOME", self.temp_home)
        monkeypatch.setenv("SHELL", "/bin/bash")

    def test_install_all_shells(self, monkeypatch):
        self._mock_home(monkeypatch)
        installer = WrapperInstaller(self.config)

        results = installer.install_all_shells(dry_run=False)

        assert "bash" in results
        assert "zsh" in results
        assert "fish" in results
        assert all(r.success for r in results.values())

        # Check all RC files have config
        assert (Path(self.temp_home) / ".bashrc").exists()
        assert (Path(self.temp_home) / ".zshrc").exists()
        assert (Path(self.temp_home) / ".config" / "fish" / "config.fish").exists()


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def setup_method(self):
        self.temp_home = tempfile.mkdtemp()
        self.temp_wrapper_dir = Path(self.temp_home) / ".local" / "bin"

        self.config = WrapperConfig(
            wrapper_dir=str(self.temp_wrapper_dir),
            wrapper_commands=["git"],
        )

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_home, ignore_errors=True)

    def _mock_home(self, monkeypatch):
        monkeypatch.setenv("HOME", self.temp_home)
        monkeypatch.setenv("SHELL", "/bin/bash")

    def test_install_wrappers_function(self, monkeypatch):
        self._mock_home(monkeypatch)
        result = install_wrappers("bash", config=self.config)
        assert result.success is True
        assert (self.temp_wrapper_dir / "lsmonitor-git").exists()

    def test_uninstall_wrappers_function(self, monkeypatch):
        self._mock_home(monkeypatch)
        install_wrappers("bash", config=self.config)
        result = uninstall_wrappers("bash", config=self.config)
        assert result.success is True
        assert not (self.temp_wrapper_dir / "lsmonitor-git").exists()


class TestRemoveMarkerSection:
    """Tests for removing marker sections from RC files."""

    def setup_method(self):
        self.temp_home = tempfile.mkdtemp()
        self.temp_wrapper_dir = Path(self.temp_home) / ".local" / "bin"
        self.config = WrapperConfig(wrapper_dir=str(self.temp_wrapper_dir))
        self.installer = WrapperInstaller(self.config)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_home, ignore_errors=True)

    def test_removes_marker_section(self):
        content = """# user config
export PATH=/usr/bin
# >>> linuxsecmonitor wrapper >>>
export PATH="/home/user/.local/bin:$PATH"
hash -r
# <<< linuxsecmonitor wrapper <<<
# more user config
"""
        cleaned = self.installer._remove_marker_section(content)
        assert MARKER_START not in cleaned
        assert MARKER_END not in cleaned
        assert "export PATH=/usr/bin" in cleaned
        assert "# more user config" in cleaned
        assert "/home/user/.local/bin" not in cleaned

    def test_handles_no_markers(self):
        content = "# just user config\nexport PATH=/usr/bin\n"
        cleaned = self.installer._remove_marker_section(content)
        assert cleaned == content

    def test_handles_partial_markers(self):
        content = """# >>> linuxsecmonitor wrapper >>>
export PATH="/home/user/.local/bin:$PATH"
# missing end marker
"""
        cleaned = self.installer._remove_marker_section(content)
        # Should remove from start marker to end
        assert MARKER_START not in cleaned
        assert "/home/user/.local/bin" not in cleaned


if __name__ == "__main__":
    pytest.main([__file__, "-v"])