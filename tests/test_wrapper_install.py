"""Tests for wrapper installation."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from p4_1_home_rc_guard import guard_primary_home_rc
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

    def test_template_shebang_pins_installer_interpreter(self):
        # Must use the interpreter that ran the installer, never a generic
        # env lookup, so a venv-installed wheel yields a venv shim.
        assert WRAPPER_TEMPLATE.startswith("#!{sys_executable}")

    def test_template_has_no_source_checkout_dependency(self):
        project_root = str(Path(__file__).resolve().parent.parent)
        assert "wrapper_root" not in WRAPPER_TEMPLATE
        assert "sys.path.insert" not in WRAPPER_TEMPLATE
        assert project_root not in WRAPPER_TEMPLATE

    def test_template_fails_closed_with_recovery_path(self):
        assert "return 127" in WRAPPER_TEMPLATE
        assert "never falls back" in WRAPPER_TEMPLATE
        assert "python -m pip install linuxsecmonitor" in WRAPPER_TEMPLATE
        assert "linuxsecmonitor --wrapper-integration uninstall" in WRAPPER_TEMPLATE
        # Startup imports are guarded; a failure must not reach execution.
        assert "except Exception as exc" in WRAPPER_TEMPLATE
        assert WRAPPER_TEMPLATE.index("try:") < WRAPPER_TEMPLATE.index(
            "from src.wrapper.core import CommandWrapper"
        )


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
        assert cleaned == content


class TestInstallConflictsAndLifecycle:
    """Conflict preflight, idempotency, backups, and owned-only uninstall."""

    def setup_method(self):
        import shutil

        self._shutil = shutil
        self.temp_home = tempfile.mkdtemp()
        self.temp_wrapper_dir = Path(self.temp_home) / ".local" / "bin"
        self.config = WrapperConfig(
            wrapper_dir=str(self.temp_wrapper_dir),
            config_dir=str(Path(self.temp_home) / ".config" / "linuxsecmonitor"),
            wrapper_commands=["git"],
            backup_shell_rc=True,
        )
        self.installer = WrapperInstaller(self.config)

    def teardown_method(self):
        self._shutil.rmtree(self.temp_home, ignore_errors=True)

    def _mock_home(self, monkeypatch):
        monkeypatch.setenv("HOME", self.temp_home)
        monkeypatch.setenv("SHELL", "/bin/bash")

    def _install(self, monkeypatch):
        self._mock_home(monkeypatch)
        return self.installer.install("bash", dry_run=False)

    def test_foreign_regular_file_blocks_install_untouched(self, monkeypatch):
        self.temp_wrapper_dir.mkdir(parents=True)
        foreign = self.temp_wrapper_dir / "git"
        foreign.write_text("#!/bin/sh\necho foreign\n")
        bashrc = Path(self.temp_home) / ".bashrc"
        bashrc.write_text("# user\n")

        result = self._install(monkeypatch)

        assert result.success is False
        assert any("git" in error for error in result.errors)
        # Nothing may change on conflict.
        assert foreign.read_text() == "#!/bin/sh\necho foreign\n"
        assert MARKER_START not in bashrc.read_text()
        assert not (self.temp_wrapper_dir / "lsmonitor-git").exists()
        assert not (Path(self.temp_home) / ".bashrc.linuxsecmonitor.bak").exists()

    def test_foreign_symlink_blocks_install_untouched(self, monkeypatch):
        self.temp_wrapper_dir.mkdir(parents=True)
        foreign = self.temp_wrapper_dir / "git"
        foreign.symlink_to("/usr/bin/git")

        result = self._install(monkeypatch)

        assert result.success is False
        assert foreign.is_symlink()
        assert os.readlink(foreign) == "/usr/bin/git"
        assert not (self.temp_wrapper_dir / "lsmonitor-git").exists()

    def test_foreign_shim_file_blocks_install_untouched(self, monkeypatch):
        self.temp_wrapper_dir.mkdir(parents=True)
        foreign = self.temp_wrapper_dir / "lsmonitor-git"
        foreign.write_text(
            "#!/bin/sh\n# LinuxSecMonitor managed wrapper v1\necho foreign shim\n"
        )
        bashrc = Path(self.temp_home) / ".bashrc"
        bashrc.write_text("# user\n")

        result = self._install(monkeypatch)

        assert result.success is False
        assert foreign.read_text() == (
            "#!/bin/sh\n# LinuxSecMonitor managed wrapper v1\necho foreign shim\n"
        )
        assert not (self.temp_wrapper_dir / "git").exists()
        assert bashrc.read_text() == "# user\n"
        assert not (Path(self.temp_home) / ".bashrc.linuxsecmonitor.bak").exists()

    def test_own_previous_shim_link_is_replaceable(self, monkeypatch):
        self.temp_wrapper_dir.mkdir(parents=True)
        old_shim = WRAPPER_TEMPLATE.format(
            command="git", sys_executable=sys.executable,
        )
        (self.temp_wrapper_dir / "lsmonitor-git").write_text(old_shim)
        (self.temp_wrapper_dir / "git").symlink_to("lsmonitor-git")

        result = self._install(monkeypatch)

        assert result.success is True, result.errors
        shim = self.temp_wrapper_dir / "lsmonitor-git"
        assert "old shim" not in shim.read_text()
        assert "CommandWrapper" in shim.read_text()
        link = self.temp_wrapper_dir / "git"
        assert link.is_symlink()
        assert os.readlink(link) == "lsmonitor-git"

    def test_reinstall_is_byte_identical(self, monkeypatch):
        bashrc = Path(self.temp_home) / ".bashrc"
        bashrc.write_text("# user\n")

        first = self._install(monkeypatch)
        assert first.success is True, first.errors

        def snapshot():
            state = {"bashrc": bashrc.read_bytes()}
            for entry in sorted(self.temp_wrapper_dir.iterdir()):
                if entry.is_symlink():
                    state[entry.name] = ("link", os.readlink(entry))
                else:
                    state[entry.name] = ("file", entry.read_bytes())
            return state

        before = snapshot()
        second = self.installer.install("bash", dry_run=False)
        assert second.success is True, second.errors
        assert snapshot() == before

    def test_reinstall_preserves_pristine_backup(self, monkeypatch):
        original = "# original bashrc\n"
        bashrc = Path(self.temp_home) / ".bashrc"
        bashrc.write_text(original)
        backup = Path(self.temp_home) / ".bashrc.linuxsecmonitor.bak"

        assert self._install(monkeypatch).success is True
        assert backup.read_text() == original

        assert self.installer.install("bash", dry_run=False).success is True
        # The pristine backup must never be overwritten with the marked RC.
        assert backup.read_text() == original
        assert MARKER_START in bashrc.read_text()

        self._shutil.copy2(backup, bashrc)
        assert bashrc.read_text() == original

    def test_valid_existing_pristine_backup_is_preserved_on_reinstall(self, monkeypatch):
        self._mock_home(monkeypatch)
        original = "# pre-existing user bashrc\nexport EDITOR=vim\n"
        bashrc = Path(self.temp_home) / ".bashrc"
        backup = Path(self.temp_home) / ".bashrc.linuxsecmonitor.bak"
        bashrc.write_text(original)
        backup.write_text(original)

        first = self.installer.install("bash")
        assert first.success is True, first.errors
        assert first.backed_up_files == []
        assert backup.read_text() == original

        second = self.installer.install("bash")
        assert second.success is True, second.errors
        assert second.backed_up_files == []
        assert backup.read_text() == original

    def test_dangling_backup_symlink_blocks_install(self, monkeypatch):
        self._mock_home(monkeypatch)
        bashrc = Path(self.temp_home) / ".bashrc"
        backup = Path(self.temp_home) / ".bashrc.linuxsecmonitor.bak"
        missing_target = Path(self.temp_home) / "missing-backup-target"
        original = "# user bashrc\n"
        bashrc.write_text(original)
        backup.symlink_to(missing_target)

        result = self.installer.install("bash")

        assert result.success is False
        assert "not a regular file" in " ".join(result.errors)
        assert bashrc.read_text() == original
        assert backup.is_symlink()
        assert not missing_target.exists()

    def test_backup_symlink_to_outside_home_blocks_install(self, monkeypatch):
        self._mock_home(monkeypatch)
        outside_home = Path(tempfile.mkdtemp(prefix="p41-backup-outside-"))
        try:
            target = outside_home / "preserve-me"
            original_target = "# outside data\n"
            target.write_text(original_target)
            bashrc = Path(self.temp_home) / ".bashrc"
            backup = Path(self.temp_home) / ".bashrc.linuxsecmonitor.bak"
            original_rc = "# user bashrc\n"
            bashrc.write_text(original_rc)
            backup.symlink_to(target)

            result = self.installer.install("bash")

            assert result.success is False
            assert "not a regular file" in " ".join(result.errors)
            assert bashrc.read_text() == original_rc
            assert backup.is_symlink()
            assert target.read_text() == original_target
        finally:
            self._shutil.rmtree(outside_home)

    @pytest.mark.parametrize("backup_kind", ["file", "directory"])
    def test_invalid_existing_backup_blocks_install(self, monkeypatch, backup_kind):
        self._mock_home(monkeypatch)
        bashrc = Path(self.temp_home) / ".bashrc"
        backup = Path(self.temp_home) / ".bashrc.linuxsecmonitor.bak"
        original_rc = "# user bashrc\n"
        bashrc.write_text(original_rc)
        if backup_kind == "file":
            backup.write_text("# stale or foreign backup\n")
        else:
            backup.mkdir()

        result = self.installer.install("bash")

        assert result.success is False
        assert "backup" in " ".join(result.errors).lower()
        assert bashrc.read_text() == original_rc
        if backup_kind == "directory":
            assert backup.is_dir()
        else:
            assert backup.read_text() == "# stale or foreign backup\n"

    def test_failed_backup_creation_leaves_rc_unchanged(self, monkeypatch):
        self._mock_home(monkeypatch)
        bashrc = Path(self.temp_home) / ".bashrc"
        backup = Path(self.temp_home) / ".bashrc.linuxsecmonitor.bak"
        original_rc = "# user bashrc\n"
        bashrc.write_text(original_rc)
        real_open = os.open

        def fail_backup_open(path, flags, *args, **kwargs):
            if Path(path) == backup:
                raise PermissionError("fixture denies backup creation")
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr("src.wrapper.install.os.open", fail_backup_open)

        result = self.installer.install("bash")

        assert result.success is False
        assert "fixture denies backup creation" in " ".join(result.errors)
        assert bashrc.read_text() == original_rc
        assert not backup.exists()

    def test_uninstall_removes_only_ours_and_reports_retained(self, monkeypatch):
        assert self._install(monkeypatch).success is True

        foreign = self.temp_wrapper_dir / "git"
        foreign.unlink()
        foreign.write_text("foreign git\n")
        unrelated = self.temp_wrapper_dir / "mytool"
        unrelated.write_text("unrelated\n")

        result = self.installer.uninstall("bash", dry_run=False)

        assert result.success is True, result.errors
        assert not (self.temp_wrapper_dir / "lsmonitor-git").exists()
        assert foreign.read_text() == "foreign git\n"
        assert unrelated.read_text() == "unrelated\n"
        retained = [str(path) for path in result.retained_files]
        assert str(foreign) in retained
        assert str(unrelated) in retained
        assert MARKER_START not in (Path(self.temp_home) / ".bashrc").read_text()
        # Directory survives because foreign entries remain.
        assert self.temp_wrapper_dir.exists()

    def test_uninstall_retains_unverified_shim_and_dangling_link(self, monkeypatch):
        self.temp_wrapper_dir.mkdir(parents=True)
        foreign_shim = self.temp_wrapper_dir / "lsmonitor-git"
        foreign_shim.write_text(
            "#!/bin/sh\n# LinuxSecMonitor managed wrapper v1\n"
            "echo not an LSM shim\n"
        )
        link = self.temp_wrapper_dir / "git"
        link.symlink_to("lsmonitor-git")

        result = self.installer.uninstall("bash", dry_run=False)

        assert result.success is True, result.errors
        assert foreign_shim.read_text().endswith("echo not an LSM shim\n")
        assert link.is_symlink()
        assert str(foreign_shim) in {str(path) for path in result.retained_files}
        assert str(link) in {str(path) for path in result.retained_files}

    def test_malformed_rc_markers_block_install_and_uninstall(self, monkeypatch):
        self._mock_home(monkeypatch)
        bashrc = Path(self.temp_home) / ".bashrc"
        original = f"# user\n{MARKER_START}\nexport PATH=/unsafe\n"
        bashrc.write_text(original)

        install = self.installer.install("bash")
        uninstall = self.installer.uninstall("bash")

        assert install.success is False
        assert uninstall.success is False
        assert bashrc.read_text() == original
        assert not self.temp_wrapper_dir.exists()

    def test_symlinked_rc_is_not_modified(self, monkeypatch):
        self._mock_home(monkeypatch)
        outside = Path(self.temp_home) / "external-profile"
        outside.write_text("# outside user file\n")
        bashrc = Path(self.temp_home) / ".bashrc"
        bashrc.symlink_to(outside)

        result = self.installer.install("bash")

        assert result.success is False
        assert bashrc.is_symlink()
        assert outside.read_text() == "# outside user file\n"
        assert not self.temp_wrapper_dir.exists()

    def test_created_wrapper_dir_is_0755(self, monkeypatch):
        assert self._install(monkeypatch).success is True
        mode = stat.S_IMODE(self.temp_wrapper_dir.stat().st_mode)
        assert mode == 0o755

    def test_preexisting_wrapper_dir_mode_preserved(self, monkeypatch):
        self.temp_wrapper_dir.mkdir(parents=True)
        os.chmod(self.temp_wrapper_dir, 0o700)

        result = self._install(monkeypatch)

        assert result.success is True, result.errors
        mode = stat.S_IMODE(self.temp_wrapper_dir.stat().st_mode)
        assert mode == 0o700


class TestStatusReporting:
    """Extended status(): full field coverage, JSON-serializable, recovery hint."""

    def setup_method(self):
        import shutil

        self._shutil = shutil
        self.temp_home = tempfile.mkdtemp()
        self.temp_wrapper_dir = Path(self.temp_home) / ".local" / "bin"
        self.config = WrapperConfig(
            wrapper_dir=str(self.temp_wrapper_dir),
            config_dir=str(Path(self.temp_home) / ".config" / "linuxsecmonitor"),
            wrapper_commands=["git", "npm"],
            backup_shell_rc=True,
        )
        self.installer = WrapperInstaller(self.config)

    def teardown_method(self):
        self._shutil.rmtree(self.temp_home, ignore_errors=True)

    def _mock_home(self, monkeypatch):
        monkeypatch.setenv("HOME", self.temp_home)
        monkeypatch.setenv("SHELL", "/bin/bash")

    def test_status_reports_all_fields_when_missing(self, monkeypatch):
        self._mock_home(monkeypatch)
        report = self.installer.status("bash")

        required = {
            "shell", "rc_file", "rc_configured", "wrapper_dir",
            "wrapper_dir_exists", "installed_wrappers", "missing_wrappers",
            "total_commands", "wrappers", "shim_status", "path_precedence",
            "git_resolution", "recovery",
        }
        assert required <= set(report)
        json.dumps(report)  # must be JSON-serializable

        assert report["shell"] == "bash"
        assert report["rc_file"] == str(Path(self.temp_home) / ".bashrc")
        assert report["rc_configured"] is False
        assert report["wrapper_dir"] == str(self.temp_wrapper_dir)
        assert report["wrapper_dir_exists"] is False
        assert report["shim_status"] == "missing"
        assert report["missing_wrappers"] == ["git", "npm"]
        assert report["installed_wrappers"] == []
        assert report["total_commands"] == 2
        assert len(report["wrappers"]) == 2
        entry = report["wrappers"][0]
        assert entry["command"] == "git"
        assert entry["shim_path"] == str(self.temp_wrapper_dir / "lsmonitor-git")
        assert entry["shim_present"] is False
        assert entry["shim_state"] == "missing"
        assert entry["path_link"] == str(self.temp_wrapper_dir / "git")
        assert entry["path_link_present"] is False
        assert report["path_precedence"]["in_path"] is False
        assert report["git_resolution"]["via_wrapper"] is False
        assert report["recovery"] is not None
        assert "--wrapper-integration install" in report["recovery"]

    def test_status_installed_with_path_precedence_and_wrapper_git(self, monkeypatch):
        self._mock_home(monkeypatch)
        assert self.installer.install("bash", dry_run=False).success is True

        monkeypatch.setenv(
            "PATH",
            os.pathsep.join([str(self.temp_wrapper_dir), "/usr/bin", "/bin"]),
        )
        report = self.installer.status("bash")

        json.dumps(report)
        assert report["wrapper_dir_exists"] is True
        assert report["shim_status"] == "installed"
        assert report["installed_wrappers"] == ["git", "npm"]
        assert report["missing_wrappers"] == []
        assert report["rc_configured"] is True
        assert report["recovery"] is None
        for entry in report["wrappers"]:
            assert entry["shim_present"] is True
            assert entry["shim_state"] == "installed"
            assert entry["path_link_present"] is True
        assert report["path_precedence"]["index"] == 0
        assert report["path_precedence"]["in_path"] is True
        assert report["path_precedence"]["ahead_of_system_dirs"] is True
        assert report["git_resolution"]["path"] == str(
            self.temp_wrapper_dir / "git"
        )
        assert report["git_resolution"]["via_wrapper"] is True

    def test_status_partial_and_broken_shim_states(self, monkeypatch):
        self._mock_home(monkeypatch)
        assert self.installer.install("bash", dry_run=False).success is True
        (self.temp_wrapper_dir / "lsmonitor-npm").chmod(0o644)

        report = self.installer.status("bash")

        assert report["shim_status"] == "broken"
        states = {e["command"]: e["shim_state"] for e in report["wrappers"]}
        assert states["git"] == "installed"
        assert states["npm"] == "broken"
        assert report["recovery"] is not None

    def test_status_partial_when_only_some_installed(self, monkeypatch):
        self._mock_home(monkeypatch)
        assert self.installer.install("bash", dry_run=False).success is True
        (self.temp_wrapper_dir / "lsmonitor-npm").unlink()

        report = self.installer.status("bash")

        assert report["shim_status"] == "partial"
        states = {e["command"]: e["shim_state"] for e in report["wrappers"]}
        assert states == {"git": "installed", "npm": "missing"}


class TestGeneratedShimFailClosed:
    """A shim whose installed package is broken/missing fails closed."""

    def setup_method(self):
        import shutil

        self._shutil = shutil
        self.temp_home = tempfile.mkdtemp()
        self.temp_wrapper_dir = Path(self.temp_home) / ".local" / "bin"
        self.config = WrapperConfig(
            wrapper_dir=str(self.temp_wrapper_dir),
            config_dir=str(Path(self.temp_home) / ".config" / "linuxsecmonitor"),
            wrapper_commands=["git"],
            backup_shell_rc=False,
        )
        self.installer = WrapperInstaller(self.config)

    def teardown_method(self):
        self._shutil.rmtree(self.temp_home, ignore_errors=True)

    def test_shebang_pins_installer_interpreter(self, monkeypatch):
        monkeypatch.setenv("HOME", self.temp_home)
        monkeypatch.setenv("SHELL", "/bin/bash")
        assert self.installer.install("bash", dry_run=False).success is True
        shim = (self.temp_wrapper_dir / "lsmonitor-git").read_text()
        assert shim.startswith(f"#!{sys.executable}\n")

    def test_broken_package_shim_exits_127_with_recovery(self, monkeypatch):
        monkeypatch.setenv("HOME", self.temp_home)
        monkeypatch.setenv("SHELL", "/bin/bash")
        assert self.installer.install("bash", dry_run=False).success is True
        shim = self.temp_wrapper_dir / "lsmonitor-git"

        # Simulate a broken installed package with a reversible trick: a
        # 'src' package on PYTHONPATH that raises during import. This is
        # deterministic regardless of what is installed in site-packages.
        broken = Path(self.temp_home) / "broken"
        (broken / "src").mkdir(parents=True)
        (broken / "src" / "__init__.py").write_text(
            'raise ImportError("simulated broken package")\n'
        )

        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": self.temp_home,
            "PYTHONPATH": str(broken),
        }
        proc = subprocess.run(
            [str(shim), "--version"],
            capture_output=True,
            text=True,
            env=env,
            cwd=self.temp_home,
            start_new_session=True,
            timeout=30,
        )

        assert proc.returncode == 127, proc
        stderr = proc.stderr
        assert "[LinuxSecMonitor]" in stderr
        assert "simulated broken package" in stderr
        assert "never falls back" in stderr
        assert "python -m pip install linuxsecmonitor" in stderr
        assert "linuxsecmonitor --wrapper-integration uninstall" in stderr
        # The real command must never run.
        assert "git version" not in proc.stdout + stderr
        assert proc.stdout == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])