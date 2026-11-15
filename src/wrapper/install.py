"""Shell integration for wrapper installation and uninstallation."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import WrapperConfig
from .path import PathManager, find_shell_rc_file, get_shell_name


@dataclass
class InstallResult:
    """Result of an installation or uninstallation operation."""

    success: bool
    message: str
    modified_files: list[Path] = None
    backed_up_files: list[Path] = None
    errors: list[str] = None

    def __post_init__(self):
        if self.modified_files is None:
            self.modified_files = []
        if self.backed_up_files is None:
            self.backed_up_files = []
        if self.errors is None:
            self.errors = []


# Wrapper script template
WRAPPER_TEMPLATE = '''#!{sys_executable}
# LinuxSecMonitor managed wrapper v1
"""LinuxSecMonitor wrapper for {command}."""

import sys
from pathlib import Path

_RECOVERY = (
    "Recovery: reinstall with 'python -m pip install linuxsecmonitor' or "
    "remove the wrappers with 'linuxsecmonitor --wrapper-integration uninstall'."
)


def _fail(reason: str) -> int:
    print(
        "[LinuxSecMonitor] the {command} wrapper could not start: "
        + reason
        + "\\nThis is the LinuxSecMonitor command wrapper; it never falls back "
        "to executing the unwrapped command.\\n"
        + _RECOVERY,
        file=sys.stderr,
    )
    return 127


def main():
    try:
        from src.wrapper.core import CommandWrapper
        from src.wrapper.path import PathManager

        # Derive the wrapper directory from this script's own location so no
        # checkout path is ever baked into the generated shim.
        script_path = Path(__file__).resolve()
        script_name = script_path.name
        if script_name.startswith("lsmonitor-"):
            command = script_name[10:]  # Remove "lsmonitor-" prefix
        else:
            command = script_name  # Fallback: basename (symlink name)

        argv = [command] + sys.argv[1:]
        path_manager = PathManager(script_path.parent)
        wrapper = CommandWrapper(command, argv, path_manager=path_manager)
        return wrapper.execute()
    except Exception as exc:
        return _fail(type(exc).__name__ + ": " + str(exc))


if __name__ == "__main__":
    sys.exit(main())
'''

# Shell RC configuration markers
MARKER_START = "# >>> linuxsecmonitor wrapper >>>"
MARKER_END = "# <<< linuxsecmonitor wrapper <<<"

# Bash/Zsh RC template
BASH_RC_TEMPLATE = f"""{MARKER_START}
# LinuxSecMonitor wrapper configuration
export PATH="{'{wrapper_dir}'}:$PATH"
# Refresh command hash to pick up wrappers
hash -r 2>/dev/null || true
{MARKER_END}
"""

# Fish RC template
FISH_RC_TEMPLATE = f"""{MARKER_START}
# LinuxSecMonitor wrapper configuration
set -gx PATH {'{wrapper_dir}'} $PATH
{MARKER_END}
"""


class WrapperInstaller:
    """Handles wrapper installation and uninstallation for shells."""

    def __init__(self, config: Optional[WrapperConfig] = None):
        """
        Initialize the installer.

        Args:
            config: Wrapper configuration (uses defaults if None)
        """
        self.config = config or WrapperConfig()
        self.path_manager = PathManager(Path(self.config.wrapper_dir))
        self.wrapper_dir = Path(self.config.wrapper_dir).expanduser()

    def install(
        self,
        shell: Optional[str] = None,
        dry_run: bool = False,
        user: bool = True,
    ) -> InstallResult:
        """
        Install wrappers for a shell.

        Args:
            shell: Shell to install for (bash, zsh, fish). Auto-detected if None.
            dry_run: If True, only report what would be done
            user: If True, install for current user (per-user installation)

        Returns:
            InstallResult with operation details
        """
        if shell is None:
            shell = get_shell_name()

        shell = shell.lower()
        if shell not in ("bash", "zsh", "fish"):
            return InstallResult(
                success=False,
                message=f"Unsupported shell: {shell}",
                errors=[f"Supported shells: bash, zsh, fish"],
            )

        result = InstallResult(success=True, message=f"Installing for {shell}")

        # Create wrapper directory
        if not dry_run:
            self.wrapper_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.wrapper_dir, 0o755)
        result.modified_files.append(self.wrapper_dir)

        # Install wrapper scripts
        wrapper_errors = self._install_wrappers(dry_run)
        if wrapper_errors:
            result.errors.extend(wrapper_errors)
            result.success = False

        # Update shell RC
        rc_result = self._update_shell_rc(shell, dry_run)
        result.modified_files.extend(rc_result.modified_files)
        result.backed_up_files.extend(rc_result.backed_up_files)
        result.errors.extend(rc_result.errors)
        if not rc_result.success:
            result.success = False

        if dry_run:
            result.message += " (dry run)"

        return result

    def _install_wrappers(self, dry_run: bool) -> list[str]:
        """Install wrapper scripts for all configured commands."""
        errors = []

        for command in self.config.wrapper_commands:
            wrapper_path = self.path_manager.get_wrapper_path(command)
            command_path = self.path_manager.get_command_path(command)

            if dry_run:
                continue

            try:
                # Write wrapper script (internal name)
                with wrapper_path.open("w") as f:
                    f.write(WRAPPER_TEMPLATE.format(
                        command=command,
                        sys_executable=sys.executable,
                    ))

                # Make executable
                wrapper_path.chmod(0o755)

                # Create command symlink for PATH interception
                if command_path.exists() or command_path.is_symlink():
                    command_path.unlink()
                command_path.symlink_to(wrapper_path.name)

            except (OSError, IOError) as e:
                errors.append(f"Failed to install wrapper for {command}: {e}")

        return errors

    def _update_shell_rc(self, shell: str, dry_run: bool) -> InstallResult:
        """Update shell RC file with PATH configuration."""
        rc_file = find_shell_rc_file(shell)

        if rc_file is None:
            return InstallResult(
                success=False,
                message=f"Could not find RC file for {shell}",
                errors=[f"No RC file found for {shell}"],
            )

        result = InstallResult(success=True, message=f"Updated {rc_file}")

        # Generate RC content
        if shell in ("bash", "zsh"):
            rc_content = BASH_RC_TEMPLATE.format(wrapper_dir=self.wrapper_dir)
        elif shell == "fish":
            rc_content = FISH_RC_TEMPLATE.format(wrapper_dir=self.wrapper_dir)
        else:
            return InstallResult(
                success=False,
                message=f"Unsupported shell: {shell}",
                errors=[f"Unsupported shell: {shell}"],
            )

        if dry_run:
            return result

        # Backup existing RC file
        if self.config.backup_shell_rc and rc_file.exists():
            backup_path = rc_file.with_suffix(rc_file.suffix + ".linuxsecmonitor.bak")
            try:
                shutil.copy2(rc_file, backup_path)
                result.backed_up_files.append(backup_path)
            except (OSError, IOError) as e:
                result.errors.append(f"Failed to backup {rc_file}: {e}")
                result.success = False
                return result

        # Read existing content
        existing_content = ""
        if rc_file.exists():
            try:
                existing_content = rc_file.read_text(encoding="utf-8")
            except (OSError, IOError) as e:
                result.errors.append(f"Failed to read {rc_file}: {e}")
                result.success = False
                return result

        # Remove existing LinuxSecMonitor section
        cleaned_content = self._remove_marker_section(existing_content)

        # Append new configuration
        if cleaned_content and not cleaned_content.endswith("\n"):
            cleaned_content += "\n"
        cleaned_content += "\n" + rc_content

        # Write updated content
        try:
            rc_file.parent.mkdir(parents=True, exist_ok=True)
            rc_file.write_text(cleaned_content, encoding="utf-8")
            result.modified_files.append(rc_file)
        except (OSError, IOError) as e:
            result.errors.append(f"Failed to write {rc_file}: {e}")
            result.success = False

        return result

    def _remove_marker_section(self, content: str) -> str:
        """Remove existing LinuxSecMonitor marker section from content."""
        lines = content.splitlines(keepends=True)
        output = []
        in_marker = False

        for line in lines:
            if MARKER_START in line:
                in_marker = True
                continue
            if MARKER_END in line:
                in_marker = False
                continue
            if not in_marker:
                output.append(line)

        # Remove trailing blank lines
        while output and output[-1].strip() == "":
            output.pop()

        return "".join(output)

    def uninstall(
        self,
        shell: Optional[str] = None,
        dry_run: bool = False,
        user: bool = True,
    ) -> InstallResult:
        """
        Uninstall wrappers for a shell.

        Args:
            shell: Shell to uninstall for. Auto-detected if None.
            dry_run: If True, only report what would be done
            user: If True, uninstall for current user

        Returns:
            InstallResult with operation details
        """
        if shell is None:
            shell = get_shell_name()

        shell = shell.lower()
        if shell not in ("bash", "zsh", "fish"):
            return InstallResult(
                success=False,
                message=f"Unsupported shell: {shell}",
                errors=[f"Supported shells: bash, zsh, fish"],
            )

        result = InstallResult(success=True, message=f"Uninstalling for {shell}")

        # Remove wrapper scripts
        if not dry_run:
            for command in self.config.wrapper_commands:
                wrapper_path = self.path_manager.get_wrapper_path(command)
                if wrapper_path.exists():
                    try:
                        wrapper_path.unlink()
                        result.modified_files.append(wrapper_path)
                    except (OSError, IOError) as e:
                        result.errors.append(f"Failed to remove wrapper {command}: {e}")

                # Remove command symlink
                command_path = self.path_manager.get_command_path(command)
                if command_path.exists() or command_path.is_symlink():
                    try:
                        command_path.unlink()
                        result.modified_files.append(command_path)
                    except (OSError, IOError) as e:
                        result.errors.append(f"Failed to remove command symlink {command}: {e}")

        # Remove shell RC configuration
        rc_result = self._remove_shell_rc(shell, dry_run)
        result.modified_files.extend(rc_result.modified_files)
        result.errors.extend(rc_result.errors)
        if not rc_result.success:
            result.success = False

        # Try to remove wrapper directory if empty
        if not dry_run and self.wrapper_dir.exists():
            try:
                if not any(self.wrapper_dir.iterdir()):
                    self.wrapper_dir.rmdir()
                    result.modified_files.append(self.wrapper_dir)
            except (OSError, IOError):
                pass  # Directory not empty or other issue

        if dry_run:
            result.message += " (dry run)"

        return result

    def _remove_shell_rc(self, shell: str, dry_run: bool) -> InstallResult:
        """Remove LinuxSecMonitor configuration from shell RC file."""
        rc_file = find_shell_rc_file(shell)

        if rc_file is None or not rc_file.exists():
            return InstallResult(
                success=True,
                message=f"No RC file found for {shell}",
            )

        result = InstallResult(success=True, message=f"Cleaned {rc_file}")

        if dry_run:
            return result

        try:
            existing_content = rc_file.read_text(encoding="utf-8")
        except (OSError, IOError) as e:
            result.errors.append(f"Failed to read {rc_file}: {e}")
            result.success = False
            return result

        # Remove marker section
        cleaned_content = self._remove_marker_section(existing_content)

        # Write cleaned content
        try:
            rc_file.write_text(cleaned_content, encoding="utf-8")
            result.modified_files.append(rc_file)
        except (OSError, IOError) as e:
            result.errors.append(f"Failed to write {rc_file}: {e}")
            result.success = False

        return result

    def status(self, shell: Optional[str] = None) -> dict[str, Any]:
        """
        Get installation status.

        Args:
            shell: Shell to check. Auto-detected if None.

        Returns:
            Dictionary with status information
        """
        if shell is None:
            shell = get_shell_name()

        shell = shell.lower()

        rc_file = find_shell_rc_file(shell)
        wrapper_dir_exists = self.wrapper_dir.exists()

        installed_wrappers = []
        missing_wrappers = []
        for command in self.config.wrapper_commands:
            wrapper_path = self.path_manager.get_wrapper_path(command)
            if wrapper_path.exists():
                installed_wrappers.append(command)
            else:
                missing_wrappers.append(command)

        rc_configured = False
        if rc_file and rc_file.exists():
            try:
                content = rc_file.read_text(encoding="utf-8")
                rc_configured = MARKER_START in content
            except (OSError, IOError):
                pass

        return {
            "shell": shell,
            "rc_file": str(rc_file) if rc_file else None,
            "rc_configured": rc_configured,
            "wrapper_dir": str(self.wrapper_dir),
            "wrapper_dir_exists": wrapper_dir_exists,
            "installed_wrappers": installed_wrappers,
            "missing_wrappers": missing_wrappers,
            "total_commands": len(self.config.wrapper_commands),
        }

    def install_all_shells(
        self,
        dry_run: bool = False,
        user: bool = True,
    ) -> dict[str, InstallResult]:
        """Install wrappers for all supported shells."""
        results = {}
        for shell in ("bash", "zsh", "fish"):
            results[shell] = self.install(shell, dry_run=dry_run, user=user)
        return results

    def uninstall_all_shells(
        self,
        dry_run: bool = False,
        user: bool = True,
    ) -> dict[str, InstallResult]:
        """Uninstall wrappers for all supported shells."""
        results = {}
        for shell in ("bash", "zsh", "fish"):
            results[shell] = self.uninstall(shell, dry_run=dry_run, user=user)
        return results


def install_wrappers(
    shell: str = "auto",
    dry_run: bool = False,
    config: Optional[WrapperConfig] = None,
) -> InstallResult:
    """Convenience function to install wrappers."""
    installer = WrapperInstaller(config)
    if shell == "auto":
        shell = get_shell_name()
    return installer.install(shell, dry_run=dry_run)


def uninstall_wrappers(
    shell: str = "auto",
    dry_run: bool = False,
    config: Optional[WrapperConfig] = None,
) -> InstallResult:
    """Convenience function to uninstall wrappers."""
    installer = WrapperInstaller(config)
    if shell == "auto":
        shell = get_shell_name()
    return installer.uninstall(shell, dry_run=dry_run)


def load_config(path: Optional[Path] = None) -> WrapperConfig:
    """Load wrapper configuration."""
    return WrapperConfig.load(path)