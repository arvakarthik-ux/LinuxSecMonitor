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
from typing import Any, Optional

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
    retained_files: list[Path] = None

    def __post_init__(self):
        if self.modified_files is None:
            self.modified_files = []
        if self.backed_up_files is None:
            self.backed_up_files = []
        if self.errors is None:
            self.errors = []
        if self.retained_files is None:
            self.retained_files = []


# Wrapper script template.
#
# The generated shim deliberately contains no source-checkout path and no
# sys.path manipulation: it imports the INSTALLED ``src.wrapper`` package
# from site-packages. The shebang pins the interpreter that ran the
# installer (``sys.executable``) so a wheel installed into a virtual
# environment produces a shim that uses that environment's interpreter.
# Startup is fail-closed: if the installed package is missing or broken the
# shim reports the failure and a recovery path on stderr and exits nonzero
# instead of ever falling back to the unwrapped command.
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
SHIM_OWNERSHIP_MARKER = "# LinuxSecMonitor managed wrapper v1"

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

    def _is_owned_shim(self, path: Path) -> bool:
        """Return whether a regular shim exactly matches our generated form."""
        if (
            path.is_symlink()
            or not path.is_file()
            or not path.name.startswith("lsmonitor-")
        ):
            return False
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return False
        lines = content.splitlines()
        if (
            len(lines) < 2
            or not lines[0].startswith("#!")
            or lines[1] != SHIM_OWNERSHIP_MARKER
        ):
            return False
        command = path.name.removeprefix("lsmonitor-")
        expected = WRAPPER_TEMPLATE.format(
            command=command,
            sys_executable=lines[0][2:],
        )
        return content == expected

    def _is_owned_command_link(self, command: str) -> bool:
        """Return whether a command link targets its verified managed shim."""
        command_path = self.path_manager.get_command_path(command)
        shim_path = self.path_manager.get_wrapper_path(command)
        if not command_path.is_symlink() or not self._is_owned_shim(shim_path):
            return False
        try:
            return os.readlink(command_path) == shim_path.name
        except OSError:
            return False

    @staticmethod
    def _marker_state(content: str) -> str:
        """Classify shell RC markers without treating malformed text as owned."""
        lines = [line.rstrip("\r\n") for line in content.splitlines(keepends=True)]
        starts = [index for index, line in enumerate(lines) if line == MARKER_START]
        ends = [index for index, line in enumerate(lines) if line == MARKER_END]
        if not starts and not ends:
            return "absent"
        if len(starts) == len(ends) == 1 and starts[0] < ends[0]:
            return "owned"
        return "invalid"

    def _inspect_shell_rc(
        self, shell: str
    ) -> tuple[Optional[Path], Optional[str], Optional[str]]:
        """Read an RC file only when it is a regular user-controlled file."""
        rc_file = find_shell_rc_file(shell)
        if rc_file is None:
            return None, None, f"No RC file found for {shell}"
        if rc_file.is_symlink():
            return rc_file, None, f"Refusing to modify symlinked shell RC file {rc_file}"
        if not rc_file.exists():
            return rc_file, "", None
        try:
            content = rc_file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            return rc_file, None, f"Could not read shell RC file {rc_file}: {exc}"
        if self._marker_state(content) == "invalid":
            return rc_file, content, (
                f"Shell RC file {rc_file} contains an incomplete or ambiguous "
                "LinuxSecMonitor marker block"
            )
        return rc_file, content, None

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

        _rc_file, _content, rc_error = self._inspect_shell_rc(shell)
        if rc_error:
            return InstallResult(
                success=False,
                message=f"Refusing to update shell integration: {rc_error}",
                errors=[rc_error],
            )

        # Preflight conflict detection BEFORE any writes: never unlink or
        # overwrite a file LinuxSecMonitor does not own, and never write the
        # shell RC block when a conflict exists.
        conflicts = self._detect_conflicts()
        if conflicts:
            return InstallResult(
                success=False,
                message=(
                    "Refusing to install: found existing entries that "
                    "LinuxSecMonitor does not own. Nothing was changed; move "
                    "the listed files aside and run the install again."
                ),
                errors=conflicts,
            )

        result = InstallResult(success=True, message=f"Installing for {shell}")

        if dry_run:
            result.message += " (dry run)"
            return result

        if self.wrapper_dir.is_symlink():
            return InstallResult(
                success=False,
                message=f"Wrapper directory {self.wrapper_dir} is a symlink",
                errors=[f"Refusing to install through symlinked wrapper directory {self.wrapper_dir}"],
            )
        if self.wrapper_dir.exists() and not self.wrapper_dir.is_dir():
            return InstallResult(
                success=False,
                message=f"Wrapper directory {self.wrapper_dir} exists and is not a directory",
                errors=[f"{self.wrapper_dir} exists and is not a directory"],
            )

        # Create wrapper directory only if missing; chmod 0o755 only when we
        # created it (never chmod a pre-existing shared directory).
        if not self.wrapper_dir.exists():
            try:
                self.wrapper_dir.mkdir(parents=True, exist_ok=True)
                os.chmod(self.wrapper_dir, 0o755)
                result.modified_files.append(self.wrapper_dir)
            except OSError as exc:
                return InstallResult(
                    success=False,
                    message=f"Could not create wrapper directory {self.wrapper_dir}",
                    errors=[str(exc)],
                )

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

        return result

    def _detect_conflicts(self) -> list[str]:
        """Detect foreign files at shim and PATH-link locations."""
        conflicts: list[str] = []
        for command in self.config.wrapper_commands:
            command_path = self.path_manager.get_command_path(command)
            expected_shim = self.path_manager.get_wrapper_path(command)
            try:
                if (
                    (expected_shim.exists() or expected_shim.is_symlink())
                    and not self._is_owned_shim(expected_shim)
                ):
                    conflicts.append(
                        f"{expected_shim} exists but is not a verified "
                        "LinuxSecMonitor shim; move it aside before installing"
                    )
                if command_path.is_symlink():
                    if not self._is_owned_command_link(command):
                        conflicts.append(
                            f"{command_path} is not a link to a verified "
                            f"LinuxSecMonitor '{expected_shim.name}' shim; "
                            "move it aside before installing"
                        )
                elif command_path.exists():
                    conflicts.append(
                        f"{command_path} already exists and is not a "
                        "LinuxSecMonitor wrapper; move it aside before installing"
                    )
            except OSError as exc:
                conflicts.append(f"Could not inspect {command_path}: {exc}")
        return conflicts

    def _install_wrappers(self, dry_run: bool) -> list[str]:
        """Install wrapper scripts for all configured commands."""
        errors = []

        for command in self.config.wrapper_commands:
            wrapper_path = self.path_manager.get_wrapper_path(command)
            command_path = self.path_manager.get_command_path(command)

            if dry_run:
                continue

            try:
                # Write wrapper script (internal name). The shim imports the
                # installed package and pins the installing interpreter; no
                # checkout path is embedded.
                with wrapper_path.open("w") as f:
                    f.write(WRAPPER_TEMPLATE.format(
                        command=command,
                        sys_executable=sys.executable,
                    ))

                # Make executable
                wrapper_path.chmod(0o755)

                # Create command symlink for PATH interception. The preflight
                # conflict check guarantees the entry is absent or ours.
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

        rc_file, existing_content, rc_error = self._inspect_shell_rc(shell)
        if rc_file is None or rc_error:
            error = rc_error or f"No RC file found for {shell}"
            return InstallResult(success=False, message=error, errors=[error])

        # Remove existing LinuxSecMonitor section
        cleaned_content = self._remove_marker_section(existing_content or "")

        if self.config.backup_shell_rc and rc_file.exists():
            backup_path, backup_error = self._ensure_shell_rc_backup(
                rc_file, cleaned_content,
            )
            if backup_error:
                result.errors.append(backup_error)
                result.success = False
                return result
            if backup_path is not None:
                result.backed_up_files.append(backup_path)

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

    def _ensure_shell_rc_backup(
        self, rc_file: Path, pristine_content: str
    ) -> tuple[Optional[Path], Optional[str]]:
        """Validate or exclusively create the pristine RC backup without following links."""
        backup_path = rc_file.with_suffix(
            rc_file.suffix + ".linuxsecmonitor.bak"
        )
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            return None, "Cannot safely inspect the shell RC backup without O_NOFOLLOW"

        try:
            backup_stat = backup_path.lstat()
        except FileNotFoundError:
            backup_stat = None
        except OSError as exc:
            return None, f"Could not inspect shell RC backup {backup_path}: {exc}"

        if backup_stat is not None:
            if not stat.S_ISREG(backup_stat.st_mode):
                return None, (
                    f"Refusing to modify {rc_file}: backup path {backup_path} "
                    "is not a regular file"
                )
            flags = os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0)
            try:
                fd = os.open(backup_path, flags)
                with os.fdopen(fd, "rb") as backup_file:
                    opened_stat = os.fstat(backup_file.fileno())
                    if not stat.S_ISREG(opened_stat.st_mode):
                        return None, (
                            f"Refusing to modify {rc_file}: backup path "
                            f"{backup_path} is not a regular file"
                        )
                    backup_content = backup_file.read()
            except OSError as exc:
                return None, (
                    f"Could not safely read shell RC backup {backup_path}: {exc}"
                )
            try:
                normalized_backup = backup_content.decode("utf-8")
            except UnicodeError:
                normalized_backup = None
            if normalized_backup is not None:
                normalized_backup = normalized_backup.replace("\r\n", "\n").replace("\r", "\n")
            if normalized_backup != pristine_content:
                return None, (
                    f"Refusing to modify {rc_file}: existing backup {backup_path} "
                    "is not a valid pristine LinuxSecMonitor backup"
                )
            return None, None

        try:
            rc_fd = os.open(
                rc_file,
                os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
            )
            with os.fdopen(rc_fd, "rb") as rc_stream:
                rc_stat = os.fstat(rc_stream.fileno())
                if not stat.S_ISREG(rc_stat.st_mode):
                    return None, f"Refusing to back up non-regular shell RC file {rc_file}"
                raw_content = rc_stream.read()
        except OSError as exc:
            return None, f"Could not safely read shell RC file {rc_file}: {exc}"

        pristine_bytes = self._pristine_rc_bytes(raw_content)
        if pristine_bytes is None:
            return None, f"Refusing to back up malformed shell RC file {rc_file}"
        try:
            normalized_pristine = pristine_bytes.decode("utf-8")
        except UnicodeError:
            return None, f"Refusing to back up non-UTF-8 shell RC file {rc_file}"
        normalized_pristine = normalized_pristine.replace("\r\n", "\n").replace("\r", "\n")
        if normalized_pristine != pristine_content:
            return None, f"Shell RC file {rc_file} changed while preparing its backup"

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow
        try:
            fd = os.open(
                backup_path, flags, stat.S_IMODE(rc_stat.st_mode),
            )
        except OSError as exc:
            return None, f"Could not safely create shell RC backup {backup_path}: {exc}"

        created_stat = os.fstat(fd)
        try:
            with os.fdopen(fd, "wb") as backup_file:
                backup_file.write(pristine_bytes)
                backup_file.flush()
                os.fsync(backup_file.fileno())
        except OSError as exc:
            try:
                current_stat = backup_path.lstat()
                if (
                    current_stat.st_dev == created_stat.st_dev
                    and current_stat.st_ino == created_stat.st_ino
                ):
                    backup_path.unlink()
            except OSError:
                pass
            return None, f"Could not safely write shell RC backup {backup_path}: {exc}"
        return backup_path, None

    @staticmethod
    def _pristine_rc_bytes(content: bytes) -> Optional[bytes]:
        """Remove one valid managed RC block while preserving original bytes."""
        lines = content.splitlines(keepends=True)
        starts = [
            index for index, line in enumerate(lines)
            if line.rstrip(b"\r\n") == MARKER_START.encode("ascii")
        ]
        ends = [
            index for index, line in enumerate(lines)
            if line.rstrip(b"\r\n") == MARKER_END.encode("ascii")
        ]
        if not starts and not ends:
            return content
        if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
            return None
        before = lines[:starts[0]]
        if before and not before[-1].strip():
            before.pop()
        return b"".join(before + lines[ends[0] + 1:])

    def _remove_marker_section(self, content: str) -> str:
        """Remove only one complete, unambiguous LinuxSecMonitor section."""
        lines = content.splitlines(keepends=True)
        if self._marker_state(content) != "owned":
            return content
        start = next(
            index for index, line in enumerate(lines)
            if line.rstrip("\r\n") == MARKER_START
        )
        end = next(
            index for index, line in enumerate(lines)
            if line.rstrip("\r\n") == MARKER_END
        )
        before = lines[:start]
        if before and not before[-1].strip():
            before.pop()
        return "".join(before + lines[end + 1:])

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

        _rc_file, _content, rc_error = self._inspect_shell_rc(shell)
        if rc_error:
            return InstallResult(
                success=False,
                message=f"Refusing to uninstall shell integration: {rc_error}",
                errors=[rc_error],
            )

        result = InstallResult(success=True, message=f"Uninstalling for {shell}")

        if self.wrapper_dir.is_symlink():
            return InstallResult(
                success=False,
                message=f"Refusing to uninstall through symlinked wrapper directory {self.wrapper_dir}",
                errors=[f"Wrapper directory {self.wrapper_dir} is a symlink"],
            )

        # Remove only configured command links and shim files carrying the
        # ownership marker. Keep and report every unknown entry.
        if not dry_run and self.wrapper_dir.is_dir():
            managed_names: set[str] = set()
            for command in self.config.wrapper_commands:
                shim = self.path_manager.get_wrapper_path(command)
                command_path = self.path_manager.get_command_path(command)
                managed_names.update((shim.name, command_path.name))
                for entry, owned in (
                    (command_path, self._is_owned_command_link(command)),
                    (shim, self._is_owned_shim(shim)),
                ):
                    if not entry.exists() and not entry.is_symlink():
                        continue
                    if not owned:
                        result.retained_files.append(entry)
                        continue
                    try:
                        entry.unlink()
                        result.modified_files.append(entry)
                    except (OSError, IOError) as e:
                        result.errors.append(f"Failed to remove {entry}: {e}")
                        result.success = False

            for entry in sorted(self.wrapper_dir.iterdir()):
                if entry.name not in managed_names:
                    result.retained_files.append(entry)

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

        if result.retained_files:
            result.message += (
                " Left in place (not owned by LinuxSecMonitor): "
                + ", ".join(str(path) for path in result.retained_files)
            )

        if dry_run:
            result.message += " (dry run)"

        return result

    def _remove_shell_rc(self, shell: str, dry_run: bool) -> InstallResult:
        """Remove LinuxSecMonitor configuration from shell RC file."""
        rc_file, existing_content, rc_error = self._inspect_shell_rc(shell)
        if rc_error:
            return InstallResult(
                success=False,
                message=f"Refusing to remove shell integration: {rc_error}",
                errors=[rc_error],
            )
        if rc_file is None or not rc_file.exists():
            return InstallResult(
                success=True,
                message=f"No RC file found for {shell}",
            )

        result = InstallResult(success=True, message=f"Cleaned {rc_file}")

        if dry_run:
            return result

        # Remove marker section
        cleaned_content = self._remove_marker_section(existing_content or "")

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

        Read-only. The returned mapping is JSON-serializable and reports the
        active shell, per-command shim location and presence, shell RC
        integration, overall shim state, PATH precedence, how ``git``
        resolves under the current PATH, and a recovery hint when the
        wrapper is not (fully) installed or a shim is broken.

        Args:
            shell: Shell to check. Auto-detected if None.

        Returns:
            Dictionary with status information
        """
        if shell is None:
            shell = get_shell_name()

        shell = shell.lower()

        rc_file, rc_content, rc_error = self._inspect_shell_rc(shell)
        wrapper_dir_exists = self.wrapper_dir.exists()

        wrappers: list[dict[str, Any]] = []
        installed_wrappers = []
        missing_wrappers = []
        for command in self.config.wrapper_commands:
            wrapper_path = self.path_manager.get_wrapper_path(command)
            command_path = self.path_manager.get_command_path(command)
            present = wrapper_path.exists() or wrapper_path.is_symlink()
            if not present:
                state = "missing"
            elif self._is_owned_shim(wrapper_path) and os.access(wrapper_path, os.X_OK):
                state = "installed"
            else:
                state = "broken"
            if state == "installed":
                installed_wrappers.append(command)
            elif state == "missing":
                missing_wrappers.append(command)
            wrappers.append({
                "command": command,
                "shim_path": str(wrapper_path),
                "shim_present": present,
                "shim_state": state,
                "path_link": str(command_path),
                "path_link_present": command_path.is_symlink() or command_path.exists(),
            })

        states = [entry["shim_state"] for entry in wrappers]
        if not states:
            shim_status = "installed"
        elif any(state == "broken" for state in states):
            shim_status = "broken"
        elif all(state == "installed" for state in states):
            shim_status = "installed"
        elif all(state == "missing" for state in states):
            shim_status = "missing"
        else:
            shim_status = "partial"

        rc_configured = (
            rc_content is not None and self._marker_state(rc_content) == "owned"
        )

        # PATH precedence: where the wrapper directory sits in the current
        # PATH relative to the standard system directories.
        path_entries = os.environ.get("PATH", "").split(os.pathsep)
        wrapper_dir_str = str(self.wrapper_dir)
        index = (
            path_entries.index(wrapper_dir_str)
            if wrapper_dir_str in path_entries
            else None
        )
        system_dirs = (
            "/usr/local/bin", "/usr/bin", "/bin",
            "/usr/local/sbin", "/usr/sbin", "/sbin",
        )
        ahead_of_system_dirs = index is not None and all(
            path_entries.index(directory) > index
            for directory in system_dirs
            if directory in path_entries
        )

        # How git resolves under the current PATH.
        git_path = shutil.which("git")
        via_wrapper = False
        if git_path:
            try:
                via_wrapper = (
                    Path(git_path).resolve().parent
                    == self.path_manager.wrapper_dir
                )
            except (OSError, RuntimeError):
                via_wrapper = False

        recovery = None
        if shim_status != "installed" or not rc_configured or rc_error:
            recovery = (
                "Wrapper is not fully installed "
                f"(shim status: {shim_status}; RC marker present: {rc_configured}). "
                "Run 'linuxsecmonitor --wrapper-integration install' to repair, "
                "'linuxsecmonitor --wrapper-integration uninstall' to remove it, "
                "or reinstall the package with 'python -m pip install "
                "linuxsecmonitor'."
            )

        return {
            "shell": shell,
            "rc_file": str(rc_file) if rc_file else None,
            "rc_configured": rc_configured,
            "rc_error": rc_error,
            "wrapper_dir": wrapper_dir_str,
            "wrapper_dir_exists": wrapper_dir_exists,
            "installed_wrappers": installed_wrappers,
            "missing_wrappers": missing_wrappers,
            "total_commands": len(self.config.wrapper_commands),
            "wrappers": wrappers,
            "shim_status": shim_status,
            "path_precedence": {
                "index": index,
                "in_path": index is not None,
                "ahead_of_system_dirs": ahead_of_system_dirs,
            },
            "git_resolution": {
                "path": git_path,
                "via_wrapper": via_wrapper,
            },
            "recovery": recovery,
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