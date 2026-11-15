"""PATH management utilities for wrapper framework."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class PathResolution:
    """Result of resolving a command to its trusted executable."""

    command: str
    wrapper_path: Path
    trusted_executable: Optional[Path]
    is_wrapper: bool
    bypass_reason: Optional[str] = None


class PathManager:
    """Manages PATH resolution and wrapper installation paths."""

    # Commands that are wrapped by LinuxSecMonitor
    WRAPPED_COMMANDS: frozenset[str] = frozenset({
        "git", "npm", "yarn", "pnpm", "pip", "pip3", "pipx", "poetry",
        "cargo", "go", "make", "cmake", "meson", "bazel",
        "docker", "docker-compose", "podman",
        "python", "python3", "node", "deno", "bun",
        "bash", "sh", "zsh", "fish",
    })

    def __init__(self, wrapper_dir: Path):
        """
        Initialize path manager.

        Args:
            wrapper_dir: Directory containing LinuxSecMonitor wrappers
        """
        self.wrapper_dir = wrapper_dir.expanduser().resolve()

    def get_wrapper_path(self, command: str) -> Path:
        """Get the wrapper script path for a command."""
        return self.wrapper_dir / f"lsmonitor-{command}"

    def get_command_path(self, command: str) -> Path:
        """Get the command symlink path for PATH interception."""
        return self.wrapper_dir / command

    def get_all_wrapper_paths(self) -> list[Path]:
        """Get all wrapper script paths."""
        return [self.get_wrapper_path(cmd) for cmd in self.WRAPPED_COMMANDS]

    def is_wrapped_command(self, command: str) -> bool:
        """Check if a command is wrapped by LinuxSecMonitor."""
        return command in self.WRAPPED_COMMANDS

    def resolve_trusted_executable(self, command: str) -> Optional[Path]:
        """
        Resolve the trusted system executable for a command.

        This searches in standard system paths, avoiding the wrapper directory
        and any user-controlled PATH elements that could be compromised.

        Args:
            command: Command name to resolve

        Returns:
            Path to trusted executable or None if not found
        """
        # System paths to search (in order of preference)
        system_paths = [
            "/usr/bin",
            "/usr/local/bin",
            "/bin",
            "/sbin",
            "/usr/sbin",
        ]

        for sys_path in system_paths:
            candidate = Path(sys_path) / command
            if candidate.is_file() and os.access(candidate, os.X_OK):
                # Verify it's not a symlink into a repository
                try:
                    resolved = candidate.resolve(strict=True)
                    # Basic check: not in common user directories
                    user_dirs = [Path.home(), Path("/tmp"), Path("/var/tmp")]
                    if not any(resolved.is_relative_to(d) for d in user_dirs):
                        return resolved
                except (OSError, RuntimeError):
                    continue

        return None

    def resolve_command(self, command: str, argv: list[str]) -> PathResolution:
        """
        Resolve a command to its trusted executable, handling bypasses.

        Args:
            command: Command name (may be absolute path)
            argv: Full argument vector

        Returns:
            PathResolution with details
        """
        wrapper_path = self.get_wrapper_path(command)
        is_wrapper = wrapper_path.exists()

        # Check for bypasses
        bypass_reason = self._check_bypass(command, argv)
        if bypass_reason:
            return PathResolution(
                command=command,
                wrapper_path=wrapper_path,
                trusted_executable=None,
                is_wrapper=is_wrapper,
                bypass_reason=bypass_reason,
            )

        trusted = self.resolve_trusted_executable(command)
        return PathResolution(
            command=command,
            wrapper_path=wrapper_path,
            trusted_executable=trusted,
            is_wrapper=is_wrapper,
        )

    def _check_bypass(self, command: str, argv: list[str]) -> Optional[str]:
        """Check if command should bypass the wrapper."""
        # Absolute path bypass
        if os.path.isabs(command):
            return "absolute_path"

        # Shell builtins
        shell_builtins = {
            "source", ".", "eval", "exec", "export", "readonly", "local",
            "declare", "typeset", "alias", "unalias", "function", "cd",
            "pwd", "pushd", "popd", "dirs", "echo", "printf", "read",
            "readarray", "mapfile", "let", "break", "continue", "return",
            "exit", "shift", "set", "unset", "trap", "wait", "jobs", "fg",
            "bg", "kill", "disown", "suspend", "hash", "type", "command",
            "builtin", "enable", "help", "history", "fc", "time", "times",
            "ulimit", "umask",
        }
        base_name = Path(command).name.lower()
        if base_name in shell_builtins:
            return "shell_builtin"

        # Inline interpreter
        if len(argv) >= 2:
            interpreters = {"bash", "sh", "zsh", "fish", "python", "python3",
                          "python2", "perl", "ruby", "php", "node", "deno", "bun", "lua", "tclsh"}
            if base_name in interpreters and "-c" in argv[1:]:
                return "inline_interpreter"

        # Sudo
        if base_name in {"sudo", "doas", "run0"}:
            return "sudo_environment"

        return None

    def ensure_wrapper_dir_in_path(self, current_path: Optional[str] = None) -> str:
        """
        Ensure wrapper directory is in PATH with correct precedence.

        Args:
            current_path: Current PATH string (defaults to os.environ["PATH"])

        Returns:
            Updated PATH string
        """
        if current_path is None:
            current_path = os.environ.get("PATH", "")

        path_entries = current_path.split(os.pathsep)
        wrapper_dir_str = str(self.wrapper_dir)

        # Remove existing wrapper directory entries
        path_entries = [p for p in path_entries if p != wrapper_dir_str]

        # Prepend wrapper directory for precedence
        path_entries.insert(0, wrapper_dir_str)

        return os.pathsep.join(path_entries)

    def remove_wrapper_dir_from_path(self, current_path: Optional[str] = None) -> str:
        """Remove wrapper directory from PATH."""
        if current_path is None:
            current_path = os.environ.get("PATH", "")

        path_entries = current_path.split(os.pathsep)
        wrapper_dir_str = str(self.wrapper_dir)

        path_entries = [p for p in path_entries if p != wrapper_dir_str]

        return os.pathsep.join(path_entries)

    def verify_no_recursion(self, command: str, argv: list[str]) -> bool:
        """
        Verify that executing the trusted executable won't recurse into the wrapper.

        Args:
            command: Command name
            argv: Argument vector

        Returns:
            True if safe to execute, False if recursion detected
        """
        trusted = self.resolve_trusted_executable(command)
        if trusted is None:
            return False

        # Check if trusted executable is the wrapper itself
        try:
            wrapper_path = self.get_wrapper_path(command)
            if wrapper_path.exists():
                wrapper_resolved = wrapper_path.resolve(strict=True)
                if trusted == wrapper_resolved:
                    return False
        except (OSError, RuntimeError):
            pass

        return True


def find_shell_rc_file(shell: str) -> Optional[Path]:
    """Find the appropriate shell RC file for a shell."""
    home = Path(os.environ.get("HOME", str(Path.home())))

    shell_rc_map = {
        "bash": [
            home / ".bashrc",
            home / ".bash_profile",
            home / ".profile",
        ],
        "zsh": [
            home / ".zshrc",
            home / ".zprofile",
            home / ".zlogin",
        ],
        "fish": [
            home / ".config" / "fish" / "config.fish",
        ],
    }

    candidates = shell_rc_map.get(shell.lower(), [])
    for candidate in candidates:
        if candidate.exists():
            return candidate

    # Return the primary one even if it doesn't exist yet
    return candidates[0] if candidates else None


def get_shell_name() -> str:
    """Detect the user's current shell."""
    shell = os.environ.get("SHELL", "")
    if shell:
        return Path(shell).name.lower()

    # Fallback: check parent process
    try:
        import psutil
        parent = psutil.Process(os.getppid())
        return Path(parent.name()).name.lower()
    except ImportError:
        pass
    except psutil.NoSuchProcess:
        pass

    return "bash"  # Default fallback