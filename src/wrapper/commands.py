"""Command definitions and tier classification for wrapper framework."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Sequence

from .detection import RepositoryDetector, RepositoryInfo


class Tier(Enum):
    """Command security tier classification."""

    TIER_1_DANGEROUS = "tier_1_dangerous"
    TIER_2_WARN = "tier_2_warn"
    TIER_3_PASSTHROUGH = "tier_3_passthrough"
    BYPASS = "bypass"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CommandPattern:
    """Pattern for matching a command and its arguments."""

    command: str
    subcommands: tuple[str, ...] = field(default_factory=tuple)
    tier: Tier = Tier.UNKNOWN
    requires_repo: bool = False
    aliases: tuple[str, ...] = field(default_factory=tuple)


TIER_1_PATTERNS: tuple[CommandPattern, ...] = (
    CommandPattern("git", ("checkout", "switch", "restore", "merge", "pull", "rebase", "cherry-pick", "reset", "apply", "am", "commit", "push"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("git", ("clone",), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("git", ("submodule", "update"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("git", ("worktree", "add", "move", "remove", "prune"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("npm", ("install", "ci", "add", "update", "audit", "exec", "run-script"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("yarn", ("install", "add", "upgrade", "exec"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("pnpm", ("install", "add", "update", "exec"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("pip", ("install", "download", "wheel"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("pip3", ("install", "download", "wheel"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("pipx", ("install", "inject", "run"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("poetry", ("install", "add", "update", "run"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("cargo", ("install", "add", "update", "build", "test", "run"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("go", ("get", "install", "mod", "build", "run", "test", "generate"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("make", ("install",), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("cmake", ("--install", "--build"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("meson", ("install", "compile", "test"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("bazel", ("build", "test", "run", "install"), Tier.TIER_1_DANGEROUS, True),
    CommandPattern("docker", ("build", "run", "pull", "push", "exec"), Tier.TIER_1_DANGEROUS, False),
    CommandPattern("docker-compose", ("up", "build", "run", "exec", "pull"), Tier.TIER_1_DANGEROUS, False),
    CommandPattern("podman", ("build", "run", "pull", "push", "exec"), Tier.TIER_1_DANGEROUS, False),
)

TIER_2_PATTERNS: tuple[CommandPattern, ...] = (
    CommandPattern("git", ("status", "diff", "log", "show", "branch", "tag", "remote", "fetch", "ls-remote", "describe", "blame", "grep", "shortlog", "stash", "bisect"), Tier.TIER_2_WARN, True),
    CommandPattern("npm", ("run", "test", "build", "start", "dev", "preview", "lint", "format"), Tier.TIER_2_WARN, True),
    CommandPattern("yarn", ("run", "test", "build", "start", "dev"), Tier.TIER_2_WARN, True),
    CommandPattern("pnpm", ("run", "test", "build", "start", "dev"), Tier.TIER_2_WARN, True),
    CommandPattern("pip", ("list", "show", "check", "search", "cache"), Tier.TIER_2_WARN, True),
    CommandPattern("pip3", ("list", "show", "check", "search", "cache"), Tier.TIER_2_WARN, True),
    CommandPattern("poetry", ("show", "lock", "export", "run", "build", "test"), Tier.TIER_2_WARN, True),
    CommandPattern("cargo", ("build", "test", "run", "check", "clippy", "fmt", "doc", "metadata", "tree", "search", "update"), Tier.TIER_2_WARN, True),
    CommandPattern("go", ("build", "test", "run", "vet", "fmt", "mod", "list", "doc", "generate"), Tier.TIER_2_WARN, True),
    CommandPattern("make", (), Tier.TIER_2_WARN, True),
    CommandPattern("cmake", (), Tier.TIER_2_WARN, True),
    CommandPattern("meson", ("setup", "configure", "introspect"), Tier.TIER_2_WARN, True),
    CommandPattern("bazel", ("query", "info", "version", "help"), Tier.TIER_2_WARN, True),
    CommandPattern("python", (), Tier.TIER_2_WARN, True),
    CommandPattern("python3", (), Tier.TIER_2_WARN, True),
    CommandPattern("node", (), Tier.TIER_2_WARN, True),
    CommandPattern("deno", (), Tier.TIER_2_WARN, True),
    CommandPattern("bun", (), Tier.TIER_2_WARN, True),
    CommandPattern("bash", (), Tier.TIER_2_WARN, False),
    CommandPattern("sh", (), Tier.TIER_2_WARN, False),
    CommandPattern("zsh", (), Tier.TIER_2_WARN, False),
    CommandPattern("fish", (), Tier.TIER_2_WARN, False),
)

TIER_3_PASSTHROUGH_PATTERNS: tuple[CommandPattern, ...] = (
    CommandPattern("git", ("--version", "--help", "version", "help", "config", "init", "add", "rm", "mv", "ls-files", "ls-tree", "rev-parse", "symbolic-ref", "name-rev", "count-objects", "gc", "fsck", "prune", "reflog", "verify-commit", "verify-tag", "archive", "bundle", "daemon", "instaweb", "filter-branch", "replace", "notes", "credential", "credential-cache", "credential-store", "send-pack", "receive-pack", "upload-pack", "upload-archive", "request-pull", "format-patch"), Tier.TIER_3_PASSTHROUGH, True),
    CommandPattern("npm", ("--version", "--help", "version", "help", "ls", "list", "outdated", "audit", "fund", "owner", "pack", "publish", "access", "profile", "team", "org", "token", "whoami", "login", "logout", "adduser", "star", "stars", "view", "search", "docs", "repo", "bugs", "home", "ping", "dist-tag", "deprecate", "unpublish", "cache", "completion", "diff", "explain", "query", "why"), Tier.TIER_3_PASSTHROUGH, True),
    CommandPattern("python", ("-m", "pip", "-c", "-m pytest", "-m unittest"), Tier.TIER_3_PASSTHROUGH, False),
    CommandPattern("python3", ("-m", "pip", "-c", "-m pytest", "-m unittest"), Tier.TIER_3_PASSTHROUGH, False),
)


SHELL_BUILTINS: frozenset[str] = frozenset({
    "source", ".", "eval", "exec", "export", "readonly", "local", "declare",
    "typeset", "alias", "unalias", "function", "cd", "pwd", "pushd", "popd",
    "dirs", "echo", "printf", "read", "readarray", "mapfile", "let",
    "(( ))", "[[ ]]", "[ ]", "test", "true", "false", ":", "break", "continue",
    "return", "exit", "shift", "set", "unset", "trap", "wait", "jobs", "fg",
    "bg", "kill", "disown", "suspend", "hash", "type", "command", "builtin",
    "enable", "help", "history", "fc", "time", "times", "ulimit", "umask",
})


class CommandClassifier:
    """Classifies commands into security tiers based on command and arguments."""

    def __init__(self):
        self._config_hash = self._compute_config_hash()
        self._scanner_version = "1.0.0"
        self._malware_db_version = "1.0.0"

    def _compute_config_hash(self) -> str:
        """Compute hash of security configuration."""
        config_data = b"linuxsecmonitor-wrapper-config-v1"
        return hashlib.sha256(config_data).hexdigest()[:16]

    def get_config_hash(self) -> str:
        """Get configuration hash for cache key."""
        return self._config_hash

    def get_scanner_version(self) -> str:
        """Get scanner version for cache key."""
        return self._scanner_version

    def get_malware_db_version(self) -> str:
        """Get malware database version for cache key."""
        return self._malware_db_version

    def classify(self, command_name: str, argv: Sequence[str]) -> tuple[Tier, Optional[str]]:
        """
        Classify a command into a security tier.

        Args:
            command_name: The executable name (basename or absolute path)
            argv: Full argument vector

        Returns:
            Tuple of (Tier, bypass_reason_if_any)
        """
        base_name = Path(command_name).name.lower()

        if self._is_absolute_path_bypass(command_name):
            return Tier.BYPASS, "absolute_path"

        if self._is_shell_builtin(base_name):
            return Tier.BYPASS, "shell_builtin"

        if self._is_inline_interpreter(argv):
            return Tier.BYPASS, "inline_interpreter"

        if self._is_sudo_command(argv):
            return Tier.BYPASS, "sudo_environment"

        tier = self._match_patterns(base_name, argv)
        if tier != Tier.UNKNOWN:
            return tier, None

        return Tier.UNKNOWN, None

    def _is_absolute_path_bypass(self, command_name: str) -> bool:
        """Check if command is an absolute path (bypasses PATH wrapper)."""
        return os.path.isabs(command_name)

    def _is_shell_builtin(self, command_name: str) -> bool:
        """Check if command is a shell builtin."""
        return command_name in SHELL_BUILTINS

    def _is_inline_interpreter(self, argv: Sequence[str]) -> bool:
        """Check if command is an inline interpreter invocation (bash -c, python -c, etc.)."""
        if len(argv) < 2:
            return False

        base_name = Path(argv[0]).name.lower()
        interpreters = {"bash", "sh", "zsh", "fish", "python", "python3", "python2",
                        "perl", "ruby", "php", "node", "deno", "bun", "lua", "tclsh"}

        if base_name not in interpreters:
            return False

        if "-c" in argv[1:]:
            return True

        return False

    def _is_sudo_command(self, argv: Sequence[str]) -> bool:
        """Check if command is run via sudo (different PATH/env)."""
        if not argv:
            return False
        base_name = Path(argv[0]).name.lower()
        return base_name in {"sudo", "doas", "run0"}

    def _match_patterns(self, command_name: str, argv: Sequence[str]) -> Tier:
        """Match command against tier patterns."""
        if len(argv) < 2:
            return self._default_tier(command_name)

        subcommand = argv[1].lower()

        for pattern in TIER_1_PATTERNS:
            if pattern.command == command_name:
                if not pattern.subcommands or subcommand in pattern.subcommands:
                    if subcommand in pattern.aliases:
                        return pattern.tier
                    return pattern.tier

        for pattern in TIER_2_PATTERNS:
            if pattern.command == command_name:
                if not pattern.subcommands or subcommand in pattern.subcommands:
                    if subcommand in pattern.aliases:
                        return pattern.tier
                    return pattern.tier

        for pattern in TIER_3_PASSTHROUGH_PATTERNS:
            if pattern.command == command_name:
                if not pattern.subcommands or subcommand in pattern.subcommands:
                    return pattern.tier

        return self._default_tier(command_name)

    def _default_tier(self, command_name: str) -> Tier:
        """Get default tier for unknown subcommands."""
        dangerous_commands = {
            "git", "npm", "yarn", "pnpm", "pip", "pip3", "pipx", "poetry",
            "cargo", "go", "make", "cmake", "meson", "bazel", "docker",
            "docker-compose", "podman",
        }
        if command_name in dangerous_commands:
            return Tier.TIER_2_WARN
        return Tier.TIER_3_PASSTHROUGH