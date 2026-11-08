"""TOML configuration for wrapper framework."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib

# tomli_w is optional - saving config requires it
try:
    import tomli_w
except ImportError:
    tomli_w = None


@dataclass
class WrapperConfig:
    """Wrapper framework configuration."""

    # Shell configuration
    enabled_shells: list[str] = field(default_factory=lambda: ["bash", "zsh", "fish"])

    # Installation paths
    wrapper_dir: str = "~/.local/bin"
    config_dir: str = "~/.config/linuxsecmonitor"

    # Wrapper commands to install
    wrapper_commands: list[str] = field(default_factory=lambda: [
        "git", "npm", "yarn", "pnpm", "pip", "pip3", "pipx", "poetry",
        "cargo", "go", "make", "cmake", "meson", "bazel",
        "docker", "docker-compose", "podman",
        "python", "python3", "node", "deno", "bun",
        "bash", "sh", "zsh", "fish",
    ])

    # Security tier configuration
    tier1_commands: list[str] = field(default_factory=lambda: [
        "checkout", "switch", "restore", "merge", "pull", "rebase",
        "cherry-pick", "reset", "apply", "am", "commit", "push", "clone",
        "install", "ci", "add", "update", "exec", "run-script",
        "build", "test", "run",
        "download", "wheel",
        "inject",
        "mod",
        "get",
    ])

    tier2_commands: list[str] = field(default_factory=lambda: [
        "status", "diff", "log", "show", "branch", "tag", "remote",
        "fetch", "ls-remote", "describe",
        "test", "build", "start", "dev", "preview", "lint", "format",
        "list", "show", "check", "search", "cache",
        "check", "clippy", "fmt", "doc", "metadata", "tree", "search", "update",
        "vet", "mod", "list", "doc", "generate",
    ])

    # Scan cache settings
    cache_enabled: bool = True
    cache_ttl_seconds: int = 300
    cache_max_entries: int = 1000
    cache_max_size_mb: int = 50
    cache_dir: str = "~/.cache/linuxsecmonitor"

    # Timeout settings
    scan_timeout_seconds: int = 120
    approval_timeout_seconds: int = 300
    staging_timeout_seconds: int = 30

    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None

    # User policy
    require_tty_for_approval: bool = True
    fail_closed_on_scan_error: bool = True
    fail_closed_on_malware_detection: bool = True
    fail_closed_on_critical_finding: bool = True

    # Installation
    dry_run: bool = False
    backup_shell_rc: bool = True

    def __post_init__(self):
        """Expand paths after initialization."""
        self.wrapper_dir = os.path.expanduser(self.wrapper_dir)
        self.config_dir = os.path.expanduser(self.config_dir)
        self.cache_dir = os.path.expanduser(self.cache_dir)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> WrapperConfig:
        """Load configuration from TOML file."""
        if path is None:
            config_dir = Path(os.path.expanduser("~/.config/linuxsecmonitor"))
            path = config_dir / "wrapper.toml"

        if not path.exists():
            return cls()

        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise ValueError(f"Invalid TOML configuration: {e}")

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WrapperConfig:
        """Create configuration from dictionary."""
        # Filter out unknown keys to be strict
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary for serialization."""
        data = {
            "enabled_shells": self.enabled_shells,
            "wrapper_dir": self.wrapper_dir,
            "config_dir": self.config_dir,
            "wrapper_commands": self.wrapper_commands,
            "tier1_commands": self.tier1_commands,
            "tier2_commands": self.tier2_commands,
            "cache_enabled": self.cache_enabled,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "cache_max_entries": self.cache_max_entries,
            "cache_max_size_mb": self.cache_max_size_mb,
            "cache_dir": self.cache_dir,
            "scan_timeout_seconds": self.scan_timeout_seconds,
            "approval_timeout_seconds": self.approval_timeout_seconds,
            "staging_timeout_seconds": self.staging_timeout_seconds,
            "log_level": self.log_level,
            "require_tty_for_approval": self.require_tty_for_approval,
            "fail_closed_on_scan_error": self.fail_closed_on_scan_error,
            "fail_closed_on_malware_detection": self.fail_closed_on_malware_detection,
            "fail_closed_on_critical_finding": self.fail_closed_on_critical_finding,
            "dry_run": self.dry_run,
            "backup_shell_rc": self.backup_shell_rc,
        }
        if self.log_file is not None:
            data["log_file"] = self.log_file
        return data

    def save(self, path: Optional[Path] = None) -> None:
        """Save configuration to TOML file."""
        if tomli_w is None:
            raise RuntimeError("tomli_w is required to save configuration. Install with: pip install tomli_w")

        if path is None:
            path = Path(self.config_dir) / "wrapper.toml"

        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("wb") as f:
            tomli_w.dump(self.to_dict(), f)

    def validate(self) -> list[str]:
        """Validate configuration and return list of errors."""
        errors = []

        # Validate paths
        for path_name, path_value in [
            ("wrapper_dir", self.wrapper_dir),
            ("config_dir", self.config_dir),
            ("cache_dir", self.cache_dir),
        ]:
            path = Path(path_value)
            if path.is_absolute() and not path.parts[0] == "/":
                errors.append(f"{path_name}: must be absolute or start with ~")
            if ".." in path.parts:
                errors.append(f"{path_name}: must not contain '..'")

        # Validate security settings
        if not self.fail_closed_on_scan_error:
            errors.append("fail_closed_on_scan_error: must be true for security")
        if not self.fail_closed_on_malware_detection:
            errors.append("fail_closed_on_malware_detection: must be true for security")
        if not self.fail_closed_on_critical_finding:
            errors.append("fail_closed_on_critical_finding: must be true for security")

        # Validate timeouts
        if self.scan_timeout_seconds <= 0:
            errors.append("scan_timeout_seconds: must be positive")
        if self.approval_timeout_seconds <= 0:
            errors.append("approval_timeout_seconds: must be positive")
        if self.staging_timeout_seconds <= 0:
            errors.append("staging_timeout_seconds: must be positive")

        # Validate cache settings
        if self.cache_ttl_seconds <= 0:
            errors.append("cache_ttl_seconds: must be positive")
        if self.cache_max_entries <= 0:
            errors.append("cache_max_entries: must be positive")
        if self.cache_max_size_mb <= 0:
            errors.append("cache_max_size_mb: must be positive")

        # Validate log level
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_levels:
            errors.append(f"log_level: must be one of {valid_levels}")

        return errors


def load_config(path: Optional[Path] = None) -> WrapperConfig:
    """Load wrapper configuration from TOML file."""
    return WrapperConfig.load(path)