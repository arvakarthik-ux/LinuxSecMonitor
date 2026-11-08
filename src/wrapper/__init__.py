"""LinuxSecMonitor wrapper framework for automatic repository protection."""

from __future__ import annotations

__version__ = "0.1.0"

from .core import CommandWrapper, WrapperDecision, WrapperTier
from .commands import CommandClassifier, Tier
from .detection import RepositoryDetector, RepositoryInfo
from .cache import ScanCache, CacheEntry, CacheKey
from .config import WrapperConfig, load_config
from .path import PathManager, PathResolution
from .install import WrapperInstaller, install_wrappers, uninstall_wrappers, InstallResult
from .scanners import ScannerOrchestrator, repository_content_hash
from .report import build_unified_report, render_json, render_terminal
from .approval import ApprovalManager, ApprovalRecord

__all__ = [
    "CommandWrapper",
    "WrapperDecision",
    "WrapperTier",
    "CommandClassifier",
    "Tier",
    "RepositoryDetector",
    "RepositoryInfo",
    "ScanCache",
    "CacheEntry",
    "CacheKey",
    "WrapperConfig",
    "load_config",
    "PathManager",
    "PathResolution",
    "WrapperInstaller",
    "install_wrappers",
    "uninstall_wrappers",
    "InstallResult",
    "ScannerOrchestrator",
    "repository_content_hash",
    "build_unified_report",
    "render_json",
    "render_terminal",
    "ApprovalManager",
    "ApprovalRecord",
]