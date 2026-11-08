"""Wrapper core: command identification, repository context, and decision coordination."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Sequence

from scanner.child_environment import build_child_environment

from .commands import CommandClassifier, Tier
from .detection import RepositoryDetector, RepositoryInfo
from .cache import ScanCache, CacheKey
from .path import PathManager


class WrapperTier(Enum):
    """Wrapper execution tier classification."""

    TIER_1_DANGEROUS = "tier_1_dangerous"
    TIER_2_WARN = "tier_2_warn"
    TIER_3_PASSTHROUGH = "tier_3_passthrough"
    BYPASS = "bypass"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class WrapperDecision:
    """Structured decision from the wrapper framework."""

    command_name: str
    argv: tuple[str, ...]
    tier: WrapperTier
    repository: Optional[RepositoryInfo]
    should_intercept: bool
    bypass_reason: Optional[str] = None
    cache_key: Optional[CacheKey] = None
    original_argv: tuple[str, ...] = field(default_factory=tuple)

    @property
    def requires_approval(self) -> bool:
        """Whether this command requires explicit approval."""
        return self.tier == WrapperTier.TIER_1_DANGEROUS

    @property
    def requires_warning(self) -> bool:
        """Whether this command should warn but auto-approve."""
        return self.tier == WrapperTier.TIER_2_WARN

    @property
    def is_passthrough(self) -> bool:
        """Whether this command passes through without interception."""
        return self.tier in (WrapperTier.TIER_3_PASSTHROUGH, WrapperTier.BYPASS)


class CommandWrapper:
    """Central wrapper framework for automatic repository protection."""

    def __init__(
        self,
        command_name: str,
        argv: Sequence[str],
        *,
        cwd: Optional[Path] = None,
        classifier: Optional[CommandClassifier] = None,
        detector: Optional[RepositoryDetector] = None,
        cache: Optional[ScanCache] = None,
        path_manager: Optional[PathManager] = None,
    ):
        """
        Initialize the wrapper with a command and arguments.

        Args:
            command_name: The executable name (e.g., 'git', 'npm', 'python')
            argv: Full argument vector including command (e.g., ['git', 'checkout', 'main'])
            cwd: Working directory (defaults to current working directory)
            classifier: Command classifier instance (created if not provided)
            detector: Repository detector instance (created if not provided)
            cache: Scan cache instance (created if not provided)
            path_manager: PATH manager for trusted executable resolution (created if not provided)
        """
        self.command_name = command_name
        self.argv = tuple(argv) if argv else (command_name,)
        self.cwd = cwd or Path.cwd()
        self.classifier = classifier or CommandClassifier()
        self.detector = detector or RepositoryDetector()
        self.cache = cache or ScanCache()
        self.path_manager = path_manager or PathManager(Path.home() / ".local" / "bin")

    def should_intercept(self) -> bool:
        """Determine if this command should be intercepted."""
        decision = self._make_decision()
        return decision.should_intercept

    def get_decision(self) -> WrapperDecision:
        """Get the full structured decision for this command."""
        return self._make_decision()

    def _make_decision(self) -> WrapperDecision:
        """Make the wrapper decision."""
        original_argv = self.argv

        tier, bypass_reason = self.classifier.classify(self.command_name, self.argv)

        if tier == Tier.BYPASS:
            wrapper_tier = WrapperTier.BYPASS
            repository = None
            should_intercept = False
            cache_key = None
        else:
            wrapper_tier = self._map_tier(tier)
            repository = self.detector.detect(self.cwd)
            should_intercept = tier != Tier.TIER_3_PASSTHROUGH

            if repository and repository.is_repository:
                cache_key = CacheKey.from_repository(
                    repository.root,
                    self.classifier.get_config_hash(),
                    self.classifier.get_scanner_version(),
                    self.classifier.get_malware_db_version(),
                )
            else:
                cache_key = None

        return WrapperDecision(
            command_name=self.command_name,
            argv=self.argv,
            tier=wrapper_tier,
            repository=repository,
            should_intercept=should_intercept,
            bypass_reason=bypass_reason,
            cache_key=cache_key,
            original_argv=original_argv,
        )

    def _map_tier(self, tier: Tier) -> WrapperTier:
        """Map command tier to wrapper tier."""
        mapping = {
            Tier.TIER_1_DANGEROUS: WrapperTier.TIER_1_DANGEROUS,
            Tier.TIER_2_WARN: WrapperTier.TIER_2_WARN,
            Tier.TIER_3_PASSTHROUGH: WrapperTier.TIER_3_PASSTHROUGH,
            Tier.BYPASS: WrapperTier.BYPASS,
            Tier.UNKNOWN: WrapperTier.UNKNOWN,
        }
        return mapping.get(tier, WrapperTier.UNKNOWN)

    def execute(self) -> int:
        """
        Execute the command after wrapper decision.

        This is the main entry point for the wrapper. It:
        1. Makes the wrapper decision
        2. Handles bypasses
        3. For Tier 1/2, coordinates with scanners and approval
        4. Executes the original command via argv (no shell)

        Returns:
            Exit code from the executed command
        """
        decision = self._make_decision()

        if decision.is_passthrough:
            return self._execute_passthrough(decision)

        if decision.tier == WrapperTier.TIER_1_DANGEROUS:
            return self._execute_tier1(decision)

        if decision.tier == WrapperTier.TIER_2_WARN:
            return self._execute_tier2(decision)

        return self._execute_passthrough(decision)

    def _execute_passthrough(self, decision: WrapperDecision) -> int:
        """Execute command without interception (Tier 3 or bypass)."""
        if decision.bypass_reason:
            print(f"[LinuxSecMonitor] PASSTHROUGH: {' '.join(decision.argv)} ({decision.bypass_reason})", file=sys.stderr)

        return self._run_command(decision.argv)

    def _execute_tier2(self, decision: WrapperDecision) -> int:
        """Execute Tier 2 command: scan + warn, then auto-approve."""
        print(f"[LinuxSecMonitor] TIER 2: Scanning repository before {' '.join(decision.argv)}", file=sys.stderr)

        if decision.repository and decision.repository.is_repository:
            report = self._scan_repository(decision)
            if report.get("coverage_complete") is not True:
                print("[LinuxSecMonitor] BLOCKED: repository inspection is incomplete", file=sys.stderr)
                return 1
            if report.get("malware_findings"):
                print("[LinuxSecMonitor] BLOCKED: confirmed malware detected", file=sys.stderr)
                return 1
            for finding in report.get("findings", []):
                if finding.get("severity") == "CRITICAL":
                    print("[LinuxSecMonitor] BLOCKED: critical security finding", file=sys.stderr)
                    return 1

        return self._run_command(decision.argv)

    def _execute_tier1(self, decision: WrapperDecision) -> int:
        """Execute Tier 1 command: scan + require explicit approval."""
        print(f"[LinuxSecMonitor] TIER 1: Scanning repository before {' '.join(decision.argv)}", file=sys.stderr)

        if not decision.repository or not decision.repository.is_repository:
            print("[LinuxSecMonitor] No repository context found; cannot enforce approval", file=sys.stderr)
            return self._run_command(decision.argv)

        report = self._scan_repository(decision)
        if report.get("coverage_complete") is not True:
            print("[LinuxSecMonitor] BLOCKED: repository inspection is incomplete", file=sys.stderr)
            return 1
        if report.get("malware_findings") or report.get("repository_changed_during_scan"):
            print("[LinuxSecMonitor] BLOCKED: malware detected or repository assessment invalid", file=sys.stderr)
            return 1

        from .approval import ApprovalManager
        from .scanners import repository_content_hash
        approval = ApprovalManager(ttl_seconds=300.0)
        record = approval.request_approval(
            repository_content_hash=str(report["repository_content_hash"]),
            argv=decision.argv,
            working_directory=self.cwd,
            config_hash=self.classifier.get_config_hash(),
            scanner_versions=report.get("scanner_versions", {}),
            malware_db_version=self.classifier.get_malware_db_version(),
            report=report,
        )
        if record is None:
            print("[LinuxSecMonitor] Approval cancelled or unavailable", file=sys.stderr)
            return 3
        if not approval.consume(
            record,
            repository_content_hash=repository_content_hash(decision.repository.root),
            argv=decision.argv,
            working_directory=self.cwd,
            config_hash=self.classifier.get_config_hash(),
            scanner_versions=report.get("scanner_versions", {}),
            malware_db_version=self.classifier.get_malware_db_version(),
        ):
            print("[LinuxSecMonitor] Approval revalidation failed", file=sys.stderr)
            return 1

        return self._run_command(
            decision.argv,
            working_directory=decision.repository.root if self.cwd == Path.cwd() else self.cwd,
        )

    def _scan_repository(self, decision: WrapperDecision) -> dict[str, object]:
        """Use a cached complete assessment or run the bounded scanner set."""
        from .report import build_unified_report
        from .scanners import ScannerOrchestrator

        if decision.cache_key is not None:
            cached = self.cache.get(decision.cache_key)
            if isinstance(cached, dict) and cached.get("coverage_complete") is True:
                return cached

        scanner = ScannerOrchestrator(timeout_seconds=120.0)
        scan = scanner.scan(decision.repository.root)
        report = build_unified_report(scan)
        report["scanner_versions"] = scan.get("scanner_versions", {})
        if report.get("coverage_complete") is True and decision.cache_key is not None:
            self.cache.set(decision.cache_key, report)
        return report

    def _scan_and_warn(self, repo_root: Path) -> None:
        """Compatibility warning helper retained for callers and focused tests."""
        from scanner.repository_scanner import scan_repository
        from scanner.repository_malware_scanner import scan_repository_malware
        from scanner.repository_security_scanner import scan_repository_security

        inventory = scan_repository(repo_root)
        malware = scan_repository_malware(repo_root)
        security = scan_repository_security(repo_root)

        if malware.status == "detected":
            print("[LinuxSecMonitor] WARNING: Malware detected in repository", file=sys.stderr)
        if security.findings:
            print(f"[LinuxSecMonitor] WARNING: {len(security.findings)} security findings in repository", file=sys.stderr)

    def _run_command(self, argv: Sequence[str], working_directory: Optional[Path] = None) -> int:
        """Execute command via trusted executable (no shell, resolved cwd)."""
        try:
            repo_cwd = working_directory if working_directory is not None else self.cwd
            command = argv[0]

            trusted = self.path_manager.resolve_trusted_executable(command)
            if trusted is None:
                print(f"[LinuxSecMonitor] Failed to resolve trusted executable for {command}", file=sys.stderr)
                return 1

            safe_argv = [str(trusted)] + list(argv)[1:]

            # Explicit allowlist environment policy shared with the
            # execution guard (scanner.child_environment). PWD is built from
            # the same cwd passed to the child; PATH is validated trusted
            # system directories; runtime overrides (VIRTUAL_ENV,
            # NPM_CONFIG_PREFIX, CARGO_HOME, ...) are never re-injected.
            env = build_child_environment(cwd=repo_cwd)

            completed = subprocess.run(
                safe_argv,
                cwd=repo_cwd,
                check=False,
                shell=False,
                env=env,
            )
            return completed.returncode
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"[LinuxSecMonitor] Failed to execute command: {exc}", file=sys.stderr)
            return 1

    @staticmethod
    def resolve_executable(command_name: str) -> Optional[str]:
        """Resolve executable to absolute path without trusting PATH for security decisions."""
        if os.path.isabs(command_name):
            return command_name if os.path.isfile(command_name) and os.access(command_name, os.X_OK) else None

        path = shutil.which(command_name)
        return path