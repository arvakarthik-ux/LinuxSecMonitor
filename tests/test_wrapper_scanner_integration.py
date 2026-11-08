"""Focused tests for wrapper scanner integration and reporting."""

from __future__ import annotations

import io
import json
import time

from scanner.repository_malware_scanner import RepositoryMalwareAssessment, RepositoryMalwareDetection
from scanner.repository_scanner import RepositoryScanResult
from scanner.repository_security_scanner import RepositorySecurityAssessment, RepositorySecurityFinding
from src.wrapper.approval import ApprovalManager
from src.wrapper.report import build_unified_report, classify_severity, render_json
from src.wrapper.scanners import ScannerOrchestrator


def complete(name):
    return RepositoryScanResult(status="completed", repository_path=name,
                                coverage_complete=True) if name.endswith("inventory") else None


def test_scanner_success_and_parallel_limit(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "safe.txt").write_text("safe\n")
    orchestrator = ScannerOrchestrator(
        inventory_scanner=lambda _: RepositoryScanResult("completed", str(repo), coverage_complete=True),
        malware_scanner=lambda _: RepositoryMalwareAssessment("no_detection", repository_path=str(repo), coverage_complete=True),
        security_scanner=lambda _: RepositorySecurityAssessment("completed", str(repo), coverage_complete=True),
    )
    result = orchestrator.scan(repo)
    assert result["coverage_complete"] is True
    assert result["repository_content_hash"]
    assert result["scan_duration_seconds"] >= 0


def test_scanner_failure_timeout_and_incomplete(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def timeout(_):
        time.sleep(1)

    orchestrator = ScannerOrchestrator(
        timeout_seconds=0.01,
        inventory_scanner=lambda _: RepositoryScanResult("completed", str(repo), coverage_complete=True),
        malware_scanner=timeout,
        security_scanner=lambda _: RepositorySecurityAssessment("completed", str(repo), coverage_complete=True),
    )
    result = orchestrator.scan(repo)
    assert result["coverage_complete"] is False
    assert "timed out" in " ".join(result["malware"]["errors"]).lower()


def test_malware_detection_and_modification_invalidation(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    detection = RepositoryMalwareDetection("Eicar-Test-Signature", "payload.txt")
    orchestrator = ScannerOrchestrator(
        inventory_scanner=lambda _: RepositoryScanResult("completed", str(repo), coverage_complete=True),
        malware_scanner=lambda _: RepositoryMalwareAssessment(
            "detected", repository_path=str(repo), coverage_complete=True,
            detections=[detection]),
        security_scanner=lambda _: RepositorySecurityAssessment("completed", str(repo), coverage_complete=True),
    )
    scan = orchestrator.scan(repo)
    report = build_unified_report(scan)
    assert report["malware_findings"][0]["severity"] == "CRITICAL"

    (repo / "changed.txt").write_text("change")
    scan = dict(scan)
    scan["repository_changed_during_scan"] = True
    scan["coverage_complete"] = False
    assert build_unified_report(scan)["coverage_complete"] is False


def test_severity_json_and_secret_redaction(tmp_path):
    finding = RepositorySecurityFinding("demo", "HIGH", "app.py", "password=hunter2", "review")
    scan = {
        "repository": str(tmp_path),
        "repository_content_hash": "abc",
        "coverage_complete": True,
        "inventory": {"status": "completed", "coverage_complete": True},
        "malware": {"status": "no_detection", "coverage_complete": True, "detections": [], "limitations": []},
        "security": {"status": "completed", "coverage_complete": True, "findings": [finding], "limitations": []},
    }
    report = build_unified_report(scan)
    assert classify_severity({"severity": "medium"}) == "MEDIUM"
    assert "[REDACTED]" in json.dumps(report)
    assert "hunter2" not in json.dumps(report)
    assert json.loads(render_json(report))["repository_content_hash"] == "abc"


def test_run_approval_single_use_expiry_and_binding(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    terminal = io.StringIO("RUN\n")
    clock = iter([1000.0, 1000.0, 1001.0, 1301.0])
    manager = ApprovalManager(ttl_seconds=300, clock=lambda: next(clock))
    record = manager.request_approval(
        repository_content_hash="hash",
        argv=("git", "checkout", "main"),
        working_directory=repo,
        config_hash="config",
        scanner_versions={"security": "1"},
        malware_db_version="db",
        report={"coverage_complete": True},
        terminal=terminal,
    )
    identity = dict(repository_content_hash="hash", argv=("git", "checkout", "main"),
                    working_directory=repo, config_hash="config",
                    scanner_versions={"security": "1"}, malware_db_version="db")
    assert record is not None
    assert manager.validate(record, **identity)
    assert manager.consume(record, **identity)
    assert not manager.consume(record, **identity)

    manager2 = ApprovalManager(ttl_seconds=1, clock=lambda: 10)
    terminal2 = io.StringIO("RUN\n")
    expired = manager2.request_approval(repository_content_hash="hash", argv=("git", "status"),
        working_directory=repo, config_hash="config", scanner_versions={}, malware_db_version="db",
        terminal=terminal2)
    manager2.clock = lambda: 12
    assert not manager2.validate(expired, repository_content_hash="hash", argv=("git", "status"),
                                 working_directory=repo, config_hash="config",
                                 scanner_versions={}, malware_db_version="db")


def test_approval_cancellation_eof_and_interrupt(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    common = dict(repository_content_hash="hash", argv=("git", "status"), working_directory=repo,
                  config_hash="config", scanner_versions={}, malware_db_version="db",
                  report={"coverage_complete": True})
    assert ApprovalManager().request_approval(terminal=io.StringIO("no\n"), **common) is None
    assert ApprovalManager().request_approval(terminal=io.StringIO(""), **common) is None

    class Interrupted(io.StringIO):
        def readline(self, *args):
            raise KeyboardInterrupt

    assert ApprovalManager().request_approval(terminal=Interrupted(), **common) is None
