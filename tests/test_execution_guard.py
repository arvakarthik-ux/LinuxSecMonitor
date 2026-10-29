"""Tests for explicit user-mediated repository execution review."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from scanner import execution_guard


def _assessment(**values):
    return SimpleNamespace(to_dict=lambda: dict(values))


class _Terminal:
    def __init__(self, answer):
        self.answer = answer
        self.output = ""

    def write(self, value):
        self.output += value
        return len(value)

    def flush(self):
        pass

    def readline(self):
        return self.answer


def _review(*, security_findings=None, malware_status="no_detection", coverage=True):
    return execution_guard.review_repository_for_execution(
        "/repo",
        inventory_scanner=lambda path: _assessment(
            coverage_complete=coverage, status="completed",
        ),
        malware_scanner=lambda path: _assessment(
            coverage_complete=coverage,
            status=malware_status,
            detections=[{"name": "fixture", "path": "file"}] if malware_status == "detected" else [],
        ),
        security_scanner=lambda path, include_generated: _assessment(
            coverage_complete=coverage,
            status="requires_review" if security_findings else "completed",
            findings=security_findings or [],
        ),
    )


def test_complete_clean_review_is_reported_as_complete():
    report = _review()
    assert report["review_status"] == "review_complete"
    assert report["coverage_complete"] is True
    assert report["command_status"] == "not_started"


def test_static_review_lead_requires_review_but_can_be_confirmed():
    finding = {"rule_id": "test-lead"}
    report = _review(security_findings=[finding])
    assert report["review_status"] == "review_required"
    assert report["coverage_complete"] is True


@pytest.mark.parametrize(
    ("malware_status", "coverage", "expected"),
    [("error", False, "blocked_incomplete"), ("detected", True, "blocked_detection")],
)
def test_incomplete_or_detected_review_is_blocked(malware_status, coverage, expected):
    report = _review(malware_status=malware_status, coverage=coverage)
    assert report["review_status"] == expected


def test_scanner_exception_becomes_incomplete_report_without_exception_text():
    report = execution_guard.review_repository_for_execution(
        "/repo",
        inventory_scanner=lambda path: (_ for _ in ()).throw(OSError("private path detail")),
        malware_scanner=lambda path: _assessment(coverage_complete=True, status="no_detection", detections=[]),
        security_scanner=lambda path, include_generated: _assessment(
            coverage_complete=True, status="completed", findings=[],
        ),
    )
    assert report["review_status"] == "blocked_incomplete"
    assert "private path detail" not in str(report)
    assert "OSError" in str(report)


def test_cancellation_does_not_start_marker_command(tmp_path):
    marker = tmp_path / "cancelled-marker"
    report = _review()
    result = execution_guard.run_reviewed_command(
        report,
        tmp_path,
        [sys.executable, "-c", f"from pathlib import Path; Path({json.dumps(str(marker))}).touch()"],
        terminal=_Terminal("CANCEL\n"),
    )
    assert result == 3
    assert report["command_status"] == "cancelled"
    assert not marker.exists()


def test_exact_approval_runs_argv_without_shell_and_creates_marker(tmp_path):
    marker = tmp_path / "approved-marker"
    report = _review()
    result = execution_guard.run_reviewed_command(
        report,
        tmp_path,
        [sys.executable, "-c", f"from pathlib import Path; Path({json.dumps(str(marker))}).touch()"],
        terminal=_Terminal("RUN\n"),
    )
    assert result == 0
    assert marker.is_file()
    assert report["command_status"] == "completed"
    assert report["command_returncode"] == 0


def test_json_command_output_is_routed_away_from_json_stdout(tmp_path):
    report = _review()
    captured = {}

    def runner(command, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0)

    result = execution_guard.run_reviewed_command(
        report,
        tmp_path,
        ["tool", "arg"],
        terminal=_Terminal("RUN\n"),
        runner=runner,
        json_output=True,
    )
    assert result == 0
    assert captured["shell"] is False
    assert captured["stdout"] is sys.stderr
    assert captured["stderr"] is sys.stderr


def test_incomplete_scan_blocks_even_after_confirmation_attempt(tmp_path, monkeypatch):
    report = _review(coverage=False)
    monkeypatch.setattr(
        execution_guard, "confirm_execution",
        lambda terminal=None: pytest.fail("incomplete scan must not prompt"),
    )
    result = execution_guard.run_reviewed_command(report, tmp_path, ["true"])
    assert result == 1
    assert report["command_status"] == "blocked_incomplete"


def test_malware_detection_blocks_even_with_complete_coverage(tmp_path, monkeypatch):
    report = _review(malware_status="detected")
    monkeypatch.setattr(
        execution_guard, "confirm_execution",
        lambda terminal=None: pytest.fail("signature detection must not prompt"),
    )
    result = execution_guard.run_reviewed_command(report, tmp_path, ["true"])
    assert result == 1
    assert report["command_status"] == "blocked_detection"


def test_run_fails_closed_without_tty(monkeypatch):
    monkeypatch.setattr(
        "builtins.open", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("no tty")),
    )
    assert execution_guard.confirm_execution(terminal=None) is False


def test_report_does_not_include_command_arguments():
    report = _review()
    assert "command" not in report
    assert "secret-value" not in str(report)
