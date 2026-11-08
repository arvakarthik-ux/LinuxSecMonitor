"""Tests for explicit user-mediated repository execution review."""

from __future__ import annotations

import json
import os
import pwd
import sys
from pathlib import Path
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


class _BinaryTerminal:
    """Binary unbuffered terminal double for testing non-seekable I/O."""
    def __init__(self, answer: bytes):
        self.answer = answer
        self.output = b""
        self._closed = False

    def write(self, value: bytes) -> int:
        self.output += value
        return len(value)

    def flush(self) -> None:
        return None

    def readline(self) -> bytes:
        return self.answer

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def mode(self) -> str:
        return "r+b"


class _SelectableBinaryTerminal(_BinaryTerminal):
    """Binary terminal with a selectable file descriptor for timeout testing."""
    def fileno(self) -> int:
        return 42


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


def test_confirm_execution_binary_terminal_success():
    """Test successful RUN approval with binary unbuffered terminal."""
    terminal = _BinaryTerminal(b"RUN\n")
    assert execution_guard.confirm_execution(terminal) is True
    assert b"RUN to start" in terminal.output


def test_confirm_execution_binary_terminal_rejects_lowercase():
    """Test that lowercase 'run' is rejected with binary terminal."""
    terminal = _BinaryTerminal(b"run\n")
    assert execution_guard.confirm_execution(terminal) is False


def test_confirm_execution_binary_terminal_rejects_trailing_space():
    """Test that 'RUN ' with trailing space is rejected with binary terminal."""
    terminal = _BinaryTerminal(b"RUN \n")
    assert execution_guard.confirm_execution(terminal) is False


def test_confirm_execution_binary_terminal_rejects_empty():
    """Test that empty input is rejected with binary terminal."""
    terminal = _BinaryTerminal(b"\n")
    assert execution_guard.confirm_execution(terminal) is False


def test_confirm_execution_binary_terminal_eof():
    """Test that EOF is rejected with binary terminal."""
    terminal = _BinaryTerminal(b"")
    assert execution_guard.confirm_execution(terminal) is False


def test_confirm_execution_binary_terminal_timeout(monkeypatch):
    """Test that binary terminal times out correctly."""
    terminal = _SelectableBinaryTerminal(b"RUN\n")
    calls = []
    monkeypatch.setattr(
        execution_guard.select, "select",
        lambda readers, writers, errors, timeout: (calls.append(timeout) or ([], [], [])),
    )
    assert execution_guard.confirm_execution(terminal) is False
    assert calls == [300]


def test_confirm_execution_binary_terminal_no_fileno():
    """Test binary terminal without fileno falls back to synchronous read."""
    class NoFilenoBinaryTerminal(_BinaryTerminal):
        def fileno(self):
            raise OSError("no fileno")

    terminal = NoFilenoBinaryTerminal(b"RUN\n")
    assert execution_guard.confirm_execution(terminal) is True


def test_confirm_execution_binary_terminal_keyboard_interrupt():
    """Test that KeyboardInterrupt is handled with binary terminal."""
    class InterruptedBinaryTerminal(_BinaryTerminal):
        def readline(self):
            raise KeyboardInterrupt

    assert execution_guard.confirm_execution(InterruptedBinaryTerminal(b"")) is False


def test_confirm_execution_binary_terminal_cleanup_on_error(monkeypatch):
    """Test terminal cleanup when an error occurs during prompt."""
    class ErrorBinaryTerminal(_BinaryTerminal):
        def write(self, value):
            raise OSError("write failed")

    terminal = ErrorBinaryTerminal(b"RUN\n")
    assert execution_guard.confirm_execution(terminal) is False


def test_run_reviewed_command_with_binary_terminal_success(tmp_path):
    """Test full run_reviewed_command with binary terminal approval."""
    report = _review()
    terminal = _BinaryTerminal(b"RUN\n")
    marker = tmp_path / "approved-marker"
    result = execution_guard.run_reviewed_command(
        report,
        tmp_path,
        [sys.executable, "-c", f"from pathlib import Path; Path({json.dumps(str(marker))}).touch()"],
        terminal=terminal,
    )
    assert result == 0
    assert marker.is_file()
    assert report["command_status"] == "completed"
    assert terminal.closed is False  # function doesn't close passed-in terminal


def test_run_reviewed_command_with_binary_terminal_rejection(tmp_path):
    """Test full run_reviewed_command with binary terminal rejection."""
    report = _review()
    terminal = _BinaryTerminal(b"no\n")
    marker = tmp_path / "approved-marker"
    result = execution_guard.run_reviewed_command(
        report,
        tmp_path,
        [sys.executable, "-c", f"from pathlib import Path; Path({json.dumps(str(marker))}).touch()"],
        terminal=terminal,
    )
    assert result == 3
    assert not marker.exists()
    assert report["command_status"] == "cancelled"


def test_run_reviewed_command_blocks_on_invalid_empty_command(tmp_path):
    """Test that run_reviewed_command blocks on empty command list."""
    report = _review()
    result = execution_guard.run_reviewed_command(report, tmp_path, [])
    assert result == 1
    assert report["command_status"] == "invalid_command"


def test_run_reviewed_command_blocks_on_invalid_non_string_args(tmp_path):
    """Test that run_reviewed_command blocks on non-string command arguments."""
    report = _review()
    result = execution_guard.run_reviewed_command(report, tmp_path, ["valid", 123, "also_valid"])
    assert result == 1
    assert report["command_status"] == "invalid_command"


def test_run_reviewed_command_blocks_on_invalid_empty_string_args(tmp_path):
    """Test that run_reviewed_command blocks on empty string arguments."""
    report = _review()
    result = execution_guard.run_reviewed_command(report, tmp_path, ["valid", "", "also_valid"])
    assert result == 1
    assert report["command_status"] == "invalid_command"


def test_run_reviewed_command_handles_oserror_error_type_from_runner(tmp_path):
    """Test that run_reviewed_command handles OSError from runner."""
    report = _review()

    def failing_runner(command, **kwargs):
        raise OSError("runner failed")

    result = execution_guard.run_reviewed_command(
        report, tmp_path, ["true"], terminal=_Terminal("RUN\n"), runner=failing_runner
    )
    assert result == 1
    assert report["command_status"] == "error"
    assert report["command_error_type"] == "OSError"


def test_run_reviewed_command_handles_runtimeerror_error_type_from_runner(tmp_path):
    """Test that run_reviewed_command handles RuntimeError from runner."""
    report = _review()

    def failing_runner(command, **kwargs):
        raise RuntimeError("runner failed")

    result = execution_guard.run_reviewed_command(
        report, tmp_path, ["true"], terminal=_Terminal("RUN\n"), runner=failing_runner
    )
    assert result == 1
    assert report["command_status"] == "error"
    assert report["command_error_type"] == "RuntimeError"


def test_run_reviewed_command_handles_valueerror_error_type_from_runner(tmp_path):
    """Test that run_reviewed_command handles ValueError from runner."""
    report = _review()

    def failing_runner(command, **kwargs):
        raise ValueError("runner failed")

    result = execution_guard.run_reviewed_command(
        report, tmp_path, ["true"], terminal=_Terminal("RUN\n"), runner=failing_runner
    )
    assert result == 1
    assert report["command_status"] == "error"
    assert report["command_error_type"] == "ValueError"


def test_run_reviewed_command_passes_explicit_child_environment(
    tmp_path, monkeypatch
):
    """The reviewed command must run in the allowlist child environment."""
    monkeypatch.setenv("LD_PRELOAD", "/evil.so")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/evil/gitconfig")
    monkeypatch.setenv("PYTHONPATH", "/evil/py")
    monkeypatch.setenv("BASH_ENV", "/evil/bashenv")
    before_environ = dict(os.environ)

    captured = {}

    def runner(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return SimpleNamespace(returncode=0)

    report = _review()
    result = execution_guard.run_reviewed_command(
        report,
        tmp_path,
        ["tool", "arg"],
        terminal=_Terminal("RUN\n"),
        runner=runner,
    )
    assert result == 0

    # Exact argv list, no shell, explicit environment.
    assert captured["command"] == ["tool", "arg"]
    assert captured["shell"] is False
    child_env = captured["env"]
    assert isinstance(child_env, dict)

    # The injected dangerous variables must not reach the child.
    for dangerous_key in ("LD_PRELOAD", "GIT_CONFIG_GLOBAL", "PYTHONPATH", "BASH_ENV"):
        assert dangerous_key not in child_env

    # PATH is the trusted policy PATH (parent PATH would be /evil entries).
    for entry in child_env["PATH"].split(":"):
        assert os.path.isabs(entry)
        assert os.stat(entry).st_uid == 0
        assert not os.stat(entry).st_mode & 0o022
    assert child_env["HOME"] == pwd.getpwuid(os.geteuid()).pw_dir
    assert child_env["PWD"] == os.fspath(Path(tmp_path).resolve(strict=True))
    assert child_env["SHELL"] == "/bin/sh"

    # cwd is the resolved repository directory.
    assert captured["cwd"] == os.fspath(Path(tmp_path).resolve(strict=True))

    # The parent environment is untouched.
    assert dict(os.environ) == before_environ
    assert os.environ["LD_PRELOAD"] == "/evil.so"


def test_report_does_not_include_command_arguments_or_secrets():
    """Test that report does not leak command arguments or secret values."""
    report = _review()
    # Run with a command that has secret-like values
    execution_guard.run_reviewed_command(
        report, "/repo", ["cmd", "secret-value", "password=123"],
        terminal=_Terminal("CANCEL\n"),
    )
    report_str = str(report)
    # The report should have command_status and command_returncode fields but NOT the actual command arguments
    assert "secret-value" not in report_str
    assert "password=123" not in report_str
    # Command arguments should not be serialized in the report
    assert "cmd" not in report_str or report_str.count("cmd") == 0
