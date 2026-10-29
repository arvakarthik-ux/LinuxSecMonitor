"""User-mediated repository review before starting an explicit command.

This is a convenience gate, not a sandbox or an interception mechanism. A
caller can still run the command directly or change repository contents after
review, so this module must never describe its scan as a safety guarantee.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Sequence, TextIO

from .repository_malware_scanner import scan_repository_malware
from .repository_scanner import scan_repository
from .repository_security_scanner import scan_repository_security


def review_repository_for_execution(
    repository: str | Path,
    *,
    include_generated: bool = False,
    inventory_scanner: Callable = scan_repository,
    malware_scanner: Callable = scan_repository_malware,
    security_scanner: Callable = scan_repository_security,
) -> dict[str, object]:
    """Run the repository assessments and return a fail-closed review report."""
    def stage(name: str, operation: Callable) -> dict[str, object]:
        try:
            result = operation().to_dict()
            if isinstance(result, dict):
                return result
            raise TypeError("assessment serialization was not an object")
        except Exception as exc:
            # Preserve the failure category without serializing arbitrary
            # exception text that could contain paths or sensitive values.
            return {
                "status": "error",
                "coverage_complete": False,
                "errors": [f"{name} failed ({type(exc).__name__})."],
            }

    inventory = stage("Repository inventory", lambda: inventory_scanner(repository))
    malware = stage("Repository malware scan", lambda: malware_scanner(repository))
    security = stage(
        "Repository static review",
        lambda: security_scanner(repository, include_generated=include_generated),
    )

    coverage_complete = (
        inventory.get("coverage_complete") is True
        and malware.get("coverage_complete") is True
        and malware.get("status") in {"no_detection", "detected"}
        and security.get("coverage_complete") is True
        and security.get("status") in {"completed", "requires_review"}
    )
    findings_present = bool(malware.get("detections")) or bool(security.get("findings"))
    if not coverage_complete:
        review_status = "blocked_incomplete"
    elif malware.get("status") == "detected":
        review_status = "blocked_detection"
    elif findings_present:
        review_status = "review_required"
    else:
        review_status = "review_complete"

    return {
        "review_status": review_status,
        "coverage_complete": coverage_complete,
        "command_status": "not_started",
        "command_returncode": None,
        "inventory": inventory,
        "malware_assessment": malware,
        "repository_security_assessment": security,
        "limitations": [
            "This review is advisory and does not sandbox the command.",
            "Repository contents may change after scanning; concurrent writers are not controlled.",
            "Commands run directly can bypass this wrapper.",
        ],
    }


def confirm_execution(terminal: TextIO | None = None) -> bool:
    """Require an exact interactive RUN confirmation; fail closed without a TTY."""
    opened = None
    try:
        if terminal is None:
            opened = open("/dev/tty", "r+", encoding="utf-8", errors="replace")
            terminal = opened
        terminal.write("Review complete. Type exactly RUN to start the command: ")
        terminal.flush()
        answer = terminal.readline()
        return answer.removesuffix("\n").removesuffix("\r") == "RUN"
    except (OSError, EOFError, KeyboardInterrupt):
        return False
    finally:
        if opened is not None:
            opened.close()


def run_reviewed_command(
    report: dict[str, object],
    repository: str | Path,
    command: Sequence[str],
    *,
    terminal: TextIO | None = None,
    runner: Callable = subprocess.run,
    json_output: bool = False,
) -> int:
    """Prompt and run an argv command only after complete repository review."""
    if not command or any(not isinstance(item, str) or not item for item in command):
        report["command_status"] = "invalid_command"
        return 1
    if report.get("coverage_complete") is not True:
        report["command_status"] = "blocked_incomplete"
        return 1
    if report.get("review_status") == "blocked_detection":
        report["command_status"] = "blocked_detection"
        return 1
    if not confirm_execution(terminal):
        report["command_status"] = "cancelled"
        return 3

    try:
        output_streams = (
            {"stdout": sys.stderr, "stderr": sys.stderr}
            if json_output else {}
        )
        completed = runner(
            list(command),
            cwd=os.fspath(Path(repository).expanduser().resolve(strict=True)),
            check=False,
            shell=False,
            **output_streams,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        # Do not serialize exception strings: they can contain a command path
        # or other user-supplied data. The detailed cause is available locally.
        report["command_status"] = "error"
        report["command_error_type"] = type(exc).__name__
        return 1

    returncode = completed.returncode
    report["command_returncode"] = returncode
    report["command_status"] = "completed" if returncode == 0 else "failed"
    if returncode is None:
        return 1
    if returncode < 0:
        return min(255, 128 + abs(returncode))
    return min(255, returncode)
