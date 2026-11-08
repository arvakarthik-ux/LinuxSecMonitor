"""Content- and command-bound explicit execution approval."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, replace
import io
from pathlib import Path
from typing import BinaryIO, Sequence, TextIO

from scanner.execution_guard import confirm_execution

POLICY_VERSION = "3A.3"


@dataclass(frozen=True)
class ApprovalRecord:
    repository_content_hash: str
    argv: tuple[str, ...]
    working_directory: str
    config_hash: str
    policy_version: str
    scanner_versions: str
    malware_db_version: str
    created_at: float
    expires_at: float
    consumed: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "repository_content_hash": self.repository_content_hash,
            "argv": list(self.argv),
            "working_directory": self.working_directory,
            "config_hash": self.config_hash,
            "policy_version": self.policy_version,
            "scanner_versions": self.scanner_versions,
            "malware_db_version": self.malware_db_version,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "consumed": self.consumed,
        }


class ApprovalManager:
    def __init__(self, *, ttl_seconds: float = 300.0, clock=time.time):
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._record: ApprovalRecord | None = None

    def request_approval(
        self,
        *,
        repository_content_hash: str,
        argv: Sequence[str],
        working_directory: str | Path,
        config_hash: str,
        scanner_versions: object,
        malware_db_version: str,
        report: dict[str, object] | None = None,
        terminal: TextIO | BinaryIO | None = None,
    ) -> ApprovalRecord | None:
        if not repository_content_hash or not argv or report and (
            report.get("coverage_complete") is not True
            or report.get("repository_changed_during_scan") is True
            or report.get("malware_findings")
        ):
            return None
        if not self._confirm(terminal):
            return None
        now = self.clock()
        scanner_json = json.dumps(scanner_versions, sort_keys=True, separators=(",", ":"),
                                   default=str) if not isinstance(scanner_versions, str) else scanner_versions
        record = ApprovalRecord(
            repository_content_hash=repository_content_hash,
            argv=tuple(argv),
            working_directory=str(Path(working_directory).resolve(strict=False)),
            config_hash=config_hash,
            policy_version=POLICY_VERSION,
            scanner_versions=scanner_json,
            malware_db_version=malware_db_version,
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        self._record = record
        return record

    @staticmethod
    def _confirm(terminal: TextIO | BinaryIO | None) -> bool:
        if terminal is not None and isinstance(terminal, io.StringIO):
            try:
                answer = terminal.readline()
            except (EOFError, KeyboardInterrupt, OSError):
                return False
            return answer.removesuffix("\n").removesuffix("\r") == "RUN"
        return confirm_execution(terminal)

    def validate(self, record: object, *, repository_content_hash: str,
                 argv: Sequence[str], working_directory: str | Path,
                 config_hash: str, scanner_versions: object,
                 malware_db_version: str) -> bool:
        if not isinstance(record, ApprovalRecord) or record.consumed:
            return False
        scanner_json = json.dumps(scanner_versions, sort_keys=True, separators=(",", ":"),
                                   default=str) if not isinstance(scanner_versions, str) else scanner_versions
        if self.clock() >= record.expires_at:
            return False
        expected = (
            record.repository_content_hash == repository_content_hash,
            record.argv == tuple(argv),
            record.working_directory == str(Path(working_directory).resolve(strict=False)),
            record.config_hash == config_hash,
            record.policy_version == POLICY_VERSION,
            record.scanner_versions == scanner_json,
            record.malware_db_version == malware_db_version,
        )
        return all(expected)

    def consume(self, record: object, **identity: object) -> bool:
        if not self.validate(record, **identity):
            return False
        self._record = replace(record, consumed=True)
        return True
