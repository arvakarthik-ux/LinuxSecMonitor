"""Unified, redacted repository security reports."""

from __future__ import annotations

import json
import re
from typing import Any

SECRET_PATTERNS = (
    re.compile(r"(?i)\b(api[_-]?key|token|password|secret|authorization|cookie)\b\s*[:=]\s*[\"']?[^\s\"',;]+"),
    re.compile(r"(?i)\b(BEARER\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
)


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, str):
        redacted = value
        for pattern in SECRET_PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, dict):
        return {str(key): redact_sensitive(item) for key, item in value.items()}
    return value


def classify_severity(finding: dict[str, Any]) -> str:
    explicit = str(finding.get("severity", "")).upper()
    if explicit in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return explicit
    score = finding.get("confidence_score", finding.get("confidence", 0))
    try:
        if float(score) >= 0.9:
            return "HIGH"
        if float(score) >= 0.7:
            return "MEDIUM"
    except (TypeError, ValueError):
        pass
    return "LOW"


def build_unified_report(scan: dict[str, Any]) -> dict[str, Any]:
    malware = scan.get("malware", {}) or {}
    detections = malware.get("detections", []) or []
    security = scan.get("security", {}) or {}
    security_findings = security.get("findings", []) or []

    malware_findings = []
    for detection in detections:
        item = detection.to_dict() if hasattr(detection, "to_dict") else dict(detection)
        malware_findings.append({
            "kind": "confirmed_malware",
            "name": item.get("name", "Unknown"),
            "severity": "CRITICAL",
            "confidence": "confirmed",
            "path": item.get("path"),
        })

    findings = list(malware_findings)
    for finding in security_findings:
        item = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        findings.append({
            "kind": "security",
            "rule_id": item.get("rule_id"),
            "severity": classify_severity(item),
            "confidence": item.get("confidence", "heuristic"),
            "path": item.get("path"),
            "line_number": item.get("line_number"),
            "evidence": item.get("evidence"),
            "explanation": item.get("explanation"),
        })

    scanner_status = {}
    for name in ("inventory", "malware", "security"):
        result = scan.get(name, {}) or {}
        scanner_status[name] = {
            "status": result.get("status", "error"),
            "coverage_complete": result.get("coverage_complete") is True,
            "errors": result.get("errors", []),
        }

    report = {
        "repository": scan.get("repository"),
        "repository_content_hash": scan.get("repository_content_hash"),
        "scanner_status": scanner_status,
        "malware_findings": malware_findings,
        "security_findings": findings[len(malware_findings):],
        "findings": findings,
        "scanner_errors": {
            name: status["errors"] for name, status in scanner_status.items() if status["errors"]
        },
        "coverage_complete": scan.get("coverage_complete") is True,
        "coverage_limitations": [
            *(malware.get("limitations", []) or []),
            *((scan.get("security", {}) or {}).get("limitations", []) or []),
            *((scan.get("inventory", {}) or {}).get("limitations", []) or []),
        ],
        "repository_changed_during_scan": scan.get("repository_changed_during_scan", False),
        "scan_duration_seconds": scan.get("scan_duration_seconds", 0),
    }
    return redact_sensitive(report)


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(redact_sensitive(report), indent=2, sort_keys=True)


def render_terminal(report: dict[str, Any]) -> str:
    lines = [
        "LinuxSecMonitor repository security report",
        f"Repository: {report.get('repository')}",
        f"Content hash: {report.get('repository_content_hash')}",
        f"Coverage complete: {report.get('coverage_complete')}",
        f"Scan duration: {report.get('scan_duration_seconds')} seconds",
    ]
    for finding in report.get("findings", []):
        location = finding.get("path", "")
        if finding.get("line_number") is not None:
            location += f":{finding['line_number']}"
        lines.append(f"- [{finding.get('severity', 'LOW')}] {finding.get('kind')}: {location}")
    for error in report.get("scanner_errors", {}).values():
        lines.extend(f"ERROR: {item}" for item in error)
    if report.get("repository_changed_during_scan"):
        lines.append("BLOCKED: repository content changed during scanning")
    return "\n".join(lines)
