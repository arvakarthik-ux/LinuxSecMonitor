"""Command-line entry point for LinuxSecMonitor Sprint 1."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from time import perf_counter
from typing import Callable, TextIO, TypeVar

from scanner import collect_system_info, scan_installed_packages
from scanner.apt_hook import run_apt_preinstall_hook
from scanner.apt_lifecycle import (
    LifecycleError,
    disable_apt_hook,
    enable_apt_hook,
    install_apt_hook,
    integration_status,
    uninstall_apt_hook,
    validate_effective_hook_order,
    validate_trusted_runtime,
)
from scanner.diagnostics import collect_diagnostics
from scanner.execution_guard import review_repository_for_execution, run_reviewed_command
from scanner.malware_scanner import MAX_PACKAGE_BYTES, MalwareAssessment, scan_deb
from scanner.package_scanner import Package
from scanner.repository_scanner import scan_repository
from scanner.repository_malware_scanner import scan_repository_malware
from scanner.repository_security_scanner import scan_repository_security
from scanner.vulnerability_assessment import assess_packages

T = TypeVar("T")
DiagnosticCallback = Callable[[str], None]
DETAILS_PREVIEW_LIMIT = 240
REPOSITORY_MANIFEST_PREVIEW_LIMIT = 20
REPOSITORY_SECURITY_FINDING_PREVIEW_LIMIT = 20
_SYSTEM_COMMAND_PATHS = {
    "apt-get": "/usr/bin/apt-get",
    "sudo": "/usr/bin/sudo",
    "chgrp": "/usr/bin/chgrp",
    "chmod": "/usr/bin/chmod",
}


def _find_system_command(name: str) -> str | None:
    """Find an expected system command without trusting the caller's PATH."""
    path = _SYSTEM_COMMAND_PATHS.get(name)
    if path is None:
        return None
    try:
        return path if Path(path).is_file() and os.access(path, os.X_OK) else None
    except OSError:
        return None


def _diagnose(callback: DiagnosticCallback | None, message: str) -> None:
    """Send optional progress details through the caller's stderr callback."""
    if callback is not None:
        try:
            callback(message)
        except Exception:
            # A closed diagnostic stream must not change a scan result.
            pass


def _run_timed_stage(
    name: str, operation: Callable[[], T], diagnostic: DiagnosticCallback | None,
) -> T:
    """Run one operation with optional start, elapsed, and failure diagnostics."""
    if diagnostic is None:
        return operation()
    started = perf_counter()
    _diagnose(diagnostic, f"{name} started.")
    try:
        result = operation()
    except Exception as exc:
        _diagnose(
            diagnostic,
            f"{name} failed in {perf_counter() - started:.3f}s "
            f"({type(exc).__name__}); see the raised exception for details.",
        )
        raise
    _diagnose(diagnostic, f"{name} completed in {perf_counter() - started:.3f}s.")
    return result


def build_result(diagnostic: DiagnosticCallback | None = None) -> dict[str, object]:
    """Collect system and package data in a JSON-ready result structure."""
    system = _run_timed_stage("System information collection", collect_system_info, diagnostic)
    system_info = system.to_dict()
    _diagnose(
        diagnostic,
        f"Detected distribution={system_info.get('distribution') or 'unknown'}, "
        f"release={system_info.get('distribution_version') or 'unknown'}.",
    )
    package_scan_result = _run_timed_stage("Package inventory", scan_installed_packages, diagnostic)
    package_scan = package_scan_result.to_dict()
    if diagnostic is not None:
        _diagnose(
            diagnostic,
            f"Package inventory result: success={package_scan_result.success}, "
            f"package_entries={len(package_scan_result.packages)}"
            + ("; see the report for the scan error." if package_scan_result.error else "."),
        )
    if package_scan_result.success:
        assessment_args = (
            package_scan_result.packages,
            system_info.get("distribution"),
            system_info.get("distribution_version"),
        )
        assessment = (
            assess_packages(*assessment_args, diagnostic=diagnostic)
            if diagnostic is not None else assess_packages(*assessment_args)
        )
        vulnerability_assessment = assessment.to_dict()
    else:
        vulnerability_assessment = {
            "assessment_status": "error",
            "distribution": system_info.get("distribution"),
            "release": system_info.get("distribution_version"),
            "source": None,
            "error": "Vulnerability assessment was not run because package inventory failed.",
            "packages": [],
            "advisory_context": {},
            "summary": {
                "total_assessed_packages": 0,
                "status_counts": {},
                "no_known_match_is_safe": False,
                "no_known_match_note": (
                    "no_known_match means no matching record was found in the queried data; "
                    "it is not proof that a package is safe."
                ),
            },
        }
    return {
        "system_info": system_info,
        "package_scan": package_scan,
        "vulnerability_assessment": vulnerability_assessment,
    }


def _render_text(result: dict[str, object]) -> str:
    """Format a concise human-readable report."""
    system = result["system_info"]
    package_scan = result["package_scan"]
    assert isinstance(system, dict) and isinstance(package_scan, dict)
    packages = package_scan["packages"]
    assert isinstance(packages, list)
    lines = ["LinuxSecMonitor — Sprint 1", "System information:"]
    labels = {
        "operating_system": "Operating system", "distribution": "Distribution",
        "distribution_version": "Distribution version", "kernel_version": "Kernel",
        "architecture": "Architecture", "python_version": "Python", "hostname": "Hostname",
    }
    lines.extend(f"  {label}: {system.get(key) or 'Unavailable'}" for key, label in labels.items())
    lines.append("Package inventory:")
    if package_scan["success"]:
        lines.append(f"  Total packages found: {len(packages)}")
        lines.extend(f"  {p['name']} {p['version']}" for p in packages[:10])
        if not packages:
            lines.append("  No installed packages were returned.")
        elif len(packages) > 10:
            lines.append(f"  … and {len(packages) - 10} more")
    else:
        lines.append(f"  Scan failed: {package_scan['error']}")
        if packages:
            lines.append(
                f"  Partial inventory: {len(packages)} package(s) retained; "
                "this is not a complete inventory."
            )
            lines.extend(f"  {p['name']} {p['version']}" for p in packages[:10])
            if len(packages) > 10:
                lines.append(f"  … and {len(packages) - 10} more")
    assessment = result.get("vulnerability_assessment")
    if isinstance(assessment, dict):
        lines.append("Vulnerability assessment:")
        lines.append(f"  Status: {assessment.get('assessment_status', 'Unavailable')}")
        if assessment.get("distribution"):
            lines.append(f"  Distribution: {assessment['distribution']}")
        if assessment.get("release"):
            lines.append(f"  Release: {assessment['release']}")
        if assessment.get("source"):
            lines.append(f"  Source: {assessment['source']}")
        if assessment.get("error"):
            lines.append(f"  Details: {assessment['error']}")
        else:
            lines.append(f"  Details: {assessment.get('explanation', 'See per-package assessments in JSON output.')}")
        assessed = assessment.get("packages", [])
        if isinstance(assessed, list):
            summary = assessment.get("summary")
            # Render counts from the entries themselves so a stale or partial
            # summary cannot contradict the detailed package assessments.
            total = len(assessed)
            counts = {}
            for item in assessed:
                status = (
                    item.get("assessment_status", "unknown")
                    if isinstance(item, dict) else "unknown"
                )
                counts[status] = counts.get(status, 0) + 1
            lines.append(f"  Total assessed package entries: {total}")
            if isinstance(counts, dict):
                lines.append("  Package assessment counts:")
                if counts:
                    lines.extend(f"    {status}: {count}" for status, count in sorted(counts.items()))
                else:
                    lines.append("    None")
            note = summary.get("no_known_match_note") if isinstance(summary, dict) else None
            if note and counts.get("no_known_match", 0) > 0:
                lines.append(f"  Note: {note}")
            if not assessment.get("error"):
                findings = []
                for item in assessed:
                    if not isinstance(item, dict):
                        continue
                    package_findings = item.get("findings", [])
                    if isinstance(package_findings, list):
                        findings.extend(
                            finding for finding in package_findings
                            if isinstance(finding, dict)
                        )
                advisory_context = assessment.get("advisory_context", {})
                if not isinstance(advisory_context, dict):
                    advisory_context = {}
                rendered_context_ids: set[str] = set()
                for finding in findings[:10]:
                    lines.append(
                        f"  {finding.get('assessment_status', 'unknown')}: "
                        f"{finding.get('advisory_id', 'advisory')} — "
                        f"{finding.get('package_name', 'package')} {finding.get('installed_version', '')}"
                    )
                    severity = finding.get("severity")
                    if isinstance(severity, str) and severity.strip():
                        lines.append(f"    Severity: {severity.strip()}")
                    explanation = finding.get("explanation")
                    if isinstance(explanation, str) and explanation.strip():
                        concise_explanation = " ".join(explanation.split())
                        if len(concise_explanation) > DETAILS_PREVIEW_LIMIT:
                            concise_explanation = (
                                concise_explanation[:DETAILS_PREVIEW_LIMIT - 1].rstrip() + "…"
                            )
                        lines.append(f"    Explanation: {concise_explanation}")
                    urgency = finding.get("urgency")
                    if isinstance(urgency, str) and urgency.strip():
                        lines.append(f"    Debian urgency: {urgency.strip()}")
                    source_name = finding.get("source_package_name")
                    source_version = finding.get("source_version")
                    if (isinstance(source_name, str) and source_name.strip()
                            and isinstance(source_version, str) and source_version.strip()):
                        lines.append(f"    Source package: {source_name} {source_version}")
                    advisory_id = finding.get("advisory_id")
                    context = advisory_context.get(advisory_id) if isinstance(advisory_id, str) else None
                    if isinstance(context, dict) and advisory_id not in rendered_context_ids:
                        rendered_context_ids.add(advisory_id)
                        summary = context.get("summary")
                        if isinstance(summary, str) and summary.strip():
                            lines.append(f"    Summary: {summary.strip()}")
                        details = context.get("details")
                        if isinstance(details, str) and details.strip():
                            concise_details = " ".join(details.split())
                            if len(concise_details) > DETAILS_PREVIEW_LIMIT:
                                concise_details = concise_details[:DETAILS_PREVIEW_LIMIT - 1].rstrip() + "…"
                            lines.append(f"    Details: {concise_details}")
                        references = context.get("references")
                        if isinstance(references, list):
                            first_reference = next((ref for ref in references
                                                    if isinstance(ref, dict)
                                                    and isinstance(ref.get("url"), str)
                                                    and ref["url"].strip()), None)
                            if first_reference:
                                lines.append(f"    Advisory reference: {first_reference['url'].strip()}")
                if len(findings) > 10:
                    lines.append(f"  … and {len(findings) - 10} more findings")
    return "\n".join(lines)


def _render_malware_text(assessment: dict[str, object]) -> str:
    """Render the opt-in downloaded-package malware assessment."""
    def terminal_text(value: object, fallback: str = "Unavailable") -> str:
        """Escape nonprinting characters before displaying untrusted text."""
        if not isinstance(value, str):
            return fallback
        return "".join(
            character if character.isprintable()
            else character.encode("unicode_escape").decode("ascii")
            for character in value
        )

    package = assessment.get("package")
    if not isinstance(package, dict):
        package = {}
    identity = " ".join(
        terminal_text(value, "") for value in (package.get("name"), package.get("version"))
        if isinstance(value, str) and value.strip()
    ) or "Unavailable"
    lines = [
        "LinuxSecMonitor — Debian package malware assessment",
        f"Package: {identity}",
        f"Status: {terminal_text(assessment.get('status'), 'error')}",
        f"Scanner: {terminal_text(assessment.get('scanner'))}",
    ]
    architecture = package.get("architecture")
    if isinstance(architecture, str) and architecture.strip():
        lines.append(f"Architecture: {terminal_text(architecture)}")
    detections = assessment.get("detections")
    if isinstance(detections, list):
        for detection in detections:
            if isinstance(detection, dict):
                lines.append(
                    f"Detection: {terminal_text(detection.get('name'), 'Unknown')} — "
                    f"{terminal_text(detection.get('path'), 'path unavailable')}"
                )
    script_findings = assessment.get("maintainer_script_findings")
    if isinstance(script_findings, list) and script_findings:
        lines.append("Maintainer-script static review (heuristic; scripts were not executed):")
        for finding in script_findings:
            if not isinstance(finding, dict):
                continue
            location = terminal_text(finding.get("path"), "path unavailable")
            line_number = finding.get("line_number")
            if isinstance(line_number, int) and not isinstance(line_number, bool) and line_number > 0:
                location += f":{line_number}"
            lines.append(
                f"Review lead [{terminal_text(finding.get('severity'), 'unknown')}]: "
                f"{terminal_text(finding.get('rule_id'), 'unknown')} at {location}"
            )
            evidence = finding.get("evidence")
            if isinstance(evidence, str) and evidence.strip():
                lines.append(f"  Evidence: {terminal_text(evidence)}")
            explanation = finding.get("explanation")
            if isinstance(explanation, str) and explanation.strip():
                lines.append(f"  Explanation: {terminal_text(explanation)}")
        lines.append("Review leads are heuristic and do not establish malicious behavior.")
    error = assessment.get("error")
    if isinstance(error, str) and error.strip():
        lines.append(f"Error: {terminal_text(error)}")
    limitations = assessment.get("limitations")
    if isinstance(limitations, list):
        lines.extend(
            f"Coverage limitation: {terminal_text(item)}"
            for item in limitations if isinstance(item, str) and item.strip()
        )
    lines.append("Note: No detection does not guarantee that this package is safe.")
    return "\n".join(lines)


def _assess_deb_vulnerability(malware_assessment: dict[str, object]) -> dict[str, object]:
    """Assess a package against the advisory source for the current host distro."""
    try:
        system = collect_system_info().to_dict()
    except Exception as exc:
        return _deb_vulnerability_error(
            None, None,
            f"System distribution metadata could not be collected ({type(exc).__name__}).",
        )

    distribution = system.get("distribution")
    release = system.get("distribution_version")
    package_data = malware_assessment.get("package")
    if not isinstance(package_data, dict):
        package_data = {}
    name = package_data.get("name")
    version = package_data.get("version")
    if not isinstance(name, str) or not name.strip() or not isinstance(version, str) or not version.strip():
        return _deb_vulnerability_error(
            distribution if isinstance(distribution, str) else None,
            release if isinstance(release, str) else None,
            "Package name or version metadata is unavailable; no vulnerability conclusion was made.",
            status="requires_review",
        )

    source_name = package_data.get("source_name")
    source_version = package_data.get("source_version")
    package = Package(
        name,
        version,
        source_name if isinstance(source_name, str) and source_name.strip() else None,
        source_version if isinstance(source_version, str) and source_version.strip() else None,
    )
    try:
        return assess_packages(
            [package],
            distribution if isinstance(distribution, str) else None,
            release if isinstance(release, str) else None,
        ).to_dict()
    except Exception as exc:
        return _deb_vulnerability_error(
            distribution if isinstance(distribution, str) else None,
            release if isinstance(release, str) else None,
            f"Vulnerability assessment failed ({type(exc).__name__}); no conclusion was made.",
        )


def _deb_vulnerability_error(
    distribution: str | None,
    release: str | None,
    error: str,
    *,
    status: str = "error",
) -> dict[str, object]:
    """Keep failed or unassessable package metadata explicit in JSON reports."""
    return {
        "assessment_status": status,
        "distribution": distribution,
        "release": release,
        "source": None,
        "error": error,
        "summary": {
            "total_assessed_packages": 0,
            "status_counts": {},
            "no_known_match_is_safe": False,
            "no_known_match_note": (
                "no_known_match means no matching record was found in the queried data; "
                "it is not proof that a package is safe."
            ),
        },
        "packages": [],
        "advisory_context": {},
    }


def _render_deb_vulnerability_text(report: dict[str, object]) -> str:
    """Render bounded vulnerability evidence without trusting archive metadata."""
    def terminal_text(value: object, fallback: str = "Unavailable") -> str:
        if not isinstance(value, str):
            return fallback
        return "".join(
            character if character.isprintable()
            else character.encode("unicode_escape").decode("ascii")
            for character in value
        )

    lines = [
        "Vulnerability assessment:",
        f"  Status: {terminal_text(report.get('assessment_status'), 'error')}",
        f"  Distribution: {terminal_text(report.get('distribution'))}",
        f"  Release: {terminal_text(report.get('release'))}",
        f"  Advisory source: {terminal_text(report.get('source'))}",
    ]
    if isinstance(report.get("error"), str) and report["error"]:
        lines.append(f"  Error: {terminal_text(report['error'])}")
    packages = report.get("packages")
    if isinstance(packages, list):
        for package in packages[:20]:
            if not isinstance(package, dict):
                continue
            lines.append(
                f"  Package: {terminal_text(package.get('package_name'))} "
                f"{terminal_text(package.get('installed_version'))} — "
                f"{terminal_text(package.get('assessment_status'), 'requires_review')}"
            )
            explanation = package.get("explanation")
            if isinstance(explanation, str) and explanation.strip():
                lines.append(f"    {terminal_text(explanation)}")
            findings = package.get("findings")
            if isinstance(findings, list):
                for finding in findings[:20]:
                    if not isinstance(finding, dict):
                        continue
                    severity = finding.get("severity")
                    detail = f"    Advisory {terminal_text(finding.get('advisory_id'))}"
                    if isinstance(severity, str) and severity.strip():
                        detail += f" [{terminal_text(severity)}]"
                    detail += f": {terminal_text(finding.get('assessment_status'))}"
                    lines.append(detail)
                    reference = finding.get("source_reference")
                    if isinstance(reference, str) and reference.strip():
                        lines.append(f"      Reference: {terminal_text(reference)}")
    lines.append("No matching advisory is not proof that the package is safe.")
    return "\n".join(lines)


def _render_deb_text(assessment: dict[str, object]) -> str:
    """Render both the malware inspection and distro-aware advisory result."""
    rendered = _render_malware_text(assessment)
    vulnerability = assessment.get("vulnerability_assessment")
    if isinstance(vulnerability, dict):
        rendered += "\n\n" + _render_deb_vulnerability_text(vulnerability)
    return rendered


def _deb_scan_success(assessment: dict[str, object]) -> bool:
    """Return success only when malware and vulnerability checks are conclusive."""
    if assessment.get("status") != "no_detection" or assessment.get("coverage_complete") is not True:
        return False
    vulnerability = assessment.get("vulnerability_assessment")
    if not isinstance(vulnerability, dict):
        return False
    return vulnerability.get("assessment_status") in {
        "no_known_match", "fixed", "not_affected", "mixed",
    }


def _render_repository_text(result: dict[str, object]) -> str:
    """Render the read-only repository inventory without trusting filenames."""
    def terminal_text(value: object, fallback: str = "Unavailable") -> str:
        if not isinstance(value, str):
            return fallback
        return "".join(
            character if character.isprintable()
            else character.encode("unicode_escape").decode("ascii")
            for character in value
        )

    lines = [
        "LinuxSecMonitor — repository inventory",
        f"Repository: {terminal_text(result.get('repository_path'))}",
        f"Status: {terminal_text(result.get('status'), 'error')}",
        f"Coverage complete: {'yes' if result.get('coverage_complete') is True else 'no'}",
        f"Files observed: {result.get('files_observed', 0)}",
        f"Regular files inventoried: {result.get('files_scanned', 0)}",
        f"Entries skipped: {result.get('files_skipped', 0)}",
        f"Bytes inventoried (from file metadata): {result.get('bytes_scanned', 0)}",
        "File types:",
    ]
    skipped_details = result.get("skipped_entry_details")
    if isinstance(skipped_details, list) and skipped_details:
        lines.append("Skipped-entry details:")
        for item in skipped_details:
            if isinstance(item, dict):
                lines.append(
                    f"  {terminal_text(item.get('path'))}: "
                    f"{terminal_text(item.get('reason'))}"
                )
        omitted = result.get("skipped_entry_details_omitted", 0)
        if isinstance(omitted, int) and omitted > 0:
            lines.append(f"  … and {omitted} additional skipped entries omitted")
    file_types = result.get("file_types")
    if isinstance(file_types, dict) and file_types:
        lines.extend(
            f"  {terminal_text(extension)}: {count}"
            for extension, count in sorted(file_types.items())
        )
    else:
        lines.append("  None")

    lines.append("Project manifests:")
    manifests = result.get("manifests")
    if isinstance(manifests, list) and manifests:
        for manifest in manifests[:REPOSITORY_MANIFEST_PREVIEW_LIMIT]:
            if isinstance(manifest, dict):
                lines.append(
                    f"  {terminal_text(manifest.get('name'))}: "
                    f"{terminal_text(manifest.get('path'))}"
                )
        if len(manifests) > REPOSITORY_MANIFEST_PREVIEW_LIMIT:
            lines.append(
                f"  … and {len(manifests) - REPOSITORY_MANIFEST_PREVIEW_LIMIT} more"
            )
    else:
        lines.append("  None found")

    for label, key in (("Limitation", "limitations"), ("Error", "errors")):
        values = result.get(key)
        if isinstance(values, list):
            lines.extend(
                f"{label}: {terminal_text(value)}"
                for value in values if isinstance(value, str) and value.strip()
            )
    lines.append(
        "Inventory scope: "
        + terminal_text(result.get("note"), "Inventory only; no content analysis was performed.")
    )
    return "\n".join(lines)


def _render_repository_malware_text(assessment: dict[str, object]) -> str:
    """Render a repository malware result while escaping untrusted output."""
    def terminal_text(value: object, fallback: str = "Unavailable") -> str:
        if not isinstance(value, str):
            return fallback
        return "".join(
            character if character.isprintable()
            else character.encode("unicode_escape").decode("ascii")
            for character in value
        )

    lines = [
        "Repository malware assessment:",
        f"  Status: {terminal_text(assessment.get('status'), 'error')}",
        f"  Scanner: {terminal_text(assessment.get('scanner'))}",
        f"  Coverage complete: {'yes' if assessment.get('coverage_complete') is True else 'no'}",
        f"  Staged files scanned: {assessment.get('files_scanned', 0)}",
        f"  Staged bytes scanned: {assessment.get('bytes_scanned', 0)}",
    ]
    skipped_count = assessment.get("entries_skipped")
    if isinstance(skipped_count, int) and not isinstance(skipped_count, bool):
        lines.append(f"  Entries skipped: {skipped_count}")
    skipped_details = assessment.get("skipped_entry_details")
    if isinstance(skipped_details, list) and skipped_details:
        lines.append("  Skipped-entry details:")
        for item in skipped_details:
            if isinstance(item, dict):
                lines.append(
                    f"    {terminal_text(item.get('path'), 'path unavailable')}: "
                    f"{terminal_text(item.get('reason'), 'reason unavailable')}"
                )
        omitted = assessment.get("skipped_entry_details_omitted", 0)
        if isinstance(omitted, int) and omitted > 0:
            lines.append(f"    … and {omitted} additional skipped details omitted")
    detections = assessment.get("detections")
    if isinstance(detections, list) and detections:
        lines.append("  Detections:")
        for detection in detections[:20]:
            if isinstance(detection, dict):
                lines.append(
                    f"    {terminal_text(detection.get('name'), 'Unknown')}: "
                    f"{terminal_text(detection.get('path'), 'path unavailable')}"
                )
        if len(detections) > 20:
            lines.append(f"    … and {len(detections) - 20} more detections")
    else:
        lines.append("  Detections: None reported")

    for label, key in (("Error", "errors"), ("Coverage limitation", "limitations")):
        values = assessment.get(key)
        if isinstance(values, list):
            lines.extend(
                f"  {label}: {terminal_text(value)}"
                for value in values if isinstance(value, str) and value.strip()
            )
    lines.append(terminal_text(
        assessment.get("note"),
        "No detection does not guarantee that a repository is safe.",
    ))
    return "\n".join(lines)


def _render_repository_security_text(assessment: dict[str, object]) -> str:
    """Render static review leads without exposing secret values or controls."""
    def terminal_text(value: object, fallback: str = "Unavailable") -> str:
        if not isinstance(value, str):
            return fallback
        return "".join(
            character if character.isprintable()
            else character.encode("unicode_escape").decode("ascii")
            for character in value
        )

    lines = [
        "Repository static security review:",
        f"  Status: {terminal_text(assessment.get('status'), 'error')}",
        f"  Coverage complete: {'yes' if assessment.get('coverage_complete') is True else 'no'}",
        f"  Files inspected: {assessment.get('files_inspected', 0)}",
        f"  Bytes inspected: {assessment.get('bytes_inspected', 0)}",
        f"  Generated paths included: {'yes' if assessment.get('include_generated') is True else 'no'}",
        f"  Generated paths excluded: {assessment.get('generated_paths_excluded', 0)}",
    ]
    skipped_count = assessment.get("entries_skipped")
    if isinstance(skipped_count, int) and not isinstance(skipped_count, bool):
        lines.append(f"  Entries skipped: {skipped_count}")
    skipped_details = assessment.get("skipped_entry_details")
    if isinstance(skipped_details, list) and skipped_details:
        lines.append("  Skipped-entry details:")
        for item in skipped_details:
            if isinstance(item, dict):
                lines.append(
                    f"    {terminal_text(item.get('path'), 'path unavailable')}: "
                    f"{terminal_text(item.get('reason'), 'reason unavailable')}"
                )
        omitted = assessment.get("skipped_entry_details_omitted", 0)
        if isinstance(omitted, int) and omitted > 0:
            lines.append(f"    … and {omitted} additional skipped details omitted")
    findings = assessment.get("findings")
    if isinstance(findings, list) and findings:
        lines.append("  Review findings:")
        for finding in findings[:REPOSITORY_SECURITY_FINDING_PREVIEW_LIMIT]:
            if not isinstance(finding, dict):
                continue
            location = terminal_text(finding.get("path"))
            line_number = finding.get("line_number")
            if isinstance(line_number, int) and not isinstance(line_number, bool) and line_number > 0:
                location += f":{line_number}"
            lines.append(
                f"    [{terminal_text(finding.get('severity'), 'unknown')}] "
                f"{terminal_text(finding.get('rule_id'))} at "
                f"{location}"
            )
            evidence = finding.get("evidence")
            explanation = finding.get("explanation")
            if isinstance(evidence, str) and evidence.strip():
                lines.append(f"      Evidence: {terminal_text(evidence)}")
            if isinstance(explanation, str) and explanation.strip():
                lines.append(f"      Review: {terminal_text(explanation)}")
        if len(findings) > REPOSITORY_SECURITY_FINDING_PREVIEW_LIMIT:
            lines.append(
                f"    … and {len(findings) - REPOSITORY_SECURITY_FINDING_PREVIEW_LIMIT} more findings"
            )
    else:
        lines.append("  Review findings: None reported")
    for label, key in (("Error", "errors"), ("Limitation", "limitations")):
        values = assessment.get(key)
        if isinstance(values, list):
            lines.extend(
                f"  {label}: {terminal_text(value)}"
                for value in values if isinstance(value, str) and value.strip()
            )
    lines.append(terminal_text(
        assessment.get("note"),
        "Static review is heuristic; no finding does not establish safety.",
    ))
    return "\n".join(lines)


def _output_is_inside_repository(output_path: Path, repository_path: Path) -> bool:
    """Reject output paths that would write into the repository being scanned."""
    try:
        output_absolute = output_path.expanduser().absolute()
        repository_absolute = repository_path.expanduser().absolute()
        output_resolved = output_absolute.resolve()
        repository_resolved = repository_absolute.resolve()
        return (
            output_absolute.is_relative_to(repository_absolute)
            or output_resolved.is_relative_to(repository_resolved)
        )
    except (OSError, RuntimeError, ValueError):
        # If containment cannot be established, avoid a potentially mutating write.
        return True


def _render_safe_run_text(report: dict[str, object]) -> str:
    """Render the repository assessments and guarded-command outcome."""
    inventory = report.get("inventory")
    malware = report.get("malware_assessment")
    security = report.get("repository_security_assessment")
    sections = []
    if isinstance(inventory, dict):
        sections.append(_render_repository_text(inventory))
    if isinstance(malware, dict):
        sections.append(_render_repository_malware_text(malware))
    if isinstance(security, dict):
        sections.append(_render_repository_security_text(security))
    sections.append(f"Execution review: {report.get('review_status', 'error')}")
    sections.append(f"Command outcome: {report.get('command_status', 'not_started')}")
    if report.get("command_returncode") is not None:
        sections.append(f"Command exit code: {report['command_returncode']}")
    if report.get("command_error_type"):
        sections.append(f"Command launch error: {report['command_error_type']}")
    limitations = report.get("limitations")
    if isinstance(limitations, list):
        sections.extend(f"Execution limitation: {item}" for item in limitations)
    return "\n\n".join(sections)


def _render_diagnostics_text(report: dict[str, object]) -> str:
    """Render prerequisite status without exposing APT hook contents."""
    lines = [
        "LinuxSecMonitor read-only diagnostics",
        f"Host status: {report.get('status', 'error')}",
        f"Operating system: {report.get('operating_system') or 'Unavailable'}",
        f"Distribution: {report.get('distribution') or report.get('distribution_id') or 'Unavailable'}",
        f"Distribution version: {report.get('distribution_version') or 'Unavailable'}",
        f"Python: {report.get('python_version', 'Unavailable')} "
        f"({'supported' if report.get('python_supported') is True else 'unsupported'})",
        f"Package inventory prerequisites: "
        f"{'available' if report.get('package_inventory_ready') is True else 'incomplete'}",
        f".deb scan prerequisites: "
        f"{'available' if report.get('deb_scan_prerequisites_available') is True else 'incomplete'}",
        f"APT hook prerequisites: "
        f"{'available' if report.get('apt_hook_prerequisites_available') is True else 'incomplete'}",
        "System tools:",
    ]
    commands = report.get("commands")
    if isinstance(commands, dict):
        for name, result in sorted(commands.items()):
            if not isinstance(result, dict):
                continue
            if result.get("available") is not True:
                status = "missing"
            elif result.get("version"):
                status = str(result["version"])
            else:
                status = f"check {result.get('check', 'unavailable')}"
            lines.append(f"  {name}: {status}")
    pre_install = report.get("apt_pre_install_hook_count")
    pre_invoke = report.get("apt_pre_invoke_hook_count")
    if pre_install is None or pre_invoke is None:
        lines.append("Configured APT hook counts: unavailable")
    else:
        lines.append(f"Configured APT Pre-Install-Pkgs hooks: {pre_install}")
        lines.append(f"Configured APT Pre-Invoke hooks: {pre_invoke}")
    limitations = report.get("limitations")
    if isinstance(limitations, list):
        lines.extend(f"Limitation: {item}" for item in limitations)
    lines.append("No configuration was changed.")
    return "\n".join(lines)


def _run_safe_repository_command(
    repository: Path,
    command: list[str],
    *,
    json_output: bool,
    output_path: Path | None,
    include_generated: bool,
    stdout: TextIO,
) -> int:
    """Review a repository, require a TTY decision, then run a command."""
    report = review_repository_for_execution(
        repository, include_generated=include_generated,
    )
    preview = _render_safe_run_text(report) + "\n"
    # The user must see the complete assessments before the prompt. Keep JSON
    # output parseable by sending that human preview to stderr.
    preview_stream = sys.stderr if json_output else stdout
    preview_stream.write(preview)
    preview_stream.flush()

    if report.get("coverage_complete") is True:
        command_exit = run_reviewed_command(
            report, repository, command, json_output=json_output,
        )
    else:
        command_exit = 1

    if json_output:
        rendered = json.dumps(report, indent=2) + "\n"
        if output_path is not None:
            try:
                output_path.write_text(rendered, encoding="utf-8")
            except OSError as exc:
                print(f"Could not write JSON output: {exc}", file=sys.stderr)
                return 2
        else:
            stdout.write(rendered)
    else:
        stdout.write(f"Final command outcome: {report.get('command_status')}\n")
    return command_exit


def _validated_deb_path(package_path: Path) -> tuple[Path | None, str | None]:
    """Resolve a readable regular .deb file without accepting a symlink."""
    try:
        candidate = package_path.expanduser().absolute()
        if candidate.suffix.lower() != ".deb":
            return None, "The package path must name a .deb file."
        if candidate.is_symlink():
            return None, "The package path must not be a symbolic link."
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.R_OK):
            return None, "The package path is not a readable regular file."
        return resolved, None
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"Could not validate the package path: {exc}"


def _output_overwrites_package(output_path: Path, package_path: Path) -> bool:
    """Return true when a report path aliases the package file being scanned."""
    try:
        output_absolute = output_path.expanduser().absolute()
        package_resolved = package_path.expanduser().resolve(strict=False)
        if output_absolute.resolve(strict=False) == package_resolved:
            return True
        return output_absolute.exists() and os.path.samefile(output_absolute, package_resolved)
    except (OSError, RuntimeError, ValueError):
        # Ambiguous path identity must not risk overwriting the input package.
        return True


def _create_package_snapshot(source: Path, destination: Path) -> None:
    """Copy a bounded, stable package snapshot for both scanning and APT."""
    source_flags = (
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    )
    if hasattr(os, "O_CLOEXEC"):
        source_flags |= os.O_CLOEXEC
    source_fd = os.open(source, source_flags)
    target_fd: int | None = None
    copied = 0
    completed = False
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise OSError("the package changed to a non-regular file")
        if before.st_size < 0 or before.st_size > MAX_PACKAGE_BYTES:
            raise OSError("the package exceeds the compressed-size limit")
        target_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0),
            0o600,
        )
        while True:
            chunk = os.read(source_fd, 64 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_PACKAGE_BYTES:
                raise OSError("the package grew beyond the compressed-size limit")
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(target_fd, remaining)
                if written <= 0:
                    raise OSError("could not finish writing the private package snapshot")
                remaining = remaining[written:]
        after = os.fstat(source_fd)
        if (
            copied != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or getattr(before, "st_mtime_ns", None) != getattr(after, "st_mtime_ns", None)
            or getattr(before, "st_ctime_ns", None) != getattr(after, "st_ctime_ns", None)
        ):
            raise OSError("the package changed while the private snapshot was being created")
        os.fsync(target_fd)
        completed = True
    finally:
        os.close(source_fd)
        if target_fd is not None:
            os.close(target_fd)
        if not completed and target_fd is not None:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass


def _preinstall_temp_parent() -> str | None:
    """Use a traversable parent so APT's sandbox can reach the private snapshot."""
    return "/tmp" if os.name == "posix" else None


def _render_preinstall_report(assessment: dict[str, object]) -> str:
    """Render the scan result shown before the installation confirmation."""
    rendered = _render_deb_text(assessment)
    if assessment.get("status") == "no_detection":
        rendered += (
            "\nNo known malware detection was found. This does not guarantee safety."
        )
    return rendered


def _is_effective_root() -> bool:
    """Return whether this process already has root privileges."""
    return os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0


def _apt_sandbox_gid() -> int:
    """Return APT's sandbox user's primary group ID on Linux."""
    if os.name != "posix":
        raise OSError("APT sandbox permissions are available only on Linux")
    try:
        import pwd

        return pwd.getpwnam("_apt").pw_gid
    except (ImportError, KeyError, OSError) as exc:
        raise OSError("could not determine the APT sandbox user's group") from exc


def _run_permission_command(command: list[str]) -> subprocess.CompletedProcess:
    """Run a fixed permission-management command without a shell."""
    return subprocess.run(
        command, check=False, shell=False, stdin=None,
        stdout=sys.stderr, stderr=sys.stderr,
    )


def _prepare_snapshot_for_apt(
    package_path: Path,
    private_root: Path,
    *,
    sudo_path: str | None,
) -> str | None:
    """Allow only APT's sandbox group to traverse/read the scanned snapshot.

    The package and its directory remain private from other local users. This
    permits APT's `_apt` acquisition sandbox to read a local package without
    making the temporary directory or package world-accessible.
    """
    try:
        sandbox_gid = _apt_sandbox_gid()
        if _is_effective_root():
            os.chown(private_root, -1, sandbox_gid)
            os.chmod(private_root, 0o710)
            os.chown(package_path, -1, sandbox_gid)
            os.chmod(package_path, 0o640)
            return None

        if sudo_path is None:
            return "sudo is unavailable; could not safely prepare the private package for APT."
        chgrp_path = _find_system_command("chgrp")
        chmod_path = _find_system_command("chmod")
        if chgrp_path is None or chmod_path is None:
            return "chgrp or chmod is unavailable; the private package was not exposed to APT."

        commands = [
            [sudo_path, chgrp_path, "--", str(sandbox_gid), str(private_root), str(package_path)],
            [sudo_path, chmod_path, "0710", "--", str(private_root)],
            [sudo_path, chmod_path, "0640", "--", str(package_path)],
        ]
        for command in commands:
            completed = _run_permission_command(command)
            if completed.returncode != 0:
                return (
                    "Could not safely prepare the private package for APT "
                    f"(permission command exited with status {completed.returncode}); "
                    "installation was not attempted."
                )
        return None
    except (OSError, PermissionError) as exc:
        return f"Could not safely prepare the private package for APT: {exc}"


def _run_preinstall_deb(
    package_argument: Path,
    *,
    json_output: bool,
    output_path: Path | None,
    stdout: TextIO,
) -> int:
    """Scan a local .deb, then install it only after an explicit confirmation."""
    if output_path is not None and _output_overwrites_package(output_path, package_argument):
        print("Could not write JSON output over the package being scanned.", file=sys.stderr)
        return 2

    package_path, validation_error = _validated_deb_path(package_argument)
    if validation_error or package_path is None:
        assessment = MalwareAssessment(
            status="error", scanner="dpkg-deb + ClamAV clamscan", error=validation_error,
        ).to_dict()
        installation: dict[str, object] = {
            "status": "blocked",
            "message": "Installation was not attempted because the package path is invalid.",
            "returncode": None,
        }
        return _finish_preinstall_report(
            assessment, installation, json_output=json_output,
            output_path=output_path, stdout=stdout, exit_code=1,
        )

    outcome: tuple[dict[str, object], dict[str, object], int] | None = None
    try:
        with tempfile.TemporaryDirectory(
            prefix="linuxsecmonitor-preinstall-", dir=_preinstall_temp_parent(),
        ) as temporary:
            private_root = Path(temporary)
            if os.name == "posix":
                os.chmod(private_root, 0o700)
            snapshot = private_root / "scanned-package.deb"
            try:
                _create_package_snapshot(package_path, snapshot)
            except OSError as exc:
                assessment = MalwareAssessment(
                    status="error",
                    scanner="dpkg-deb + ClamAV clamscan",
                    error=f"Could not create a private package snapshot: {exc}",
                ).to_dict()
                report_stream = sys.stderr if json_output else stdout
                report_stream.write(_render_preinstall_report(assessment) + "\n")
                installation: dict[str, object] = {
                    "status": "blocked",
                    "message": "Installation was not attempted because a stable package snapshot was unavailable.",
                    "returncode": None,
                }
                outcome = (assessment, installation, 1)
            else:
                outcome = _run_preinstall_snapshot(
                    snapshot, json_output=json_output, stdout=stdout,
                )
    except OSError as exc:
        if outcome is None:
            assessment = MalwareAssessment(
                status="error",
                scanner="dpkg-deb + ClamAV clamscan",
                error=f"Could not create a private package snapshot: {exc}",
            ).to_dict()
            report_stream = sys.stderr if json_output else stdout
            report_stream.write(_render_preinstall_report(assessment) + "\n")
            installation = {
                "status": "blocked",
                "message": "Installation was not attempted because a stable package snapshot was unavailable.",
                "returncode": None,
            }
            outcome = (assessment, installation, 1)
        else:
            assessment, installation, _ = outcome
            installation["message"] = (
                f"{installation['message']} Private snapshot cleanup failed: {exc}"
            )
            outcome = (assessment, installation, 1)

    assert outcome is not None
    assessment, installation, exit_code = outcome
    return _finish_preinstall_report(
        assessment, installation, json_output=json_output,
        output_path=output_path, stdout=stdout, exit_code=exit_code,
    )


def _run_preinstall_snapshot(
    package_path: Path,
    *,
    json_output: bool,
    stdout: TextIO,
) -> tuple[dict[str, object], dict[str, object], int]:
    """Assess and, after approval, install the same private package snapshot."""
    assessment = scan_deb(package_path).to_dict()
    assessment["vulnerability_assessment"] = _assess_deb_vulnerability(assessment)
    preview = _render_preinstall_report(assessment) + "\n"
    # In JSON mode, keep stdout reserved for the final machine-readable result.
    report_stream = sys.stderr if json_output else stdout
    report_stream.write(preview)
    report_stream.flush()

    status = assessment.get("status")
    if status != "no_detection" or assessment.get("coverage_complete") is not True:
        if status == "detected":
            message = "Installation blocked because the scan reported a malware detection."
        elif status == "no_detection":
            message = (
                "Installation blocked because the assessment did not confirm complete scan coverage."
            )
        else:
            message = (
                f"Installation blocked because the scan status was {status!r}; "
                "only no_detection can proceed to confirmation."
            )
        installation = {"status": "blocked", "message": message, "returncode": None}
        return assessment, installation, 1

    apt_get = _find_system_command("apt-get")
    if apt_get is None:
        installation = {
            "status": "unavailable",
            "message": "apt-get is unavailable; installation was not attempted.",
            "returncode": None,
        }
        return assessment, installation, 1

    print(
        "Scope warning: only the requested .deb snapshot was scanned. APT may "
        "install dependency packages that were not scanned; after approval, "
        "their APT hooks or package configuration scripts may run. Review the "
        "transaction and do not treat no_detection as proof of safety.",
        file=sys.stderr,
    )
    print(
        "Type INSTALL to continue with this local package; anything else cancels: ",
        end="", file=sys.stderr, flush=True,
    )
    try:
        answer = sys.stdin.readline()
    except (OSError, KeyboardInterrupt):
        answer = ""
    # Accept only the exact token plus the terminal line ending. Do not trim
    # spaces or normalize case; either would broaden approval unexpectedly.
    if answer.removesuffix("\n").removesuffix("\r") != "INSTALL":
        installation = {
            "status": "cancelled",
            "message": "Installation was not approved and was cancelled.",
            "returncode": None,
        }
        return assessment, installation, 1

    is_root = _is_effective_root()
    sudo_path = None if is_root else _find_system_command("sudo")
    if not is_root and sudo_path is None:
        installation = {
            "status": "unavailable",
            "message": "sudo is unavailable; administrator privileges were not requested and installation was not attempted.",
            "returncode": None,
        }
        return assessment, installation, 1

    if sudo_path is not None:
        print("Requesting administrator authorization for installation only.", file=sys.stderr)
        try:
            authorization = _run_permission_command([sudo_path, "-v"])
        except KeyboardInterrupt:
            installation = {
                "status": "cancelled",
                "message": "Administrator authorization was interrupted; installation was not attempted.",
                "returncode": None,
            }
            return assessment, installation, 1
        except (FileNotFoundError, PermissionError, OSError) as exc:
            installation = {
                "status": "failed",
                "message": f"Could not obtain administrator authorization; installation was not attempted: {exc}",
                "returncode": None,
            }
            return assessment, installation, 1
        if authorization.returncode != 0:
            installation = {
                "status": "failed",
                "message": "Administrator authorization was not granted; installation was not attempted.",
                "returncode": authorization.returncode,
            }
            return assessment, installation, 1

    try:
        permission_error = _prepare_snapshot_for_apt(
            package_path, package_path.parent, sudo_path=sudo_path,
        )
    except KeyboardInterrupt:
        installation = {
            "status": "cancelled",
            "message": "Preparing the private package for APT was interrupted; installation was not attempted.",
            "returncode": None,
        }
        return assessment, installation, 1
    if permission_error is not None:
        installation = {
            "status": "failed",
            "message": permission_error,
            "returncode": None,
        }
        return assessment, installation, 1

    print(
        "Starting APT for the scanned local package. APT may install dependencies "
        "from configured sources; package scripts may run.",
        file=sys.stderr,
    )
    command = [apt_get, "install", "--no-remove", "--", str(package_path)]
    if sudo_path is not None:
        command.insert(0, sudo_path)
    try:
        completed = subprocess.run(
            command,
            check=False,
            shell=False,
            stdin=None,
            stdout=sys.stderr,
            stderr=sys.stderr,
        )
    except FileNotFoundError:
        installation = {
            "status": "unavailable",
            "message": "apt-get became unavailable; installation was not attempted.",
            "returncode": None,
        }
    except PermissionError as exc:
        installation = {
            "status": "failed",
            "message": f"Permission denied while starting apt-get: {exc}",
            "returncode": None,
        }
    except OSError as exc:
        installation = {
            "status": "failed",
            "message": f"Could not run apt-get: {exc}",
            "returncode": None,
        }
    except KeyboardInterrupt:
        installation = {
            "status": "cancelled",
            "message": "APT was interrupted by the user; package state may require review.",
            "returncode": None,
        }
    else:
        if completed.returncode == 0:
            installation = {
                "status": "installed",
                "message": "APT reported successful installation.",
                "returncode": 0,
            }
        else:
            installation = {
                "status": "failed",
                "message": (
                    f"apt-get exited with status {completed.returncode}; "
                    "review its output and package state."
                ),
                "returncode": completed.returncode,
            }
    result_exit_code = 0 if installation["status"] == "installed" else 1
    return assessment, installation, result_exit_code


def _finish_preinstall_report(
    assessment: dict[str, object],
    installation: dict[str, object],
    *,
    json_output: bool,
    output_path: Path | None,
    stdout: TextIO,
    exit_code: int,
) -> int:
    """Write the final pre-install result without contaminating JSON stdout."""
    if json_output:
        rendered = json.dumps(
            {"malware_assessment": assessment, "installation": installation}, indent=2,
        ) + "\n"
        if output_path is not None:
            try:
                output_path.write_text(rendered, encoding="utf-8")
            except OSError as exc:
                print(f"Could not write JSON output: {exc}", file=sys.stderr)
                return 2
        else:
            stdout.write(rendered)
    else:
        stdout.write(f"Installation: {installation['status']} — {installation['message']}\n")
    return exit_code


def main(argv: list[str] | None = None, stdout: TextIO = sys.stdout) -> int:
    """Run the CLI and return a process exit status."""
    parser = argparse.ArgumentParser(description="Collect basic Linux system and package inventory data.")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON instead of a text report.")
    parser.add_argument("-o", "--output", type=Path, help="Write JSON to this file (requires --json).")
    parser.add_argument(
        "--diagnostics", action="store_true",
        help="Write stage progress and elapsed times to stderr.",
    )
    parser.add_argument(
        "--scan-deb", type=Path, metavar="PACKAGE.deb",
        help="Inspect a downloaded Debian package for malware and supported OSV advisories without installing it.",
    )
    parser.add_argument(
        "--preinstall-deb", type=Path, metavar="PACKAGE.deb",
        help="Scan a local .deb and offer installation only after explicit confirmation.",
    )
    parser.add_argument(
        "--apt-preinstall-hook", action="store_true",
        help="Handle APT Pre-Install-Pkgs protocol version 3 and gate the transaction.",
    )
    parser.add_argument(
        "--scan-repo", type=Path, metavar="REPOSITORY",
        help="Inventory a repository, scan staged files with ClamAV, and run bounded static checks.",
    )
    parser.add_argument(
        "--safe-run", type=Path, metavar="REPOSITORY",
        help="Review a repository and require interactive approval before a command after --.",
    )
    parser.add_argument(
        "--doctor", action="store_true",
        help="Check platform and tool prerequisites without changing configuration.",
    )
    parser.add_argument(
        "--apt-integration",
        choices=("status", "install", "enable", "disable", "uninstall"),
        metavar="ACTION",
        help=("Show or manage LinuxSecMonitor's dedicated APT hook. System-changing "
              "actions require root; inspect the target paths before use."),
    )
    parser.add_argument(
        "command_args", nargs=argparse.REMAINDER,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--include-generated", action="store_true",
        help="Include Python bytecode and common cache directories in repository static review.",
    )
    args = parser.parse_args(argv)
    if args.output and not args.json:
        parser.error("--output requires --json")
    if args.apt_integration and (args.output or args.diagnostics):
        parser.error("--apt-integration supports standard output only; --output and --diagnostics are not applicable")
    if args.include_generated and not (args.scan_repo or args.safe_run):
        parser.error("--include-generated requires --scan-repo or --safe-run")
    if args.command_args and not args.safe_run:
        parser.error("a command after -- requires --safe-run")
    safe_command = args.command_args
    if safe_command and safe_command[0] == "--":
        safe_command = safe_command[1:]
    selected_modes = sum(bool(mode) for mode in (
        args.scan_deb, args.preinstall_deb, args.apt_preinstall_hook,
        args.scan_repo, args.safe_run, args.doctor, args.apt_integration,
    ))
    if selected_modes > 1:
        parser.error(
            "--scan-deb, --preinstall-deb, --apt-preinstall-hook, --scan-repo, --safe-run, --doctor, and --apt-integration "
            "cannot be used together"
        )
    if args.apt_preinstall_hook and (args.json or args.output or args.diagnostics):
        parser.error("--apt-preinstall-hook cannot be combined with --json, --output, or --diagnostics")

    if args.apt_preinstall_hook:
        return run_apt_preinstall_hook()
    if args.apt_integration:
        try:
            paths = {"apt_conf_dir": Path("/etc/apt/apt.conf.d"),
                     "state_dir": Path("/var/lib/linuxsecmonitor")}
            if args.apt_integration == "status":
                result = integration_status(**paths)
                if result.get("status") == "enabled":
                    runtime = result.get("python")
                    try:
                        if not isinstance(runtime, str):
                            raise LifecycleError("Lifecycle receipt has no interpreter path")
                        validate_effective_hook_order(runtime)
                    except LifecycleError as exc:
                        result["status"] = "conflict"
                        result["effective_order_error"] = str(exc)
            else:
                if not _is_effective_root():
                    raise LifecycleError(
                        f"{args.apt_integration} requires effective root privileges; "
                        "no system configuration was changed"
                    )
                if args.apt_integration == "install":
                    trusted_modules = (
                        Path(__file__),
                        Path(__file__).parent / "scanner" / "apt_hook.py",
                        Path(__file__).parent / "scanner" / "malware_scanner.py",
                    )
                    validate_trusted_runtime(sys.executable, trusted_modules)
                    result = install_apt_hook(
                        **paths, python=sys.executable, module_paths=trusted_modules,
                        effective_order_check=validate_effective_hook_order,
                    )
                elif args.apt_integration == "enable":
                    trusted_modules = (
                        Path(__file__),
                        Path(__file__).parent / "scanner" / "apt_hook.py",
                        Path(__file__).parent / "scanner" / "malware_scanner.py",
                    )
                    result = enable_apt_hook(
                        **paths, module_paths=trusted_modules,
                        effective_order_check=validate_effective_hook_order,
                    )
                elif args.apt_integration == "disable":
                    result = disable_apt_hook(**paths)
                else:
                    result = uninstall_apt_hook(**paths)
        except (LifecycleError, OSError) as exc:
            print(f"APT integration {args.apt_integration} failed: {exc}", file=sys.stderr)
            return 1
        stdout.write(json.dumps(result, indent=2) + "\n" if args.json
                     else f"APT integration: {result['status']}\n"
                          f"Hook: {result['hook_path']}\n"
                          f"State: {result['state_path']}\n")
        return 0 if result["status"] in {"enabled", "disabled", "not_installed"} else 1
    if args.doctor:
        result = collect_diagnostics()
        rendered = (
            json.dumps(result, indent=2) + "\n"
            if args.json else _render_diagnostics_text(result) + "\n"
        )
        if args.output:
            try:
                args.output.write_text(rendered, encoding="utf-8")
            except OSError as exc:
                print(f"Could not write JSON output: {exc}", file=sys.stderr)
                return 2
        else:
            stdout.write(rendered)
        return 0 if (
            result.get("status") == "supported_host"
            and result.get("python_supported") is True
            and result.get("package_inventory_ready") is True
            and result.get("deb_scan_prerequisites_available") is True
        ) else 1
    if args.scan_repo and args.output and _output_is_inside_repository(args.output, args.scan_repo):
        print("Could not write JSON output inside the repository being scanned.", file=sys.stderr)
        return 2
    if args.safe_run:
        if not safe_command:
            parser.error("--safe-run requires a command after --")
        if args.output and _output_is_inside_repository(args.output, args.safe_run):
            print("Could not write JSON output inside the repository being scanned.", file=sys.stderr)
            return 2
        return _run_safe_repository_command(
            args.safe_run,
            safe_command,
            json_output=args.json,
            output_path=args.output,
            include_generated=args.include_generated,
            stdout=stdout,
        )

    if args.preinstall_deb:
        return _run_preinstall_deb(
            args.preinstall_deb,
            json_output=args.json,
            output_path=args.output,
            stdout=stdout,
        )

    if args.scan_repo:
        result = scan_repository(args.scan_repo).to_dict()
        assessment = scan_repository_malware(args.scan_repo).to_dict()
        security_assessment = scan_repository_security(
            args.scan_repo, include_generated=args.include_generated,
        ).to_dict()
        result["malware_assessment"] = assessment
        result["repository_security_assessment"] = security_assessment
        rendered = (
            json.dumps(result, indent=2) + "\n"
            if args.json else (
                _render_repository_text(result) + "\n"
                + _render_repository_malware_text(assessment) + "\n"
                + _render_repository_security_text(security_assessment) + "\n"
            )
        )
        if args.output:
            try:
                args.output.write_text(rendered, encoding="utf-8")
            except OSError as exc:
                print(f"Could not write JSON output: {exc}", file=sys.stderr)
                return 2
        else:
            stdout.write(rendered)
        return 0 if (
            result["coverage_complete"] is True
            and assessment.get("status") == "no_detection"
            and assessment.get("coverage_complete") is True
            and security_assessment.get("status") == "completed"
            and security_assessment.get("coverage_complete") is True
            and not security_assessment.get("findings")
        ) else 1

    if args.scan_deb:
        assessment = scan_deb(args.scan_deb).to_dict()
        assessment["vulnerability_assessment"] = _assess_deb_vulnerability(assessment)
        if args.json:
            rendered = json.dumps(assessment, indent=2) + "\n"
        else:
            rendered = _render_deb_text(assessment) + "\n"
        if args.output:
            try:
                args.output.write_text(rendered, encoding="utf-8")
            except OSError as exc:
                print(f"Could not write JSON output: {exc}", file=sys.stderr)
                return 2
        else:
            stdout.write(rendered)
        return 0 if _deb_scan_success(assessment) else 1

    diagnostic = None
    if args.diagnostics:
        diagnostic = lambda message: print(f"[diagnostic] {message}", file=sys.stderr)
    result = build_result(diagnostic=diagnostic) if diagnostic else build_result()
    if args.json:
        rendered = _run_timed_stage(
            "Report serialization", lambda: json.dumps(result, indent=2) + "\n", diagnostic
        )
        if args.output:
            try:
                _run_timed_stage(
                    "Report writing", lambda: args.output.write_text(rendered, encoding="utf-8"), diagnostic
                )
            except OSError as exc:
                print(f"Could not write JSON output: {exc}", file=sys.stderr)
                return 2
        else:
            _run_timed_stage("Report writing to stdout", lambda: stdout.write(rendered), diagnostic)
    else:
        rendered = _run_timed_stage("Text report rendering", lambda: _render_text(result) + "\n", diagnostic)
        _run_timed_stage("Report writing to stdout", lambda: stdout.write(rendered), diagnostic)
    package_scan = result["package_scan"]
    return 0 if package_scan["success"] else 1  # type: ignore[index]


if __name__ == "__main__":
    raise SystemExit(main())
