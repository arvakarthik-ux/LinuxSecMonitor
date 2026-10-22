"""Command-line entry point for LinuxSecMonitor Sprint 1."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from time import perf_counter
from typing import Callable, TextIO, TypeVar

from scanner import collect_system_info, scan_installed_packages
from scanner.malware_scanner import scan_deb
from scanner.vulnerability_assessment import assess_packages

T = TypeVar("T")
DiagnosticCallback = Callable[[str], None]
DETAILS_PREVIEW_LIMIT = 240


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
        help="Inspect and scan a downloaded Debian package without installing it.",
    )
    args = parser.parse_args(argv)
    if args.output and not args.json:
        parser.error("--output requires --json")

    if args.scan_deb:
        assessment = scan_deb(args.scan_deb).to_dict()
        if args.json:
            rendered = json.dumps(assessment, indent=2) + "\n"
        else:
            rendered = _render_malware_text(assessment) + "\n"
        if args.output:
            try:
                args.output.write_text(rendered, encoding="utf-8")
            except OSError as exc:
                print(f"Could not write JSON output: {exc}", file=sys.stderr)
                return 2
        else:
            stdout.write(rendered)
        return 0 if assessment["status"] == "no_detection" else 1

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
