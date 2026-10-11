"""Command-line entry point for LinuxSecMonitor Sprint 1."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TextIO

from scanner import collect_system_info, scan_installed_packages
from scanner.vulnerability_assessment import assess_packages


def build_result() -> dict[str, object]:
    """Collect system and package data in a JSON-ready result structure."""
    system_info = collect_system_info().to_dict()
    package_scan_result = scan_installed_packages()
    package_scan = package_scan_result.to_dict()
    if package_scan_result.success:
        vulnerability_assessment = assess_packages(
            package_scan_result.packages,
            system_info.get("distribution"),
            system_info.get("distribution_version"),
        ).to_dict()
    else:
        vulnerability_assessment = {
            "assessment_status": "error",
            "distribution": system_info.get("distribution"),
            "release": system_info.get("distribution_version"),
            "source": None,
            "error": "Vulnerability assessment was not run because package inventory failed.",
            "packages": [],
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
    assessment = result.get("vulnerability_assessment")
    if isinstance(assessment, dict):
        lines.append("Vulnerability assessment:")
        lines.append(f"  Status: {assessment.get('assessment_status', 'Unavailable')}")
        if assessment.get("error"):
            lines.append(f"  Details: {assessment['error']}")
        else:
            lines.append(f"  Details: {assessment.get('explanation', 'See per-package assessments in JSON output.')}")
            assessed = assessment.get("packages", [])
            if isinstance(assessed, list):
                findings = [finding for item in assessed if isinstance(item, dict)
                            for finding in item.get("findings", []) if isinstance(finding, dict)]
                for finding in findings[:10]:
                    lines.append(
                        f"  {finding.get('assessment_status', 'unknown')}: "
                        f"{finding.get('advisory_id', 'advisory')} — "
                        f"{finding.get('package_name', 'package')} {finding.get('installed_version', '')}"
                    )
                if len(findings) > 10:
                    lines.append(f"  … and {len(findings) - 10} more findings")
    return "\n".join(lines)


def main(argv: list[str] | None = None, stdout: TextIO = sys.stdout) -> int:
    """Run the CLI and return a process exit status."""
    parser = argparse.ArgumentParser(description="Collect basic Linux system and package inventory data.")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON instead of a text report.")
    parser.add_argument("-o", "--output", type=Path, help="Write JSON to this file (requires --json).")
    args = parser.parse_args(argv)
    if args.output and not args.json:
        parser.error("--output requires --json")

    result = build_result()
    if args.json:
        rendered = json.dumps(result, indent=2) + "\n"
        if args.output:
            try:
                args.output.write_text(rendered, encoding="utf-8")
            except OSError as exc:
                print(f"Could not write JSON output: {exc}", file=sys.stderr)
                return 2
        else:
            stdout.write(rendered)
    else:
        stdout.write(_render_text(result) + "\n")
    package_scan = result["package_scan"]
    return 0 if package_scan["success"] else 1  # type: ignore[index]


if __name__ == "__main__":
    raise SystemExit(main())
