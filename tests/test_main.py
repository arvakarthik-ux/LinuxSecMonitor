"""CLI formatting and JSON output tests."""

import json
from io import StringIO

import pytest

import main
from scanner.package_scanner import Package, PackageScanResult
from scanner.vulnerability_assessment import (
    PackageAssessment,
    VulnerabilityAssessmentReport,
)


def test_json_output_format(monkeypatch):
    monkeypatch.setattr(main, "build_result", lambda: {
        "system_info": {"operating_system": "Linux"},
        "package_scan": {"success": True, "error": None, "packages": [{"name": "bash", "version": "1"}]},
    })
    output = StringIO()
    assert main.main(["--json"], stdout=output) == 0
    assert json.loads(output.getvalue())["package_scan"]["packages"][0]["name"] == "bash"


def test_json_output_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(main, "build_result", lambda diagnostic=None: {
        "system_info": {}, "package_scan": {"success": True, "error": None, "packages": []},
    })
    output_file = tmp_path / "scan.json"
    assert main.main(
        ["--json", "--output", str(output_file), "--diagnostics"], stdout=StringIO()
    ) == 0
    assert json.loads(output_file.read_text())["package_scan"]["success"] is True
    stderr = capsys.readouterr().err
    assert "[diagnostic] Report serialization completed in" in stderr
    assert "[diagnostic] Report writing completed in" in stderr


def test_diagnostics_stay_on_stderr_and_preserve_json_stdout(monkeypatch, capsys):
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {"assessment_status": "no_known_match", "packages": []},
    }

    def fake_build_result(diagnostic=None):
        diagnostic("mock assessment stage completed in 0.001s.")
        return report

    monkeypatch.setattr(main, "build_result", fake_build_result)
    stdout = StringIO()

    assert main.main(["--json", "--diagnostics"], stdout=stdout) == 0

    assert json.loads(stdout.getvalue()) == report
    stderr = capsys.readouterr().err
    assert "[diagnostic] mock assessment stage" in stderr
    assert "[diagnostic] Report serialization completed in" in stderr
    assert "[diagnostic] Report writing to stdout completed in" in stderr
    assert "[diagnostic]" not in stdout.getvalue()


def test_inventory_exception_is_diagnosed_and_propagated(monkeypatch):
    monkeypatch.setattr(
        main, "collect_system_info", lambda: type("Info", (), {"to_dict": lambda self: {
            "distribution": "Debian GNU/Linux 12", "distribution_version": "12",
        }})(),
    )

    def fail_inventory():
        raise RuntimeError("mock dpkg-query exception")

    monkeypatch.setattr(main, "scan_installed_packages", fail_inventory)
    messages = []

    with pytest.raises(RuntimeError, match="mock dpkg-query exception"):
        main.build_result(diagnostic=messages.append)

    assert any("Package inventory started" in message for message in messages)
    assert any("Package inventory failed in" in message for message in messages)
    assert any("RuntimeError" in message for message in messages)
    assert any("System information collection started" in message for message in messages)
    assert any("System information collection completed in" in message for message in messages)


def test_text_reports_scan_failure(monkeypatch):
    monkeypatch.setattr(main, "build_result", lambda: {
        "system_info": {}, "package_scan": {"success": False, "error": "unsupported", "packages": []},
    })
    output = StringIO()
    assert main.main([], stdout=output) == 1
    assert "Operating system: Unavailable" in output.getvalue()
    assert "Scan failed: unsupported" in output.getvalue()


def test_text_includes_vulnerability_assessment_when_available():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "no_known_match", "error": None,
            "packages": [], "explanation": "No matching record was found.",
        },
    }
    text = main._render_text(report)
    assert "Vulnerability assessment:" in text
    assert "Status: no_known_match" in text


def test_text_reports_assessment_summary_and_context():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "mixed", "distribution": "Debian GNU/Linux 12",
            "release": "12", "source": "Debian OSV via osv.dev", "error": None,
            "explanation": "Assessment completed.",
            "summary": {
                "total_assessed_packages": 2,
                "status_counts": {"fixed": 1, "no_known_match": 1},
                "no_known_match_note": "no_known_match is not proof that a package is safe.",
            },
            "packages": [
                {"assessment_status": "fixed", "findings": []},
                {"assessment_status": "no_known_match", "findings": []},
            ],
        },
    }
    text = main._render_text(report)
    assert "Distribution: Debian GNU/Linux 12" in text
    assert "Release: 12" in text
    assert "Source: Debian OSV via osv.dev" in text
    assert "Total assessed package entries: 2" in text
    assert "fixed: 1" in text
    assert "no_known_match: 1" in text
    assert "not proof that a package is safe" in text


def test_text_renders_advisory_context_and_truncates_long_details():
    long_details = "Security advisory details. " * 30
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "vulnerable", "error": None,
            "advisory_context": {"DEBIAN-CVE-2024-6387": {
                "summary": "OpenSSH issue summary",
                "details": long_details,
                "references": [{"type": "REPORT", "url": "https://example.test/advisory"}],
            }},
            "packages": [{"assessment_status": "vulnerable", "findings": [{
                "advisory_id": "DEBIAN-CVE-2024-6387", "package_name": "openssh-server",
                "installed_version": "1", "severity": None,
                "assessment_status": "vulnerable", "urgency": "high",
            }]}],
        },
    }

    text = main._render_text(report)

    assert "Summary: OpenSSH issue summary" in text
    assert "Debian urgency: high" in text
    assert "Advisory reference: https://example.test/advisory" in text
    detail_line = next(line for line in text.splitlines() if "    Details:" in line)
    rendered_details = detail_line.removeprefix("    Details: ")
    assert len(rendered_details) <= main.DETAILS_PREVIEW_LIMIT
    assert rendered_details.endswith("…")


def test_text_omits_missing_advisory_context_fields_without_error():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "vulnerable", "error": None,
            "advisory_context": {"CVE-2024-0001": {"references": [None, {}]}},
            "packages": [{"findings": [{
                "advisory_id": "CVE-2024-0001", "assessment_status": "vulnerable",
            }]}],
        },
    }

    text = main._render_text(report)

    assert "CVE-2024-0001" in text
    assert "Summary:" not in text
    assert "    Details:" not in text
    assert "Advisory reference:" not in text


def test_text_renders_legacy_findings_without_advisory_context():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "vulnerable", "error": None,
            "packages": [{"findings": [{
                "advisory_id": "CVE-2024-0001", "package_name": "bash",
                "installed_version": "5.0", "assessment_status": "vulnerable",
            }]}],
        },
    }

    text = main._render_text(report)

    assert "vulnerable: CVE-2024-0001 — bash 5.0" in text


def test_serialized_assessment_summary_matches_terminal_counts():
    assessment = VulnerabilityAssessmentReport(
        assessment_status="vulnerable",
        distribution="Debian GNU/Linux 12",
        release="12",
        source="Debian OSV via osv.dev",
        error=None,
        packages=[
            PackageAssessment("openssl", "1.0", "vulnerable", "Affected", []),
            PackageAssessment("bash", "2.0", "no_known_match", "No match", []),
            PackageAssessment("curl", "3.0", "vulnerable", "Affected", []),
        ],
    ).to_dict()
    result = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": assessment,
    }

    serialized = json.loads(json.dumps(assessment))
    text = main._render_text(result)

    assert serialized["summary"]["total_assessed_packages"] == 3
    assert serialized["summary"]["status_counts"] == {
        "vulnerable": 2,
        "no_known_match": 1,
    }
    assert "Status: vulnerable" in text
    assert "Total assessed package entries: 3" in text
    assert "vulnerable: 2" in text
    assert "no_known_match: 1" in text


def test_text_falls_back_to_empty_summary_for_unsupported_assessment():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "unsupported", "distribution": "Kali GNU/Linux Rolling",
            "release": "2025.1", "source": None, "error": "Unsupported for Kali.",
            "packages": [],
        },
    }
    text = main._render_text(report)
    assert "Status: unsupported" in text
    assert "Distribution: Kali GNU/Linux Rolling" in text
    assert "Details: Unsupported for Kali." in text
    assert "Total assessed package entries: 0" in text
    assert "Package assessment counts:\n    None" in text


def test_text_derives_counts_for_legacy_report_without_summary():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "requires_review", "error": None,
            "packages": [
                {"package_name": "openssl", "assessment_status": "no_known_match", "findings": []},
                {"package_name": "bash", "assessment_status": "requires_review", "findings": []},
                {"package_name": "curl", "assessment_status": "no_known_match", "findings": []},
            ],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 3" in text
    assert "no_known_match: 2" in text
    assert "requires_review: 1" in text


def test_text_uses_package_entries_when_supplied_summary_counts_are_incorrect():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "mixed", "error": None,
            "summary": {
                "total_assessed_packages": 99,
                "status_counts": {"fixed": 99},
                "no_known_match_note": "No known match is not proof of safety.",
            },
            "packages": [
                {"assessment_status": "vulnerable"},
                {"assessment_status": "no_known_match"},
            ],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 2" in text
    assert "vulnerable: 1" in text
    assert "no_known_match: 1" in text
    assert "fixed: 99" not in text
    assert "No known match is not proof of safety." in text


def test_text_ignores_nonzero_supplied_summary_for_empty_package_list():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "no_known_match", "error": None,
            "summary": {
                "total_assessed_packages": 4,
                "status_counts": {"no_known_match": 4},
            },
            "packages": [],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 0" in text
    assert "Package assessment counts:\n    None" in text
    assert "no_known_match: 4" not in text


def test_text_counts_package_with_missing_status_as_unknown():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "requires_review", "error": None,
            "summary": {
                "total_assessed_packages": 0,
                "status_counts": {},
            },
            "packages": [
                {"package_name": "legacy-package"},
                {"package_name": "known-package", "assessment_status": "fixed"},
            ],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 2" in text
    assert "fixed: 1" in text
    assert "unknown: 1" in text


def test_build_result_preserves_package_inventory_failure_in_json(monkeypatch):
    monkeypatch.setattr(
        main, "collect_system_info", lambda: type("Info", (), {"to_dict": lambda self: {
            "operating_system": "Linux", "distribution": "Debian GNU/Linux 12",
            "distribution_version": "12",
        }})(),
    )
    monkeypatch.setattr(
        main, "scan_installed_packages",
        lambda: PackageScanResult([], "dpkg-query failed: database unavailable"),
    )

    messages = []
    result = main.build_result(diagnostic=messages.append)
    serialized = json.loads(json.dumps(result))
    assessment = serialized["vulnerability_assessment"]

    assert serialized["package_scan"]["success"] is False
    assert serialized["package_scan"]["error"] == "dpkg-query failed: database unavailable"
    assert assessment["assessment_status"] == "error"
    assert assessment["summary"]["total_assessed_packages"] == 0
    assert assessment["summary"]["status_counts"] == {}
    assert any("Package inventory result: success=False" in message for message in messages)
    assert any("Package inventory started" in message for message in messages)
    assert any("Package inventory completed in" in message for message in messages)


def test_build_result_uses_internal_source_metadata_without_changing_inventory_json(monkeypatch):
    package = Package("openssh-server", "1:9.2p1-2", "openssh", "1:9.2p1-2")
    monkeypatch.setattr(
        main, "collect_system_info", lambda: type("Info", (), {"to_dict": lambda self: {
            "operating_system": "Linux", "distribution": "Debian 12", "distribution_version": "12",
        }})(),
    )
    monkeypatch.setattr(main, "scan_installed_packages", lambda: PackageScanResult([package]))
    received = {}

    class Assessment:
        def to_dict(self):
            return {"assessment_status": "no_known_match", "packages": []}

    def assess(packages, distribution, release):
        received["package"] = packages[0]
        return Assessment()

    monkeypatch.setattr(main, "assess_packages", assess)
    result = main.build_result()
    assert received["package"].source_name == "openssh"
    assert received["package"].source_version == "1:9.2p1-2"
    assert result["package_scan"]["packages"] == [
        {"name": "openssh-server", "version": "1:9.2p1-2"}
    ]
