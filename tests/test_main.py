"""CLI formatting and JSON output tests."""

import json
from io import StringIO

import pytest

import main
from scanner.package_scanner import Package, PackageScanResult
from scanner.malware_scanner import MalwareAssessment, MalwareDetection
from scanner.system_info import SystemInfo
from scanner.vulnerability_assessment import (
    PackageAssessment,
    VulnerabilityFinding,
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


def test_scan_deb_cli_keeps_malware_report_separate_and_serializes_json(monkeypatch):
    monkeypatch.setattr(
        main,
        "scan_deb",
        lambda path: MalwareAssessment(
            status="detected",
            scanner="ClamAV clamscan",
            package={"name": "demo", "version": "1.2-3"},
            detections=[MalwareDetection("Test.Signature", "payload/usr/bin/demo")],
            coverage_complete=True,
        ),
    )
    output = StringIO()

    exit_code = main.main(["--scan-deb", "demo.deb", "--json"], stdout=output)

    report = json.loads(output.getvalue())
    assert exit_code == 1
    assert report["status"] == "detected"
    assert report["package"]["name"] == "demo"
    assert report["detections"][0] == {
        "name": "Test.Signature", "path": "payload/usr/bin/demo",
    }
    assert "vulnerability_assessment" not in report


def test_scan_deb_text_report_explains_status_and_safety_limit(monkeypatch):
    monkeypatch.setattr(
        main,
        "scan_deb",
        lambda path: MalwareAssessment(
            status="incomplete",
            scanner="ClamAV clamscan",
            package={"name": "demo", "version": "1.2-3", "architecture": "all"},
            error=None,
            limitations=["A symbolic link was skipped."],
        ),
    )
    output = StringIO()

    exit_code = main.main(["--scan-deb", "demo.deb"], stdout=output)

    text = output.getvalue()
    assert exit_code == 1
    assert "Package: demo 1.2-3" in text
    assert "Status: incomplete" in text
    assert "Scanner: ClamAV clamscan" in text
    assert "Coverage limitation: A symbolic link was skipped." in text
    assert "No detection does not guarantee" in text


def test_malware_text_escapes_package_and_detection_terminal_controls():
    report = {
        "status": "detected",
        "scanner": "ClamAV",
        "package": {"name": "demo\x1b[31m\nforged", "version": "1.0\rhidden"},
        "detections": [{
            "name": "Test.Signature",
            "path": "payload/evil\x1b[2J\r\nforged",
        }],
        "error": None,
        "limitations": [],
    }

    text = main._render_malware_text(report)

    assert "demo\\x1b[31m\\nforged" in text
    assert "1.0\\rhidden" in text
    assert "payload/evil\\x1b[2J\\r\\nforged" in text
    assert "\x1b" not in text
    assert "\r" not in text


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


def test_cli_json_output_file_write_failure_returns_two(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        main,
        "collect_system_info",
        lambda: SystemInfo(
            operating_system="Linux",
            distribution="Debian GNU/Linux 12",
            distribution_version="12",
            kernel_version="6.1.0-test",
            architecture="x86_64",
            python_version="3.12.0",
            hostname="test-host",
        ),
    )
    monkeypatch.setattr(
        main,
        "scan_installed_packages",
        lambda: PackageScanResult([], "mock inventory failure"),
    )
    output_file = tmp_path / "scan.json"
    attempted_paths = []

    def fail_write_text(path, data, *args, **kwargs):
        attempted_paths.append(path)
        raise OSError("mocked disk full")

    monkeypatch.setattr(main.Path, "write_text", fail_write_text)
    stdout = StringIO()

    exit_code = main.main(
        ["--json", "--output", str(output_file)], stdout=stdout
    )

    stderr = capsys.readouterr().err
    assert exit_code == 2
    assert attempted_paths == [output_file]
    assert "Could not write JSON output:" in stderr
    assert "mocked disk full" in stderr
    assert "Traceback" not in stderr
    assert stdout.getvalue() == ""


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


def test_cli_json_diagnostics_runs_real_build_result_end_to_end(monkeypatch, capsys):
    system_info = SystemInfo(
        operating_system="Linux",
        distribution="Ubuntu 24.04 LTS",
        distribution_version="24.04",
        kernel_version="6.8.0-test",
        architecture="x86_64",
        python_version="3.12.0",
        hostname="test-host",
    )
    package = Package("bash", "5.2.21-2ubuntu4", "bash", "5.2.21-2ubuntu4")
    monkeypatch.setattr(main, "collect_system_info", lambda: system_info)
    monkeypatch.setattr(main, "scan_installed_packages", lambda: PackageScanResult([package]))
    assessment_calls = {}

    def fake_assess_packages(packages, distribution, release, *, diagnostic=None):
        assessment_calls["packages"] = packages
        assessment_calls["distribution"] = distribution
        assessment_calls["release"] = release
        assessment_calls["diagnostic"] = diagnostic
        return VulnerabilityAssessmentReport(
            assessment_status="requires_review",
            distribution=distribution,
            release=release,
            source="mocked assessment source",
            error=None,
            packages=[PackageAssessment(
                package_name="bash",
                installed_version="5.2.21-2ubuntu4",
                assessment_status="requires_review",
                explanation="Mocked package assessment for CLI workflow coverage.",
                findings=[],
            )],
        )

    monkeypatch.setattr(main, "assess_packages", fake_assess_packages)
    stdout = StringIO()

    exit_code = main.main(["--json", "--diagnostics"], stdout=stdout)

    captured = capsys.readouterr()
    report = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert report["system_info"] == system_info.to_dict()
    assert report["package_scan"] == {
        "success": True,
        "error": None,
        "packages": [{"name": "bash", "version": "5.2.21-2ubuntu4"}],
    }
    assessment = report["vulnerability_assessment"]
    assert assessment["summary"]["total_assessed_packages"] == 1
    assert assessment["summary"]["status_counts"] == {"requires_review": 1}
    assert assessment["packages"][0]["package_name"] == "bash"
    assert assessment["packages"][0]["assessment_status"] == "requires_review"
    assert assessment_calls["packages"] == [package]
    assert assessment_calls["distribution"] == "Ubuntu 24.04 LTS"
    assert assessment_calls["release"] == "24.04"
    assert assessment_calls["diagnostic"] is not None
    assert "[diagnostic] System information collection started." in captured.err
    assert "[diagnostic] Package inventory started." in captured.err
    assert "[diagnostic] Report serialization completed in" in captured.err
    assert "[diagnostic] Report writing to stdout completed in" in captured.err
    assert "[diagnostic]" not in stdout.getvalue()


def test_cli_json_serializes_debian_review_finding_with_source_evidence(monkeypatch):
    system_info = SystemInfo(
        operating_system="Linux",
        distribution="Debian GNU/Linux 12",
        distribution_version="12",
        kernel_version="6.1.0-test",
        architecture="x86_64",
        python_version="3.12.0",
        hostname="test-host",
    )
    package = Package("openssh-server", "1:9.2p1-2+deb12u2", "openssh", "1:9.2p1-2+deb12u2")
    explanation = "The matching advisory has incomplete version-range data and requires review."
    finding = VulnerabilityFinding(
        advisory_id="DEBIAN-CVE-2024-9998",
        package_name=package.name,
        installed_version=package.version,
        source_reference="https://security-tracker.debian.org/tracker/CVE-2024-9998",
        severity=None,
        assessment_status="requires_review",
        explanation=explanation,
        source_package_name="openssh",
        source_version="1:9.2p1-2+deb12u2",
    )
    assessment = VulnerabilityAssessmentReport(
        assessment_status="requires_review",
        distribution="Debian GNU/Linux 12",
        release="12",
        source="Debian OSV via osv.dev",
        error=None,
        packages=[PackageAssessment(
            package_name=package.name,
            installed_version=package.version,
            assessment_status="requires_review",
            explanation=explanation,
            findings=[finding],
        )],
    )
    monkeypatch.setattr(main, "collect_system_info", lambda: system_info)
    monkeypatch.setattr(main, "scan_installed_packages", lambda: PackageScanResult([package]))
    monkeypatch.setattr(main, "assess_packages", lambda packages, distribution, release: assessment)
    stdout = StringIO()

    exit_code = main.main(["--json"], stdout=stdout)

    report = json.loads(stdout.getvalue())
    assessment_json = report["vulnerability_assessment"]
    assert exit_code == 0
    assert report["package_scan"]["success"] is True
    assert report["package_scan"]["packages"] == [
        {"name": "openssh-server", "version": "1:9.2p1-2+deb12u2"}
    ]
    assert assessment_json["summary"]["total_assessed_packages"] == 1
    assert assessment_json["summary"]["status_counts"] == {"requires_review": 1}
    serialized_finding = assessment_json["packages"][0]["findings"][0]
    assert serialized_finding["assessment_status"] == "requires_review"
    assert serialized_finding["advisory_id"] == "DEBIAN-CVE-2024-9998"
    assert serialized_finding["explanation"] == explanation
    assert serialized_finding["source_package_name"] == "openssh"
    assert serialized_finding["source_version"] == "1:9.2p1-2+deb12u2"


def test_build_result_reports_osv_error_when_inventory_succeeds(monkeypatch):
    system_info = SystemInfo(
        operating_system="Linux",
        distribution="Ubuntu 24.04 LTS",
        distribution_version="24.04",
        kernel_version="6.8.0-test",
        architecture="x86_64",
        python_version="3.12.0",
        hostname="test-host",
    )
    package = Package("bash", "5.2-2ubuntu1", "bash", "5.2-2ubuntu1")
    provider_error = "OSV query failed: offline"
    monkeypatch.setattr(main, "collect_system_info", lambda: system_info)
    monkeypatch.setattr(main, "scan_installed_packages", lambda: PackageScanResult([package]))

    def failed_assessment(packages, distribution, release):
        assert packages == [package]
        return VulnerabilityAssessmentReport(
            assessment_status="error",
            distribution=distribution,
            release=release,
            source="Ubuntu OSV via osv.dev",
            error=provider_error,
            packages=[PackageAssessment(
                package_name=package.name,
                installed_version=package.version,
                assessment_status="error",
                explanation=provider_error,
                findings=[],
            )],
        )

    monkeypatch.setattr(main, "assess_packages", failed_assessment)

    result = main.build_result()
    report = json.loads(json.dumps(result))
    assessment = report["vulnerability_assessment"]
    text = main._render_text(report)

    assert report["package_scan"]["success"] is True
    assert assessment["assessment_status"] == "error"
    assert assessment["source"] == "Ubuntu OSV via osv.dev"
    assert assessment["error"] == provider_error
    assert assessment["summary"]["total_assessed_packages"] == 1
    assert assessment["summary"]["status_counts"] == {"error": 1}
    assert assessment["packages"] == [{
        "package_name": "bash",
        "installed_version": "5.2-2ubuntu1",
        "assessment_status": "error",
        "explanation": provider_error,
        "findings": [],
    }]
    assert "Status: error" in text
    assert "Source: Ubuntu OSV via osv.dev" in text
    assert f"Details: {provider_error}" in text
    assert "Note: no_known_match means" not in text


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
    assert "Partial inventory:" not in output.getvalue()


def test_text_reports_retained_packages_as_partial_inventory():
    packages = [
        {"name": f"package-{index:02d}", "version": f"{index}.0"}
        for index in range(1, 13)
    ]
    report = {
        "system_info": {},
        "package_scan": {
            "success": False,
            "error": "dpkg-query returned 1 malformed package identity row; the inventory may be incomplete.",
            "packages": packages,
        },
    }

    text = main._render_text(report)

    assert "Scan failed: dpkg-query returned 1 malformed package identity row" in text
    assert "Partial inventory: 12 package(s) retained; this is not a complete inventory." in text
    for package in packages[:10]:
        assert f"  {package['name']} {package['version']}" in text
    assert "  package-11 11.0" not in text
    assert "  package-12 12.0" not in text
    assert "… and 2 more" in text


def test_successful_inventory_text_format_is_unchanged():
    report = {
        "system_info": {},
        "package_scan": {
            "success": True,
            "error": None,
            "packages": [
                {"name": "bash", "version": "5.2-2"},
                {"name": "libc6", "version": "2.36-9"},
            ],
        },
    }

    text = main._render_text(report)

    assert "Total packages found: 2" in text
    assert "  bash 5.2-2" in text
    assert "  libc6 2.36-9" in text
    assert "Partial inventory:" not in text
    assert "Scan failed:" not in text


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


def test_text_omits_no_match_warning_for_empty_assessment():
    assessment = VulnerabilityAssessmentReport(
        assessment_status="no_known_match",
        distribution="Debian GNU/Linux 12",
        release="12",
        source="Debian OSV via osv.dev",
        error=None,
        packages=[],
    ).to_dict()
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": assessment,
    }

    text = main._render_text(report)

    assert "Status: no_known_match" in text
    assert "Total assessed package entries: 0" in text
    assert "Note: " not in text


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
                "source_package_name": "openssh",
                "source_version": "1:9.2p1-2+deb12u2",
            }]}],
        },
    }

    finding = report["vulnerability_assessment"]["packages"][0]["findings"][0]
    finding["severity"] = "High"
    finding["explanation"] = "The installed source version is below the advisory's fixed version."

    text = main._render_text(report)

    assert "Severity: High" in text
    assert "Explanation: The installed source version is below the advisory's fixed version." in text
    assert "Summary: OpenSSH issue summary" in text
    assert "Debian urgency: high" in text
    assert "Source package: openssh 1:9.2p1-2+deb12u2" in text
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


def test_text_skips_malformed_null_findings_without_changing_package_counts():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "requires_review",
            "error": None,
            "packages": [{
                "assessment_status": "requires_review",
                "findings": None,
            }],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 1" in text
    assert "requires_review: 1" in text
    assert "CVE-" not in text


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
    assert "Source package:" not in text
    assert "Severity:" not in text
    assert "Explanation:" not in text


@pytest.mark.parametrize("severity, explanation", [(None, None), ("", "  ")])
def test_text_omits_unavailable_or_empty_finding_fields(severity, explanation):
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "requires_review", "error": None,
            "packages": [{"assessment_status": "requires_review", "findings": [{
                "advisory_id": "DEBIAN-CVE-2024-0001",
                "package_name": "openssl",
                "installed_version": "3.0.0",
                "assessment_status": "requires_review",
                "severity": severity,
                "explanation": explanation,
            }]}],
        },
    }

    text = main._render_text(report)

    assert "DEBIAN-CVE-2024-0001" in text
    assert "Severity:" not in text
    assert "Explanation:" not in text


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


def test_text_counts_malformed_package_entries_as_unknown():
    report = {
        "system_info": {},
        "package_scan": {"success": True, "error": None, "packages": []},
        "vulnerability_assessment": {
            "assessment_status": "requires_review", "error": None,
            "packages": [
                {"package_name": "bash", "assessment_status": "vulnerable"},
                "malformed entry",
                None,
                {"package_name": "curl", "assessment_status": "fixed"},
            ],
        },
    }

    text = main._render_text(report)

    assert "Total assessed package entries: 4" in text
    assert "vulnerable: 1" in text
    assert "fixed: 1" in text
    assert "unknown: 2" in text
    counts_section = text.split("Package assessment counts:\n", 1)[1].split("\n", 4)
    displayed_counts = [int(line.rsplit(": ", 1)[1]) for line in counts_section if ": " in line]
    assert sum(displayed_counts) == 4


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
    assert "Note: no_known_match means" not in main._render_text(serialized)


def test_cli_json_package_inventory_failure_exits_one_and_reports_error(monkeypatch):
    inventory_error = "dpkg-query failed: database unavailable"
    monkeypatch.setattr(
        main,
        "collect_system_info",
        lambda: SystemInfo(
            operating_system="Linux",
            distribution="Debian GNU/Linux 12",
            distribution_version="12",
            kernel_version="6.1.0-test",
            architecture="x86_64",
            python_version="3.12.0",
            hostname="test-host",
        ),
    )
    monkeypatch.setattr(
        main,
        "scan_installed_packages",
        lambda: PackageScanResult([], inventory_error),
    )
    stdout = StringIO()

    exit_code = main.main(["--json"], stdout=stdout)

    report = json.loads(stdout.getvalue())
    assessment = report["vulnerability_assessment"]
    assert exit_code == 1
    assert report["package_scan"] == {
        "success": False,
        "error": inventory_error,
        "packages": [],
    }
    assert assessment["assessment_status"] == "error"
    assert assessment["error"] == "Vulnerability assessment was not run because package inventory failed."
    assert assessment["summary"]["total_assessed_packages"] == 0
    assert assessment["summary"]["status_counts"] == {}


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
