"""CLI formatting and JSON output tests."""

import json
from io import StringIO

import main
from scanner.package_scanner import Package, PackageScanResult


def test_json_output_format(monkeypatch):
    monkeypatch.setattr(main, "build_result", lambda: {
        "system_info": {"operating_system": "Linux"},
        "package_scan": {"success": True, "error": None, "packages": [{"name": "bash", "version": "1"}]},
    })
    output = StringIO()
    assert main.main(["--json"], stdout=output) == 0
    assert json.loads(output.getvalue())["package_scan"]["packages"][0]["name"] == "bash"


def test_json_output_file(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "build_result", lambda: {
        "system_info": {}, "package_scan": {"success": True, "error": None, "packages": []},
    })
    output_file = tmp_path / "scan.json"
    assert main.main(["--json", "--output", str(output_file)], stdout=StringIO()) == 0
    assert json.loads(output_file.read_text())["package_scan"]["success"] is True


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
