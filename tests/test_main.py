"""CLI formatting and JSON output tests."""

import json
from io import StringIO

import main


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
