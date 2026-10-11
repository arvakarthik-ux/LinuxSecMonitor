"""Opt-in checks against a documented Ubuntu OSV advisory and live API."""

from __future__ import annotations

import os

import pytest

from scanner.package_scanner import Package
from scanner.vulnerability_assessment import assess_packages


pytestmark = [
    pytest.mark.live_osv,
    pytest.mark.skipif(
        os.environ.get("LINUXSECMONITOR_LIVE_OSV") != "1",
        reason="Set LINUXSECMONITOR_LIVE_OSV=1 to enable live OSV integration tests.",
    ),
]


def test_live_ubuntu_osv_matches_release_package_and_fixed_version():
    """Confirm a live Ubuntu 22.04 record includes matching binary evidence."""
    # Canonical's Ubuntu OSV record for CVE-2022-3715 lists bash on
    # Ubuntu 22.04 LTS with fixed binary version 5.1-6ubuntu1.1.
    report = assess_packages(
        [Package("bash", "5.1-6ubuntu1")],
        "Ubuntu 22.04 LTS",
        "22.04",
    )

    assert report.assessment_status != "error", report.error
    assert report.release == "22.04"
    assert report.source == "Ubuntu OSV via osv.dev"
    package = next(item for item in report.packages if item.package_name == "bash")
    finding = next(
        item for item in package.findings if item.advisory_id == "UBUNTU-CVE-2022-3715"
    )
    assert package.assessment_status == "vulnerable"
    assert finding.assessment_status == "vulnerable"
    assert finding.installed_version == "5.1-6ubuntu1"
    assert finding.source_reference == "https://ubuntu.com/security/CVE-2022-3715"
