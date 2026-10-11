"""Opt-in release-aware Debian OSV integration check."""

from __future__ import annotations

import os

import pytest

from scanner.package_scanner import Package
from scanner.vulnerability_assessment import OSVDebianProvider, ProviderResult, assess_packages


pytestmark = [
    pytest.mark.live_debian_osv,
    pytest.mark.skipif(
        os.environ.get("LINUXSECMONITOR_LIVE_DEBIAN_OSV") != "1",
        reason="Set LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 to enable live Debian OSV tests.",
    ),
]


def test_live_debian_osv_matches_documented_bookworm_advisory():
    """Validate CVE-2024-6387 against Debian 12's openssh source package."""
    # The Debian tracker/OSV record lists bookworm openssh fixed at
    # 1:9.2p1-2+deb12u3. The installed source version below is earlier.
    package = Package(
        "openssh-server",
        "1:9.2p1-2+deb12u2",
        source_name="openssh",
        source_version="1:9.2p1-2+deb12u2",
    )
    fetched = OSVDebianProvider().fetch_records([package], "Debian:12")
    assert fetched.error is None, fetched.error
    candidates = fetched.records_by_package[package.name]
    record = next(item.record for item in candidates if item.record.get("id") == "DEBIAN-CVE-2024-6387")
    affected = next(
        item for item in record["affected"]
        if item["package"].get("ecosystem") == "Debian:12"
        and item["package"].get("name") == "openssh"
    )
    assert any(
        event.get("fixed") == "1:9.2p1-2+deb12u3"
        for version_range in affected["ranges"]
        for event in version_range["events"]
    )

    class FetchedProvider:
        name = "live Debian OSV fixture"

        def fetch_records(self, packages, ecosystem):
            return ProviderResult(fetched.records_by_package, fetched.unmapped_packages, fetched.error)

    report = assess_packages([package], "Debian GNU/Linux 12 (bookworm)", "12", FetchedProvider())
    item = report.packages[0]
    finding = next(f for f in item.findings if f.advisory_id == "DEBIAN-CVE-2024-6387")
    assert report.release == "12"
    assert item.assessment_status == "vulnerable"
    assert finding.assessment_status == "vulnerable"
    assert finding.installed_version == "1:9.2p1-2+deb12u2"
    assert finding.source_reference == "https://security-tracker.debian.org/tracker/CVE-2024-6387"
