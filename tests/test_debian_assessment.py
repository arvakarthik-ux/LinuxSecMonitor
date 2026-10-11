"""Offline tests for conservative Debian OSV matching."""

import json
import shutil
import subprocess

import pytest

from scanner.package_scanner import Package
from scanner.vulnerability_assessment import (
    DEBIAN_TRACKER_URL,
    OSV_QUERY_BATCH_URL,
    OSV_VULN_URL,
    OSVDebianProvider,
    ProviderResult,
    SourceRecord,
    _debian_version_compare,
    assess_packages,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self):
        return self.payload


class FakeProvider:
    name = "mock Debian OSV"

    def __init__(self, records=None, error=None):
        self.records = records or {}
        self.error = error

    def fetch_records(self, packages, ecosystem):
        return ProviderResult(self.records, error=self.error)


def advisory(*, ecosystem="Debian:12", source="openssh", fixed="1:9.2p1-2+deb12u3", ranges=None):
    affected_entry = {
        "package": {"name": source, "ecosystem": ecosystem},
        "ranges": ranges or [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": fixed},
        ]}],
    }
    return {
        "id": "DEBIAN-CVE-2024-6387",
        "affected": [affected_entry],
        "references": [{"type": "REPORT", "url": f"{DEBIAN_TRACKER_URL}CVE-2024-6387"}],
        "ecosystem_specific": {"urgency": "not yet assigned"},
    }


def package(version="1:9.2p1-2+deb12u2", *, source="openssh", source_version=None):
    return Package("openssh-server", "1:9.2p1-2+deb12u2", source, source_version or version)


def assess(record, pkg=None, distribution="Debian GNU/Linux 12", release="12"):
    pkg = pkg or package()
    records = {pkg.name: [SourceRecord(pkg.source_name or "", record)]} if record else {}
    return assess_packages([pkg], distribution, release, FakeProvider(records))


def test_debian_confirmed_affected_source_version_has_traceable_reference():
    report = assess(advisory())
    item = report.packages[0]
    finding = item.findings[0]
    assert report.assessment_status == "vulnerable"
    assert item.assessment_status == "vulnerable"
    assert finding.advisory_id == "DEBIAN-CVE-2024-6387"
    assert finding.source_reference == f"{DEBIAN_TRACKER_URL}CVE-2024-6387"
    assert finding.severity is None
    assert "source version" in finding.explanation


def test_debian_source_version_at_or_after_fixed_boundary_is_fixed():
    pkg = package("1:9.2p1-2+deb12u3")
    report = assess(advisory(), pkg)
    assert report.packages[0].assessment_status == "fixed"
    assert report.packages[0].findings[0].assessment_status == "fixed"


@pytest.mark.parametrize(
    ("ecosystem", "source"),
    [("Debian:13", "openssh"), ("Debian:12", "other-source")],
)
def test_debian_release_and_source_identity_must_match(ecosystem, source):
    report = assess(advisory(ecosystem=ecosystem, source=source))
    assert report.packages[0].assessment_status == "no_known_match"
    assert "does not establish" in report.packages[0].explanation


def test_missing_source_version_requires_review_without_binary_fallback():
    pkg = Package("openssh-server", "1:9.2p1-2+deb12u2", "openssh", None)
    report = assess(advisory(), pkg)
    assert report.packages[0].assessment_status == "requires_review"
    assert "no binary-version substitution" in report.packages[0].explanation


def test_missing_source_name_requires_review():
    pkg = Package("openssh-server", "1:9.2p1-2+deb12u2")
    report = assess(advisory(), pkg)
    assert report.packages[0].assessment_status == "requires_review"


def test_source_range_with_no_fix_is_not_called_fixed():
    record = advisory(fixed=None, ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}])
    report = assess(record)
    assert report.packages[0].assessment_status == "vulnerable"
    assert report.packages[0].findings[0].assessment_status == "vulnerable"


def test_version_before_advisory_introduction_is_not_mislabeled_fixed():
    record = advisory(ranges=[{"type": "ECOSYSTEM", "events": [
        {"introduced": "2.0"}, {"fixed": "3.0"},
    ]}])
    pkg = Package("openssh-server", "1.0", "openssh", "1.0")
    report = assess(record, pkg)
    assert report.packages[0].assessment_status == "not_affected"
    assert report.packages[0].findings[0].assessment_status == "not_affected"


def test_multiple_ranges_consider_a_later_vulnerable_interval():
    record = advisory(source="example-src", ranges=[
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "3.0"}, {"fixed": "4.0"}]},
    ])
    pkg = Package("example-bin", "3.5", "example-src", "3.5")
    report = assess(record, pkg)
    assert report.packages[0].assessment_status == "vulnerable"


def test_explicit_affected_versions_conflicting_with_fixed_range_require_review():
    record = advisory(fixed="2.0")
    record["affected"][0]["versions"] = ["3.0"]
    pkg = Package("openssh-server", "3.0", "openssh", "3.0")
    report = assess(record, pkg)
    assert report.packages[0].assessment_status == "requires_review"
    assert "conflicts" in report.packages[0].explanation


def test_unsupported_range_event_requires_review():
    record = advisory(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "2.0"}]}])
    report = assess(record)
    assert report.packages[0].assessment_status == "requires_review"


def test_debian_empty_success_is_no_known_match_and_kali_stays_unsupported():
    pkg = package()
    empty = assess_packages([pkg], "Debian GNU/Linux 12", "12", FakeProvider())
    kali = assess_packages([pkg], "Kali GNU/Linux Rolling", "2025.1", FakeProvider())
    assert empty.packages[0].assessment_status == "no_known_match"
    assert "does not establish" in empty.packages[0].explanation
    assert kali.assessment_status == "unsupported"
    assert kali.packages[0].assessment_status == "unsupported"


def test_assessment_summary_counts_each_package_entry_once():
    first = package()
    second = Package("unknown-package", "1.0", "unknown-source", "1.0")
    report = assess_packages(
        [first, second], "Debian GNU/Linux 12", "12", FakeProvider()
    ).to_dict()
    assert report["summary"]["total_assessed_packages"] == 2
    assert report["summary"]["status_counts"] == {"no_known_match": 2}
    assert report["summary"]["no_known_match_is_safe"] is False
    assert "not proof" in report["summary"]["no_known_match_note"]


def test_assessment_summary_handles_empty_results_and_unsupported_kali():
    empty = assess_packages([], "Debian GNU/Linux 12", "12", FakeProvider()).to_dict()
    kali = assess_packages(
        [package()], "Kali GNU/Linux Rolling", "2025.1", FakeProvider()
    ).to_dict()
    assert empty["summary"]["total_assessed_packages"] == 0
    assert empty["summary"]["status_counts"] == {}
    assert kali["summary"]["total_assessed_packages"] == 1
    assert kali["summary"]["status_counts"] == {"unsupported": 1}
    assert kali["distribution"] == "Kali GNU/Linux Rolling"
    assert kali["release"] == "2025.1"
    assert kali["source"] is None
    assert "not authoritative for Kali" in kali["error"]


def test_debian_provider_queries_source_ecosystem_and_hydrates_record():
    record = advisory()
    requested = []

    def opener(request, timeout):
        requested.append(request.full_url)
        if request.full_url == OSV_QUERY_BATCH_URL:
            assert json.loads(request.data)["queries"] == [{
                "package": {"name": "openssh", "ecosystem": "Debian:12"},
                "version": "1:9.2p1-2+deb12u2",
            }]
            return FakeResponse({"results": [{"vulns": [{"id": record["id"]}]}]})
        assert request.full_url == OSV_VULN_URL + record["id"]
        return FakeResponse(record)

    result = OSVDebianProvider(opener=opener).fetch_records([package()], "Debian:12")
    assert result.error is None
    assert requested == [OSV_QUERY_BATCH_URL, OSV_VULN_URL + record["id"]]
    assert result.records_by_package["openssh-server"][0].record == record


def test_debian_provider_hydrates_repeated_advisory_once_and_keeps_associations():
    first = Package("openssh-server", "1.0", "openssh", "1.0")
    second = Package("openssl", "2.0", "openssl", "2.0")
    record = advisory(source="openssh")
    record["affected"].append({
        "package": {"name": "openssl", "ecosystem": "Debian:12"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
    })
    get_requests = []

    def opener(request, timeout):
        if request.full_url == OSV_QUERY_BATCH_URL:
            assert len(json.loads(request.data)["queries"]) == 2
            return FakeResponse({"results": [
                {"vulns": [{"id": record["id"]}, {"id": record["id"]}]},
                {"vulns": [{"id": record["id"]}]},
            ]})
        get_requests.append(request.full_url)
        assert request.full_url == OSV_VULN_URL + record["id"]
        return FakeResponse(record)

    fetched = OSVDebianProvider(opener=opener).fetch_records(
        [first, second], "Debian:12"
    )

    assert fetched.error is None
    assert get_requests == [OSV_VULN_URL + record["id"]]
    assert [item.source_package for item in fetched.records_by_package[first.name]] == ["openssh"]
    assert [item.source_package for item in fetched.records_by_package[second.name]] == ["openssl"]
    assert fetched.records_by_package[first.name][0].record is fetched.records_by_package[second.name][0].record


def test_debian_provider_timeout_becomes_an_error_assessment():
    record_id = "DEBIAN-CVE-2024-6387"

    def opener(request, timeout):
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": record_id}]}]})
        raise TimeoutError("OSV request timed out")

    report = assess_packages(
        [package()], "Debian GNU/Linux 12", "12",
        OSVDebianProvider(opener=opener),
    )

    assert report.assessment_status == "error"
    assert report.error.startswith("Debian OSV data retrieval failed:")
    assert "timed out" in report.error
    assert all(item.assessment_status == "error" for item in report.packages)


def test_debian_provider_reports_network_and_malformed_record_errors():
    def offline(*args, **kwargs):
        raise OSError("offline")

    failed = OSVDebianProvider(opener=offline).fetch_records([package()], "Debian:12")
    assert "retrieval failed" in failed.error

    responses = iter([
        FakeResponse({"results": [{"vulns": [{"id": "DEBIAN-CVE-2024-6387"}]}]}),
        FakeResponse({"id": "DEBIAN-CVE-2024-6387", "affected": []}),
    ])
    malformed = OSVDebianProvider(opener=lambda *args, **kwargs: next(responses)).fetch_records(
        [package()], "Debian:12"
    )
    assert "malformed" in malformed.error

    responses = iter([
        FakeResponse({"results": [{"vulns": [{"id": "DEBIAN-CVE-2024-6387"}]}]}),
        FakeResponse({"id": "DEBIAN-CVE-2024-6387", "affected": [{}]}),
    ])
    malformed_identity = OSVDebianProvider(
        opener=lambda *args, **kwargs: next(responses)
    ).fetch_records([package()], "Debian:12")
    assert "malformed package identity" in malformed_identity.error


def test_debian_version_comparator_matches_dpkg_when_available():
    dpkg = shutil.which("dpkg")
    if not dpkg:
        pytest.skip("dpkg --compare-versions is unavailable on this platform")
    pairs = [
        ("1.0~rc1-1", "1.0-1"),
        ("1:1.0-1", "2.0-99"),
        ("1.0-1", "1.0-1+b1"),
        ("1.0-1~deb12u1", "1.0-1"),
        ("1.0", "1.0-0"),
        ("1.0-01", "1.0-1"),
        ("1.0+really2-1", "1.0-1"),
    ]
    for left, right in pairs:
        dpkg_result = subprocess.run(
            [dpkg, "--compare-versions", left, "lt", right], capture_output=True, check=False
        )
        dpkg_greater = subprocess.run(
            [dpkg, "--compare-versions", left, "gt", right], capture_output=True, check=False
        )
        expected = -1 if dpkg_result.returncode == 0 else 1 if dpkg_greater.returncode == 0 else 0
        assert (_debian_version_compare(left, right) > 0) - (_debian_version_compare(left, right) < 0) == expected
