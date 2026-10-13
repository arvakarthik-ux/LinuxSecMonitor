"""Offline tests for conservative Debian OSV matching."""

import json
import shutil
import subprocess
import threading

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


def test_debian_tracker_reference_must_match_the_advisory_identity():
    record = advisory()
    record["references"] = [{
        "type": "REPORT",
        "url": f"{DEBIAN_TRACKER_URL}CVE-2024-0000",
    }]

    finding = assess(record).packages[0].findings[0]

    # A wrong Tracker URL is ignored; a known Debian-CVE ID can be linked to
    # its corresponding Tracker entry without trusting the unrelated URL.
    assert finding.source_reference == f"{DEBIAN_TRACKER_URL}CVE-2024-6387"


def test_debian_source_version_at_or_after_fixed_boundary_is_fixed():
    pkg = package("1:9.2p1-2+deb12u3")
    report = assess(advisory(), pkg)
    assert report.packages[0].assessment_status == "fixed"
    assert report.packages[0].findings[0].assessment_status == "fixed"


@pytest.mark.parametrize(
    ("source_version", "expected_status"),
    [
        ("1:9.2p1-2+deb12u3~rc1", "vulnerable"),
        ("1:9.2p1-2+deb12u3", "fixed"),
        ("1:9.2p1-2+deb12u3+b1", "fixed"),
    ],
)
def test_debian_fixed_boundary_compares_revision_suffixes(source_version, expected_status):
    report = assess(advisory(), package(source_version))
    assert report.packages[0].assessment_status == expected_status
    assert report.packages[0].findings[0].assessment_status == expected_status


def test_explicit_debian_affected_version_is_vulnerable_without_ranges():
    record = advisory()
    record["affected"][0].pop("ranges")
    record["affected"][0]["versions"] = ["1:9.2p1-2+deb12u2"]

    finding = assess(record).packages[0].findings[0]

    assert finding.assessment_status == "vulnerable"
    assert finding.source_reference == f"{DEBIAN_TRACKER_URL}CVE-2024-6387"


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


def test_explicit_affected_version_conflicting_with_pre_introduction_range_requires_review():
    record = advisory(ranges=[{"type": "ECOSYSTEM", "events": [
        {"introduced": "2.0"}, {"fixed": "3.0"},
    ]}])
    record["affected"][0]["versions"] = ["1.0"]
    pkg = Package("openssh-server", "1.0", "openssh", "1.0")

    item = assess(record, pkg).packages[0]

    assert item.assessment_status == "requires_review"
    assert "conflicts" in item.explanation


def test_explicit_affected_versions_use_debian_version_equivalence():
    record = advisory(fixed="1.0")
    record["affected"][0]["versions"] = ["1.0-0"]
    pkg = Package("openssh-server", "1.0", "openssh", "1.0")

    item = assess(record, pkg).packages[0]

    # Debian treats a missing revision as revision zero. The explicit affected
    # evidence therefore conflicts with a range whose fixed boundary is 1.0.
    assert item.assessment_status == "requires_review"
    assert "conflicts" in item.explanation


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


def test_debian_findings_are_associated_with_binaries_sharing_a_source_package():
    source_version = "1:2.48.1-1"
    packages = [
        Package("libwebkit2gtk-6.0-4", source_version, "webkit2gtk", source_version),
        Package("webkit2gtk-driver", source_version, "webkit2gtk", source_version),
    ]
    record = advisory(
        source="webkit2gtk", fixed="1:2.48.1-2",
    )

    def opener(request, timeout):
        if request.full_url == OSV_QUERY_BATCH_URL:
            queries = json.loads(request.data)["queries"]
            assert len(queries) == 1
            assert queries[0]["package"]["name"] == "webkit2gtk"
            return FakeResponse({"results": [{"vulns": [{"id": record["id"]}]}]})
        return FakeResponse(record)

    report = assess_packages(
        packages,
        "Debian GNU/Linux 12",
        "12",
        OSVDebianProvider(opener=opener),
    )

    assert [item.assessment_status for item in report.packages] == ["vulnerable", "vulnerable"]
    assert [item.findings[0].package_name for item in report.packages] == [
        "libwebkit2gtk-6.0-4",
        "webkit2gtk-driver",
    ]


def test_debian_provider_uses_complete_query_record_without_hydration_request():
    record = advisory()
    requested_urls = []

    def opener(request, timeout):
        requested_urls.append(request.full_url)
        return FakeResponse({"results": [{"vulns": [{"id": record["id"]}, record]}]})

    messages = []
    fetched = OSVDebianProvider(
        opener=opener, diagnostic=messages.append
    ).fetch_records([package()], "Debian:12")

    assert fetched.error is None
    assert requested_urls == [OSV_QUERY_BATCH_URL]
    assert fetched.records_by_package["openssh-server"][0].record == record
    assert any(
        "requested=2, cached=1, newly_fetched=0, inline=1, unique_ids=1" in message
        for message in messages
    )


def test_debian_provider_diagnostics_report_batch_hydration_and_periodic_progress():
    record = advisory()
    stubs = [{"id": record["id"]} for _ in range(101)]
    messages = []

    def opener(request, timeout):
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": stubs}]})
        return FakeResponse(record)

    fetched = OSVDebianProvider(opener=opener, diagnostic=messages.append).fetch_records(
        [package()], "Debian:12"
    )

    assert fetched.error is None
    assert any("OSV query preparation started for 1 package entries" in message for message in messages)
    assert any(message.startswith("OSV query preparation completed in") for message in messages)
    assert "OSV batch 1/1 started: 1 queries." in messages
    assert any(message.startswith("OSV batch 1/1 completed in") for message in messages)
    assert any("Advisory hydration progress: 101/101 references" in message for message in messages)
    assert any(
        "Advisory hydration completed" in message
        and "requested=101, cached=100, newly_fetched=1, inline=0, unique_ids=1" in message
        for message in messages
    )


def test_debian_provider_hydration_uses_configured_bounded_concurrency():
    advisory_ids = [f"DEBIAN-CVE-2024-{index}" for index in range(1, 5)]
    active = 0
    peak_active = 0
    lock = threading.Lock()
    simultaneous_requests = threading.Barrier(2)

    def opener(request, timeout):
        nonlocal active, peak_active
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": item} for item in advisory_ids]}]})

        advisory_id = request.full_url.removeprefix(OSV_VULN_URL)
        with lock:
            active += 1
            peak_active = max(peak_active, active)
        try:
            simultaneous_requests.wait(timeout=3)
            record = advisory()
            record["id"] = advisory_id
            return FakeResponse(record)
        finally:
            with lock:
                active -= 1

    fetched = OSVDebianProvider(
        opener=opener, max_hydration_workers=2
    ).fetch_records([package()], "Debian:12")

    assert fetched.error is None
    assert peak_active == 2
    assert [item.record["id"] for item in fetched.records_by_package["openssh-server"]] == advisory_ids


def test_diagnostic_callback_failure_does_not_change_debian_assessment():
    def broken_diagnostics(_message):
        raise RuntimeError("diagnostic stream failure")

    report = assess_packages(
        [package()], "Debian GNU/Linux 12", "12", FakeProvider(),
        diagnostic=broken_diagnostics,
    )

    assert report.assessment_status == "no_known_match"
    assert report.packages[0].assessment_status == "no_known_match"


def test_debian_matching_diagnostics_report_count_based_progress():
    packages = [
        Package(f"sample-{index}", "1.0", "sample-source", "1.0")
        for index in range(101)
    ]
    messages = []

    report = assess_packages(
        packages, "Debian GNU/Linux 12", "12", FakeProvider(),
        diagnostic=messages.append,
    )

    assert report.assessment_status == "no_known_match"
    assert any("Vulnerability matching started for 101 package entries" in message for message in messages)
    assert "Vulnerability matching progress: 100/101 package entries." in messages
    assert any(message.startswith("Vulnerability matching completed in") for message in messages)


def test_debian_provider_timeout_becomes_an_error_assessment():
    record_id = "DEBIAN-CVE-2024-6387"

    def opener(request, timeout):
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": record_id}]}]})
        raise TimeoutError("OSV request timed out")

    messages = []
    report = assess_packages(
        [package()], "Debian GNU/Linux 12", "12",
        OSVDebianProvider(opener=opener, diagnostic=messages.append),
        diagnostic=messages.append,
    )

    assert report.assessment_status == "error"
    assert report.error.startswith("Debian OSV data retrieval failed:")
    assert "timed out" in report.error
    assert all(item.assessment_status == "error" for item in report.packages)
    assert any("OSV advisory hydration failed after" in message for message in messages)
    assert any("matching skipped" in message.lower() for message in messages)


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
