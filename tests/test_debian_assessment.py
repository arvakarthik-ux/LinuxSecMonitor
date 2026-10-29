"""Offline tests for conservative Debian OSV matching."""

import hashlib
import json
import shutil
import subprocess
import threading
import time

import pytest

from scanner.package_scanner import Package
import scanner.vulnerability_assessment as vulnerability_assessment
from scanner.vulnerability_assessment import (
    DEFAULT_OSV_CACHE_TTL_SECONDS,
    DEBIAN_TRACKER_URL,
    OSV_QUERY_BATCH_URL,
    OSV_VULN_URL,
    OSVDebianProvider,
    ProviderResult,
    SourceRecord,
    _debian_range_status,
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

    def read(self, size=-1):
        return self.payload if size < 0 else self.payload[:size]


@pytest.fixture(autouse=True)
def isolate_default_osv_cache(tmp_path, monkeypatch):
    """Keep provider tests independent of a developer's persistent cache."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))


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
        "ecosystem_specific": {"urgency": "not yet assigned"},
    }
    return {
        "id": "DEBIAN-CVE-2024-6387",
        "affected": [affected_entry],
        "references": [{"type": "REPORT", "url": f"{DEBIAN_TRACKER_URL}CVE-2024-6387"}],
    }


def package(version="1:9.2p1-2+deb12u2", *, source="openssh", source_version=None):
    return Package("openssh-server", "1:9.2p1-2+deb12u2", source, source_version or version)


def assess(record, pkg=None, distribution="Debian GNU/Linux 12", release="12"):
    pkg = pkg or package()
    records = {pkg.name: [SourceRecord(pkg.source_name or "", record)]} if record else {}
    return assess_packages([pkg], distribution, release, FakeProvider(records))


def assess_records(records, pkg=None):
    """Assess one Debian package against several independent advisories."""
    pkg = pkg or package()
    source_records = [SourceRecord(pkg.source_name or "", record) for record in records]
    return assess_packages(
        [pkg], "Debian GNU/Linux 12", "12",
        FakeProvider({pkg.name: source_records}),
    )


def test_debian_confirmed_affected_source_version_has_traceable_reference():
    report = assess(advisory())
    item = report.packages[0]
    finding = item.findings[0]
    assert report.assessment_status == "vulnerable"
    assert item.assessment_status == "vulnerable"
    assert finding.advisory_id == "DEBIAN-CVE-2024-6387"
    assert finding.source_reference == f"{DEBIAN_TRACKER_URL}CVE-2024-6387"
    assert finding.severity is None
    assert finding.urgency == "not yet assigned"
    assert finding.source_package_name == "openssh"
    assert finding.source_version == "1:9.2p1-2+deb12u2"
    assert "source version" in finding.explanation
    serialized_finding = report.to_dict()["packages"][0]["findings"][0]
    assert serialized_finding["package_name"] == "openssh-server"
    assert serialized_finding["installed_version"] == "1:9.2p1-2+deb12u2"
    assert serialized_finding["source_reference"] == f"{DEBIAN_TRACKER_URL}CVE-2024-6387"
    assert serialized_finding["assessment_status"] == "vulnerable"
    assert serialized_finding["source_package_name"] == "openssh"
    assert serialized_finding["source_version"] == "1:9.2p1-2+deb12u2"


def test_debian_urgency_uses_matching_release_and_source_without_changing_status_or_severity():
    record = advisory()
    record["affected"].insert(0, {
        "package": {"name": "openssh", "ecosystem": "Debian:11"},
        "ecosystem_specific": {"urgency": "critical"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
    })
    record["affected"].append({
        "package": {"name": "other-source", "ecosystem": "Debian:12"},
        "ecosystem_specific": {"urgency": "high"},
    })

    report = assess(record)
    finding = report.packages[0].findings[0]

    assert finding.urgency == "not yet assigned"
    assert finding.severity is None
    assert finding.assessment_status == "vulnerable"
    assert report.packages[0].assessment_status == "vulnerable"


def test_debian_advisory_context_omits_missing_metadata_and_invalid_references():
    record = advisory()
    record.pop("summary", None)
    record.pop("details", None)
    record["references"] = [
        {"type": "REPORT", "url": "javascript:alert(1)"},
        {"type": "WEB", "url": "https://[malformed"},
        {"url": 42},
    ]
    record["affected"][0].pop("ecosystem_specific")

    serialized = assess(record).to_dict()
    finding = serialized["packages"][0]["findings"][0]

    assert record["id"] not in serialized["advisory_context"]
    assert "urgency" not in finding


def test_repeated_advisory_id_has_one_advisory_context_entry():
    record = advisory()
    record["summary"] = "OpenSSH advisory summary"
    record["details"] = "Advisory details from OSV."
    first = package()
    second = Package("openssh-client", first.version, first.source_name, first.source_version)
    report = assess_packages(
        [first, second], "Debian GNU/Linux 12", "12",
        FakeProvider({first.name: [SourceRecord("openssh", record)],
                      second.name: [SourceRecord("openssh", record)]}),
    ).to_dict()

    assert list(report["advisory_context"]) == [record["id"]]
    assert report["advisory_context"][record["id"]]["summary"] == "OpenSSH advisory summary"
    assert report["advisory_context"][record["id"]]["details"] == "Advisory details from OSV."
    assert report["advisory_context"][record["id"]]["references"] == [
        {"url": f"{DEBIAN_TRACKER_URL}CVE-2024-6387", "type": "REPORT"}
    ]


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


def test_debian_vulnerable_and_fixed_advisories_keep_both_findings_and_vulnerable_status():
    vulnerable = advisory()
    fixed = advisory(fixed="1:9.2p1-2+deb12u1")
    fixed["id"] = "DEBIAN-CVE-2024-9998"

    report = assess_records([vulnerable, fixed])
    item = report.packages[0]

    assert item.assessment_status == "vulnerable"
    assert [(finding.advisory_id, finding.assessment_status) for finding in item.findings] == [
        (vulnerable["id"], "vulnerable"),
        (fixed["id"], "fixed"),
    ]
    assert report.to_dict()["summary"]["status_counts"] == {"vulnerable": 1}


def test_debian_vulnerable_and_review_advisories_preserve_both_evidence_records():
    vulnerable = advisory()
    review = advisory(ranges="malformed")
    review["id"] = "DEBIAN-CVE-2024-9998"

    report = assess_records([vulnerable, review])
    item = report.packages[0]

    assert item.assessment_status == "vulnerable"
    assert [(finding.advisory_id, finding.assessment_status) for finding in item.findings] == [
        (vulnerable["id"], "vulnerable"),
        (review["id"], "requires_review"),
    ]
    assert item.findings[1].source_reference == f"{DEBIAN_TRACKER_URL}CVE-2024-9998"
    assert "no usable ranges" in item.findings[1].explanation
    serialized_findings = report.to_dict()["packages"][0]["findings"]
    assert serialized_findings[1]["advisory_id"] == review["id"]
    assert "no usable ranges" in serialized_findings[1]["explanation"]
    assert report.to_dict()["summary"]["status_counts"] == {"vulnerable": 1}


def test_debian_fixed_and_review_advisories_report_review_and_keep_fixed_finding():
    fixed = advisory(fixed="1:9.2p1-2+deb12u1")
    review = advisory(ranges="malformed")
    review["id"] = "DEBIAN-CVE-2024-9998"

    report = assess_records([fixed, review])
    item = report.packages[0]

    assert item.assessment_status == "requires_review"
    assert [(finding.advisory_id, finding.assessment_status) for finding in item.findings] == [
        (fixed["id"], "fixed"),
    ]
    assert "no usable ranges" in item.explanation
    assert report.to_dict()["summary"]["status_counts"] == {"requires_review": 1}


def test_debian_multiple_vulnerable_advisories_have_distinct_findings_but_one_package_count():
    first = advisory()
    second = advisory()
    second["id"] = "DEBIAN-CVE-2024-9998"

    report = assess_records([first, second])
    item = report.packages[0]

    assert item.assessment_status == "vulnerable"
    assert [finding.advisory_id for finding in item.findings] == [first["id"], second["id"]]
    assert all(finding.assessment_status == "vulnerable" for finding in item.findings)
    assert report.to_dict()["summary"]["total_assessed_packages"] == 1
    assert report.to_dict()["summary"]["status_counts"] == {"vulnerable": 1}


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


@pytest.mark.parametrize("invalid_version", ["banana", "1.0-", "1:", "abc:1.0"])
def test_debian_version_comparator_rejects_malformed_syntax(invalid_version):
    with pytest.raises(ValueError):
        _debian_version_compare(invalid_version, "1.0-1")


@pytest.mark.parametrize("invalid_version", ["banana", "1.0-", "1:"])
def test_debian_invalid_installed_source_version_requires_review(invalid_version):
    report = assess(advisory(), package(invalid_version))

    assert report.packages[0].assessment_status == "requires_review"
    assert report.packages[0].findings == []


@pytest.mark.parametrize("invalid_boundary", ["banana", "1.0-", "1:"])
def test_debian_malformed_range_boundary_requires_review(invalid_boundary):
    report = assess(advisory(fixed=invalid_boundary))

    assert report.packages[0].assessment_status == "requires_review"
    assert report.packages[0].findings == []


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
    assert report.packages[0].findings == []
    assert report.to_dict()["packages"][0]["findings"] == []


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


@pytest.mark.parametrize("malformed_ranges", [
    "not-a-range-list",
    [{"type": "ECOSYSTEM", "events": "not-an-event-list"}],
])
def test_malformed_debian_range_structure_requires_review(malformed_ranges):
    record = advisory()
    record["affected"][0]["ranges"] = malformed_ranges

    item = assess(record).packages[0]

    assert item.assessment_status == "requires_review"
    assert item.findings == []


def test_debian_range_validates_unsupported_event_after_earlier_affected_match():
    record = advisory(ranges=[{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "2.0"}, {"last_affected": "3.0"},
    ]}])

    item = assess(record, package("1.0")).packages[0]

    assert item.assessment_status == "requires_review"
    assert item.findings == []


@pytest.mark.parametrize("malformed_event", [
    {"introduced": "banana"},
    {"fixed": ""},
    "not-an-event",
])
def test_debian_range_validates_malformed_trailing_event_after_fixed(malformed_event):
    record = advisory(ranges=[{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "2.0"}, malformed_event,
    ]}])

    item = assess(record, package("1.0")).packages[0]

    assert item.assessment_status == "requires_review"
    assert item.findings == []


@pytest.mark.parametrize(
    ("installed", "expected"),
    [("1.0", "vulnerable"), ("2.0", "fixed")],
)
def test_debian_complete_introduced_fixed_range_keeps_existing_results(installed, expected):
    result, _ = _debian_range_status(
        {"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "2.0"},
        ]},
        installed,
    )

    assert result == expected


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


@pytest.mark.parametrize("query_payload", [[], {"unexpected": []}])
def test_debian_unexpected_query_response_structure_is_an_error(query_payload):
    def opener(request, timeout):
        return FakeResponse(query_payload)

    report = assess_packages(
        [package()], "Debian GNU/Linux 12", "12",
        OSVDebianProvider(opener=opener),
    )

    assert report.assessment_status == "error"
    assert report.packages[0].assessment_status == "error"
    assert report.packages[0].findings == []
    assert "no results list" in report.error


@pytest.mark.parametrize("advisory_id", ["", " \t\n"])
def test_debian_blank_advisory_id_is_rejected_without_producing_findings(advisory_id):
    requested_urls = []

    def opener(request, timeout):
        requested_urls.append(request.full_url)
        return FakeResponse({"results": [{"vulns": [{"id": advisory_id}]}]})

    report = assess_packages(
        [package()], "Debian GNU/Linux 12", "12",
        OSVDebianProvider(opener=opener),
    )

    assert report.assessment_status == "error"
    assert report.packages[0].assessment_status == "error"
    assert report.packages[0].findings == []
    assert requested_urls == [OSV_QUERY_BATCH_URL]


def test_debian_cache_miss_fetches_and_stores_valid_full_record(tmp_path):
    record = advisory()
    messages = []
    requested = []

    def opener(request, timeout):
        requested.append(request.full_url)
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": record["id"]}]}]})
        return FakeResponse(record)

    provider = OSVDebianProvider(
        opener=opener, cache_dir=tmp_path / "cache", diagnostic=messages.append
    )
    fetched = provider.fetch_records([package()], "Debian:12")

    assert fetched.error is None
    assert requested == [OSV_QUERY_BATCH_URL, OSV_VULN_URL + record["id"]]
    cache_path = provider._cache.path_for(record["id"])
    assert cache_path.name == hashlib.sha256(record["id"].encode("utf-8")).hexdigest() + ".json"
    cached_entry = json.loads(cache_path.read_text())
    assert cached_entry["record"] == record
    assert any("hits=0, misses=1" in line and "writes=1" in line for line in messages)


def test_debian_cache_ttl_defaults_to_one_day_and_is_configurable(tmp_path):
    default_provider = OSVDebianProvider(cache_dir=tmp_path / "default")
    configured_provider = OSVDebianProvider(
        cache_dir=tmp_path / "custom", cache_ttl_seconds=90
    )

    assert default_provider._cache.ttl_seconds == 24 * 60 * 60
    assert default_provider._cache.ttl_seconds == DEFAULT_OSV_CACHE_TTL_SECONDS
    assert configured_provider._cache.ttl_seconds == 90


def test_debian_cache_hit_skips_hydration_but_repeats_querybatch(tmp_path):
    record = advisory()
    requested = []
    messages = []

    def opener(request, timeout):
        requested.append(request.full_url)
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": record["id"]}]}]})
        return FakeResponse(record)

    provider = OSVDebianProvider(
        opener=opener, cache_dir=tmp_path / "cache", diagnostic=messages.append
    )
    first = provider.fetch_records([package()], "Debian:12")
    messages.clear()
    second = provider.fetch_records([package()], "Debian:12")

    assert first.error is None and second.error is None
    assert requested.count(OSV_QUERY_BATCH_URL) == 2
    assert requested.count(OSV_VULN_URL + record["id"]) == 1
    assert second.records_by_package["openssh-server"][0].record == record
    assert any(
        "OSV advisory cache: hits=1, misses=0, expired_or_invalid=0, writes=0" in line
        for line in messages
    )


def test_debian_expired_cache_entry_is_refetched(tmp_path):
    record = advisory()
    requested_gets = []

    def opener(request, timeout):
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": record["id"]}]}]})
        requested_gets.append(request.full_url)
        return FakeResponse(record)

    cache_dir = tmp_path / "cache"
    provider = OSVDebianProvider(opener=opener, cache_dir=cache_dir)
    assert provider.fetch_records([package()], "Debian:12").error is None
    cache_path = provider._cache.path_for(record["id"])
    cached = json.loads(cache_path.read_text())
    cached["cached_at"] = 1
    cache_path.write_text(json.dumps(cached), encoding="utf-8")
    messages = []
    provider = OSVDebianProvider(
        opener=opener, cache_dir=cache_dir, diagnostic=messages.append
    )

    refetched = provider.fetch_records([package()], "Debian:12")

    assert refetched.error is None
    assert len(requested_gets) == 2
    assert any("expired_or_invalid=1" in line and "misses=1" in line for line in messages)


def test_debian_expired_cache_entry_with_failed_refresh_reports_error(tmp_path, monkeypatch):
    record = advisory()
    fixed_now = 200_000
    requested_urls = []
    messages = []

    def opener(request, timeout):
        requested_urls.append(request.full_url)
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": record["id"]}]}]})
        raise OSError("mock network unavailable")

    cache_dir = tmp_path / "cache"
    provider = OSVDebianProvider(
        opener=opener, cache_dir=cache_dir, diagnostic=messages.append
    )
    monkeypatch.setattr(provider._cache, "_clock", lambda: fixed_now)
    provider._cache.store(record["id"], record)
    cache_path = provider._cache.path_for(record["id"])
    cached_entry = json.loads(cache_path.read_text(encoding="utf-8"))
    cached_entry["cached_at"] = 1
    cache_path.write_text(json.dumps(cached_entry), encoding="utf-8")

    report = assess_packages(
        [package()], "Debian GNU/Linux 12", "12", provider
    )

    assert requested_urls == [OSV_QUERY_BATCH_URL, OSV_VULN_URL + record["id"]]
    assert report.assessment_status == "error"
    assert report.error.startswith("Debian OSV data retrieval failed:")
    assert report.packages[0].assessment_status == "error"
    assert report.packages[0].findings == []
    assert any(
        "hits=0, misses=1, expired_or_invalid=1" in message
        for message in messages
    )
    assert cache_path.is_file()
    remaining_entry = json.loads(cache_path.read_text(encoding="utf-8"))
    assert remaining_entry["cached_at"] == 1
    assert remaining_entry["record"] == record
    assert provider._cache.load(record["id"]) == (None, "expired")


@pytest.mark.parametrize("cached_content", [
    "{malformed-json",
    json.dumps({
        "schema_version": 1,
        "advisory_id": "DEBIAN-CVE-2024-6387",
        "cached_at": time.time(),
        "record": {"id": "DEBIAN-CVE-2024-6387", "affected": [{}]},
    }),
])
def test_debian_malformed_or_invalid_cache_record_is_refetched(tmp_path, cached_content):
    record = advisory()
    provider = OSVDebianProvider(cache_dir=tmp_path / "cache")
    cache_path = provider._cache.path_for(record["id"])
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text(cached_content, encoding="utf-8")
    requested_gets = []
    messages = []

    def opener(request, timeout):
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": record["id"]}]}]})
        requested_gets.append(request.full_url)
        return FakeResponse(record)

    provider = OSVDebianProvider(
        opener=opener, cache_dir=cache_path.parent, diagnostic=messages.append
    )
    result = provider.fetch_records([package()], "Debian:12")

    assert result.error is None
    assert requested_gets == [OSV_VULN_URL + record["id"]]
    assert any("expired_or_invalid=1" in line for line in messages)
    assert json.loads(cache_path.read_text(encoding="utf-8"))["record"] == record


def test_debian_cache_read_write_failures_fall_back_and_clean_temp_files(tmp_path, monkeypatch):
    record = advisory()
    cache_dir = tmp_path / "cache"
    provider = OSVDebianProvider(cache_dir=cache_dir)
    cache_path = provider._cache.path_for(record["id"])
    cache_path.parent.mkdir(parents=True)
    cache_path.mkdir()
    messages = []
    requested_gets = []

    def fail_replace(source, target):
        raise OSError("mock atomic replace failure")

    monkeypatch.setattr(vulnerability_assessment.os, "replace", fail_replace)

    def opener(request, timeout):
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": record["id"]}]}]})
        requested_gets.append(request.full_url)
        return FakeResponse(record)

    provider = OSVDebianProvider(
        opener=opener, cache_dir=cache_dir, diagnostic=messages.append
    )
    result = provider.fetch_records([package()], "Debian:12")

    assert result.error is None
    assert requested_gets == [OSV_VULN_URL + record["id"]]
    assert any("read_failures=1" in line for line in messages)
    assert any("write_failures=1" in line for line in messages)
    assert not list(cache_dir.glob("*.tmp"))
    assert not list(cache_dir.glob(".*.tmp"))


def test_debian_network_failure_is_not_cached(tmp_path):
    record_id = "DEBIAN-CVE-2024-6387"

    def opener(request, timeout):
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": record_id}]}]})
        raise OSError("mock network unavailable")

    provider = OSVDebianProvider(opener=opener, cache_dir=tmp_path / "cache")
    result = provider.fetch_records([package()], "Debian:12")

    assert result.error.startswith("Debian OSV data retrieval failed:")
    assert not provider._cache.path_for(record_id).exists()


def test_debian_cache_read_failure_and_network_failure_report_assessment_error(
    tmp_path, monkeypatch
):
    record = advisory()
    cache_reads = []
    requested_urls = []
    messages = []

    def fail_cache_read(advisory_id):
        cache_reads.append(advisory_id)
        return None, "read_failure"

    def opener(request, timeout):
        requested_urls.append(request.full_url)
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": record["id"]}]}]})
        raise OSError("mock network unavailable")

    provider = OSVDebianProvider(
        opener=opener,
        cache_dir=tmp_path / "cache",
        diagnostic=messages.append,
    )
    monkeypatch.setattr(provider._cache, "load", fail_cache_read)

    report = assess_packages(
        [package()], "Debian GNU/Linux 12", "12", provider
    )

    assert cache_reads == [record["id"]]
    assert requested_urls == [OSV_QUERY_BATCH_URL, OSV_VULN_URL + record["id"]]
    assert report.assessment_status == "error"
    assert report.error.startswith("Debian OSV data retrieval failed:")
    assert report.packages[0].assessment_status == "error"
    assert report.packages[0].findings == []
    assert report.assessment_status != "no_known_match"
    assert any(
        "hits=0, misses=1" in message and "read_failures=1" in message
        for message in messages
    )
    assert not provider._cache.path_for(record["id"]).exists()


def test_cached_and_uncached_assessment_results_are_identical(tmp_path):
    record = advisory()
    requested_gets = []

    def opener(request, timeout):
        if request.full_url == OSV_QUERY_BATCH_URL:
            return FakeResponse({"results": [{"vulns": [{"id": record["id"]}]}]})
        requested_gets.append(request.full_url)
        return FakeResponse(record)

    cache_dir = tmp_path / "cache"
    first = assess_packages(
        [package()], "Debian GNU/Linux 12", "12",
        OSVDebianProvider(opener=opener, cache_dir=cache_dir),
    ).to_dict()
    second = assess_packages(
        [package()], "Debian GNU/Linux 12", "12",
        OSVDebianProvider(opener=opener, cache_dir=cache_dir),
    ).to_dict()

    assert first["assessment_status"] == second["assessment_status"] == "vulnerable"
    assert first["packages"] == second["packages"]
    assert first["packages"][0]["findings"][0]["severity"] is None
    assert first["packages"][0]["findings"][0]["urgency"] == "not yet assigned"
    assert len(requested_gets) == 1


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


def test_debian_provider_rejects_oversized_query_response():
    class OversizedResponse(FakeResponse):
        def read(self, size=-1):
            return b"x" * size if size >= 0 else b"x"

    result = OSVDebianProvider(
        opener=lambda *args, **kwargs: OversizedResponse({}),
    ).fetch_records([package()], "Debian:12")

    assert result.error is not None
    assert "response exceeded" in result.error


def test_debian_provider_rejects_oversized_hydrated_advisory(tmp_path):
    class OversizedResponse(FakeResponse):
        def read(self, size=-1):
            return b"x" * size if size >= 0 else b"x"

    responses = iter([
        FakeResponse({"results": [{"vulns": [{"id": "DEBIAN-CVE-2024-6387"}]}]}),
        OversizedResponse({}),
    ])
    result = OSVDebianProvider(
        opener=lambda *args, **kwargs: next(responses),
        cache_dir=tmp_path / "cache",
    ).fetch_records([package()], "Debian:12")

    assert result.error is not None
    assert "response exceeded" in result.error


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
