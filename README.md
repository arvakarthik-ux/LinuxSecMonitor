# LinuxSecMonitor

LinuxSecMonitor is a defensive Linux security monitoring project. It collects basic host information and installed package inventory, with conservative advisory matching for Ubuntu and Debian. It does not claim complete security coverage.

## Sprint 1 features

- Read-only system information from Python's `platform` module and Linux `/etc/os-release`.
- Debian/Ubuntu/Kali package inventory from `dpkg-query`; Debian source metadata is retained internally for advisory matching.
- Human-readable output or structured JSON on standard output / in a file.
- Graceful scan errors with a distinct successful empty inventory.
- A separate, conservative vulnerability assessment foundation with structured results.

The package scanner supports Debian, Ubuntu, and Kali Linux. It invokes `dpkg-query` with an argument list (no shell) and performs no package modifications or privileged actions.

## Setup and usage

Python 3.10 or newer is recommended. From the project directory:

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
python main.py --json
python main.py --json --output scan.json
python main.py --diagnostics --json --output scan.json
```

Package inventory requires Debian, Ubuntu, or Kali Linux and the `dpkg-query` command. System information remains available on other operating systems, but the package scan reports that it is unsupported.

## Vulnerability assessment

Ubuntu matching uses Ubuntu OSV records served through the OSV API and is limited to releases with suitable metadata. Debian matching uses Debian ecosystem records from OSV, requires an exact Debian release and source package identity, compares the source version against supported OSV affected ranges, and preserves the matching Debian Security Tracker reference. OSV query results can be abbreviated records, so full records are retrieved before matching. Debian severity remains unset when the source does not provide a severity.

**Distribution support:** package inventory supports Kali, Ubuntu, and Debian. Automated vulnerability assessment supports Ubuntu with suitable release metadata and Debian with a numeric release plus provable source package/version metadata. Kali remains explicitly unsupported; Debian and Ubuntu advisories are not applied to Kali. Other distributions require review. Packages with legacy inventory rows, malformed source metadata, unsupported range events, withdrawn advisories, or conflicting version evidence require review. Debian OSV records may omit severity. Ubuntu Pro/ESM status is not detected. `no_known_match` means no matching record was found in the queried data; it does not mean a package is safe. The scanner is read-only, requires no root privileges, and never modifies packages.

The JSON vulnerability assessment and terminal report include a package-entry total and counts grouped by the existing assessment status. Each assessed package entry is counted once. The summary preserves the detected distribution, release, data source, and any assessment error or limitation. A `no_known_match` result is explicitly not proof that a package is safe.

Assessment JSON also includes an additive `advisory_context` map keyed by OSV advisory ID. When OSV provides them, entries include the advisory `summary`, `details`, and validated HTTP(S) `references`; repeated advisory IDs share one context entry. Debian findings may include `urgency` only when it is present on the matching OSV affected entry for the detected Debian release and source package. Urgency is separate from severity and does not affect matching or assessment status. These fields come from the OSV record. Debian Security Tracker notes are not fetched during normal scans; the report retains the Tracker reference for traceability, but does not retrieve the Tracker page content.

## Tests

```bash
python -m pytest
```

Tests mock operating-system metadata and package-manager calls, so they can run on Windows without `dpkg-query`.

### Optional live Ubuntu OSV check

The normal suite remains offline; the live integration test is skipped unless explicitly enabled. It checks a documented Ubuntu OSV record for `bash` on Ubuntu 22.04 LTS and verifies its advisory ID, affected status, release, and Canonical source reference. OSV's query-batch API can return advisory stubs, so the provider retrieves full advisory records before matching.

```powershell
$env:LINUXSECMONITOR_LIVE_OSV = "1"
python -m pytest -m live_osv tests/integration -v
```

On Linux or macOS:

```bash
LINUXSECMONITOR_LIVE_OSV=1 python -m pytest -m live_osv tests/integration -v
```

The live check requires network access to `api.osv.dev`; it is intentionally separate from the deterministic unit suite.

### Scan diagnostics

Pass `--diagnostics` to print stage progress and elapsed times to stderr while keeping report JSON unchanged and JSON stdout clean. Diagnostics include system information and package inventory, Debian OSV batch requests, advisory hydration counts (requested, cached, and newly fetched), vulnerability matching progress, and report serialization/writing. Package and advisory names are not included in progress messages.

```bash
python3 main.py --diagnostics --json --output debian-scan.json
```

Progress for longer loops is emitted every 100 package/advisory entries. Diagnostics are disabled unless requested.

### Optional live Debian OSV check

The Debian integration test is also skipped unless explicitly enabled. It validates the Debian 12 `openssh` source package against the OSV record for CVE-2024-6387, including the fixed source version and Debian Security Tracker reference.

```powershell
$env:LINUXSECMONITOR_LIVE_DEBIAN_OSV = "1"
python -m pytest -m live_debian_osv tests/integration -v
```

On Linux or macOS:

```bash
LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 python -m pytest -m live_debian_osv tests/integration -v
```

## Project layout

```text
scanner/       system information and package inventory modules
tests/         pytest coverage for collectors and CLI
main.py        command-line interface
```
