# LinuxSecMonitor

LinuxSecMonitor is a defensive Linux security monitoring project. Sprint 1 collects basic host information and an installed package inventory. Sprint 2 adds an early, Ubuntu-only vulnerability assessment foundation. Neither sprint claims complete security coverage.

## Sprint 1 features

- Read-only system information from Python's `platform` module and Linux `/etc/os-release`.
- Debian/Ubuntu package names and versions from `dpkg-query`.
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
```

Package inventory requires Debian, Ubuntu, or Kali Linux and the `dpkg-query` command. System information remains available on other operating systems, but the package scan reports that it is unsupported.

## Vulnerability assessment (initial Sprint 2 foundation)

The assessment uses Ubuntu's official OSV records served through the OSV API for Ubuntu releases only. Ubuntu records include release-specific package status, fixed versions, binary package names, and available severity. The scanner resolves Ubuntu binary package names to their source package through OSV, then compares Debian-style package versions locally. It reports `vulnerable`, `fixed`, `no_known_match`, `requires_review`, `unsupported`, or `error`; `no_known_match` is not a claim that a package is safe.

**Distribution support:** package inventory supports Kali, Ubuntu, and Debian. Automated vulnerability matching in this task supports Ubuntu releases with suitable release metadata only. Kali is explicitly unsupported because Ubuntu advisory records are not authoritative for Kali packages. Debian and other distributions are reported as requiring review: this implementation does not yet map their binary packages to a distribution-specific advisory source. Ubuntu Pro/ESM-specific status is not detected, and records lacking a usable fixed binary version are sent to review. The assessment uses network access and distinguishes retrieval errors from a successful query with no known matching records. No match does not establish that a package is safe. The assessment never installs or changes packages.

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

## Project layout

```text
scanner/       system information and package inventory modules
tests/         pytest coverage for collectors and CLI
main.py        command-line interface
```
