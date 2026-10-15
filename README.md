# LinuxSecMonitor

LinuxSecMonitor is a read-only command-line tool for collecting Linux host details, inventorying Debian-family packages, and comparing installed package versions with supported OSV vulnerability data. It produces text or JSON reports and does not claim complete vulnerability coverage.

## Key features

- Collects operating system, distribution and version when available, kernel version, CPU architecture, Python version, and hostname.
- Inventories installed Debian, Ubuntu, and Kali packages with `dpkg-query` where supported. Source package metadata is retained internally for Debian assessment.
- Performs conservative, distribution-aware vulnerability assessment using Ubuntu and Debian OSV records. Kali vulnerability matching is explicitly unsupported.
- Adds available OSV summaries, details, references, and Debian urgency as advisory context. Urgency is kept separate from severity.
- Writes human-readable text or structured JSON reports.
- Provides optional progress and timing diagnostics on standard error.
- Caches validated full Debian OSV advisory records on disk for 24 hours by default.

## How a scan works

```text
main.py
  |-- collect_system_info()          scanner/system_info.py
  |-- scan_installed_packages()      scanner/package_scanner.py
  |-- assess_packages()              scanner/vulnerability_assessment.py
  |   |-- Select the distribution-specific assessment path
  |   |-- Query OSV and retrieve full advisory records when needed
  |   |-- Match supported release/package/version evidence
  |   `-- Build assessment and advisory-context results
  `-- Render text or JSON
```

The assessment runs only after package inventory succeeds. Eligible Debian assessments query OSV on each run; package-to-advisory query results are not cached. Full advisory records are read from the persistent cache when valid and unexpired; otherwise, they are retrieved from OSV. Package inventory and assessment are read-only.

## Requirements and installation

Python 3.10 or newer is recommended. Full package inventory is intended for Debian, Ubuntu, and Kali Linux systems with `dpkg-query` available. On Windows, system information and the mocked automated tests can run, but package inventory reports that the operating system is unsupported.

The WSL instructions apply when WSL is running a supported Debian, Ubuntu, or Kali Linux distribution; WSL itself is not a separate package-inventory target.

### Debian, Ubuntu, Kali Linux, and WSL

From the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The dependency file lists `pytest` for development and testing. The scanner itself uses Python's standard library.

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
```

Windows is useful for development and running the mocked tests; it is not a supported package-inventory target.

## Run the scanner

Run these commands from the project directory:

```bash
# Human-readable report
python main.py

# JSON to standard output
python main.py --json

# JSON written to a file
python main.py --json --output scan.json

# Progress and timing details to standard error, JSON report to a file
python main.py --diagnostics --json --output scan.json
```

The same CLI forms work in PowerShell when `python` resolves to the intended interpreter, or with the Windows launcher, for example `py main.py --json`. The implemented options are `--json`, `-o`/`--output`, and `--diagnostics`. `--output` requires `--json`. Diagnostics go to standard error so JSON written to standard output remains parseable. A completed package scan returns exit code `0`; a package-inventory failure returns `1`; a JSON output-file write failure returns `2`.

### Example report shape

This is a format template, not a recorded scan result. Values in angle brackets are filled from the current host and data sources.

```text
LinuxSecMonitor — Sprint 1
System information:
  Operating system: <detected operating system>
  Distribution: <distribution or Unavailable>
Package inventory:
  Total packages found: <count>
Vulnerability assessment:
  Status: <assessment status>
  Distribution: <detected distribution>
  Release: <detected release>
  Source: <assessment provider, when available>
  Total assessed package entries: <count>
```

The text report previews up to ten package entries and ten findings. JSON includes the full package inventory and assessment entries, plus an `advisory_context` map keyed by advisory ID. The map is empty when no usable OSV context is available.

## Assessment states and interpretation

Assessment status is shown for the overall assessment and for individual package entries. It describes the evidence available from the configured source; it is not a guarantee of system security.

| Status | Meaning |
| --- | --- |
| `vulnerable` | A matching source record marks the installed version as affected. |
| `no_known_match` | No matching record was found in the queried data. This is **not** evidence that the package is safe. |
| `requires_review` | Distribution, package metadata, or advisory/version evidence is missing, incomplete, or ambiguous. No safe conclusion was made. |
| `unsupported` | Automated vulnerability assessment is explicitly unsupported for the detected distribution, including Kali. |
| `fixed` | Matching source data provides fixed-version evidence for the assessed package. |
| `not_affected` | Matching range data places the version outside the affected interval; this is not a fixed-version claim. |
| `error` | The assessment could not complete, for example because required OSV data retrieval failed. |
| `mixed` | Overall result used when fixed evidence coexists with other package entries, such as `no_known_match` or `not_affected`. |

Successful empty inventory results are distinct from scan failures. A successful query with no matching advisory still produces `no_known_match`, not a statement that the package is secure.

## Distribution support and limitations

| Distribution | Package inventory | Vulnerability assessment |
| --- | --- | --- |
| Debian | Supported with `dpkg-query` | Debian OSV records, with numeric release and provable source package/version evidence; matching findings require traceable Debian Security Tracker references. |
| Ubuntu | Supported with `dpkg-query` | Ubuntu OSV data for releases with suitable metadata and package/version evidence. |
| Kali | Supported with `dpkg-query` | Explicitly unsupported. Debian or Ubuntu records are not treated as authoritative for Kali. |
| Other distributions | Unsupported | Requires review; no distribution-specific provider is configured. |
| Windows | Unsupported | System information and tests can run, but package inventory and Linux vulnerability assessment are not supported. |

Distribution detection reads `/etc/os-release` on Linux. The package scanner checks the primary distribution ID and invokes `dpkg-query` without a shell. The scanner does not detect Ubuntu Pro/ESM entitlement. Some advisories lack severity or complete version evidence, and Debian OSV coverage can be incomplete. Debian Security Tracker references are retained, but Tracker page notes are not fetched during normal scans. `no_known_match` only describes queried data and never proves safety.

## Persistent Debian OSV cache

The Debian provider caches validated full OSV advisory records, keyed by a SHA-256 digest of the advisory ID. Its default TTL is 24 hours. Package-to-advisory querybatch results are not cached, so eligible Debian scans query OSV each time. The cache reduces repeated full-record downloads, but it does not eliminate inventory collection, querybatch requests, or local matching.

Default locations:

- Linux: `$XDG_CACHE_HOME/linuxsecmonitor/osv`, or `~/.cache/linuxsecmonitor/osv` when `XDG_CACHE_HOME` is unset or not absolute.
- Windows: `%LOCALAPPDATA%\LinuxSecMonitor\osv` when `%LOCALAPPDATA%` is absolute; otherwise a per-user `AppData\Local\LinuxSecMonitor\osv` directory.

Code that constructs `OSVDebianProvider` can configure `cache_dir` and `cache_ttl_seconds`. Expired, malformed, unreadable, or invalid cache records are fetched again. Cache read/write failures are reported in diagnostics and do not replace network retrieval or turn missing data into a safe result.

In one observed Debian scan, the first scan took approximately **127.6 seconds** and a subsequent cached scan took approximately **5.6 seconds**. These are measured examples, not performance guarantees; actual timings depend on network conditions, OSV responses, package inventory size, and cache state.

## Diagnostics

Add `--diagnostics` to report stage progress and elapsed time to standard error. Diagnostics include OSV batch and hydration progress, persistent cache hit/miss/expiry/write/failure counts, matching progress, and report-writing times. They avoid printing advisory descriptions.

```bash
python main.py --diagnostics --json --output scan.json
```

## Tests

Install the project requirements, then run the deterministic offline suite:

```bash
python -m pytest -v
```

The unit tests mock operating-system commands and OSV responses, so they do not require `dpkg-query` or a live network. On Windows, the project's virtual environment can be used with:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## Manual Debian and Ubuntu Validation

Use separate disposable Debian and Ubuntu VMs for real-host validation. Take a VM snapshot first and run the scanner as a normal, non-root user. The scanner is read-only, but the JSON command writes `scan.json` in the project directory. These instructions are a checklist; they do not imply that a real-host scan has already passed.

### Debian VM checklist

- [ ] Confirm the VM is running Debian and note its release.
- [ ] From the project directory, create and activate a virtual environment, install dependencies, and run both report formats:

  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  python -m pip install -r requirements.txt
  python main.py --diagnostics --json --output scan.json
  scan_exit_code=$?
  python -m json.tool scan.json
  python main.py
  ```

- [ ] Record the detected distribution and release, whether package inventory succeeded, the package count, the assessment status and source, and the scanner's exit code (`scan_exit_code`).

### Ubuntu VM checklist

- [ ] Confirm the VM is running Ubuntu and note its release.
- [ ] From the project directory, create and activate a virtual environment, install dependencies, and run both report formats:

  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  python -m pip install -r requirements.txt
  python main.py --diagnostics --json --output scan.json
  scan_exit_code=$?
  python -m json.tool scan.json
  python main.py
  ```

- [ ] Record the detected distribution and release, whether package inventory succeeded, the package count, the assessment status and source, and the scanner's exit code (`scan_exit_code`).

The CLI exit code reflects package inventory and report writing. OSV retrieval can fail after a successful inventory; in that case the report should still show the inventory result and identify the assessment error. `no_known_match` only means no matching record was found in the queried data; it does not mean the system or package is safe. Kali package inventory is supported, but Kali vulnerability assessment remains explicitly unsupported; Debian or Ubuntu records are not authoritative for Kali.

### Optional live OSV integration tests

Live tests are skipped unless explicitly enabled. They require network access to `api.osv.dev` and verify documented Ubuntu or Debian OSV cases; they are separate from the normal offline suite.

PowerShell:

```powershell
$env:LINUXSECMONITOR_LIVE_OSV = "1"
python -m pytest -m live_osv tests/integration -v

$env:LINUXSECMONITOR_LIVE_DEBIAN_OSV = "1"
python -m pytest -m live_debian_osv tests/integration -v
```

Linux or macOS:

```bash
LINUXSECMONITOR_LIVE_OSV=1 python -m pytest -m live_osv tests/integration -v
LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 python -m pytest -m live_debian_osv tests/integration -v
```

## Security and safety

- Collection and assessment are read-only. The tool does not install, remove, upgrade, or modify packages.
- It does not require root privileges and does not run a privileged background service.
- It does not automatically remediate findings.
- A `vulnerable` result is limited to the evidence matched from the configured advisory source. The scanner does not detect every vulnerability or configuration weakness.
- `no_known_match` means only that no matching record was found in the queried data; it does **not** mean safe.
- Network failures, unsupported distributions, and uncertain package/version evidence are represented as errors, unsupported states, or items requiring review rather than silently treated as safe.

## Project structure

```text
LinuxSecMonitor/
+-- main.py
|-- requirements.txt
|-- pytest.ini
|-- README.md
|-- scanner/
|   |-- __init__.py
|   |-- system_info.py
|   |-- package_scanner.py
|   `-- vulnerability_assessment.py
`-- tests/
    |-- test_system_info.py
    |-- test_package_scanner.py
    |-- test_vulnerability_assessment.py
    |-- test_debian_assessment.py
    |-- test_main.py
    `-- integration/
        |-- test_ubuntu_osv_live.py
        `-- test_debian_osv_live.py
```

## Potential future improvements (planned, not implemented)

- Add more distribution-specific vulnerability sources after their data and matching quality are validated.
- Add security-configuration auditing and change monitoring.
- Add a web dashboard and background monitoring in a later project sprint.
- Improve historical reporting and alert workflows without automatic remediation.
