# LinuxSecMonitor

LinuxSecMonitor is a command-line tool for collecting Linux host details, inventorying Debian-family packages, and comparing installed package versions with supported OSV vulnerability data. Host scans and assessment are read-only. Separate opt-in modes can scan a downloaded `.deb` without installing it, inventory a repository, or request an explicitly confirmed local-package installation after scanning. It does not claim complete vulnerability coverage or package safety.

## Key features

- Collects operating system, distribution and version when available, kernel version, CPU architecture, Python version, and hostname.
- Inventories installed Debian, Ubuntu, and Kali packages with `dpkg-query` where supported. Source package metadata is retained internally for Debian assessment.
- Performs conservative, distribution-aware vulnerability assessment using Ubuntu and Debian OSV records. Kali vulnerability matching is explicitly unsupported.
- Adds available OSV summaries, details, references, and Debian urgency as advisory context. Urgency is kept separate from severity.
- Writes human-readable text or structured JSON reports.
- Provides optional progress and timing diagnostics on standard error.
- Caches validated full Debian OSV advisory records on disk for 24 hours by default.
- Inventories local repository files and can separately scan a bounded snapshot with ClamAV; repository code is never executed.
- Can scan a local `.deb` without installing it, and has a separate pre-install workflow that blocks installation unless a complete scan returns `no_detection` and the user explicitly confirms.

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

The opt-in `--scan-repo` mode runs repository inventory and ClamAV malware
assessment as separate stages. It copies eligible regular files into private
temporary storage and gives ClamAV that staged snapshot, not the original
repository directory. It does not run scripts, hooks, builds, package
managers, or repository commands.

The assessment runs only after package inventory succeeds. Eligible Debian assessments query OSV on each run; package-to-advisory query results are not cached. Full advisory records are read from the persistent cache when valid and unexpired; otherwise, they are retrieved from OSV. Package inventory and assessment are read-only.

## Requirements and installation

Python 3.10 or newer is recommended. Full package inventory is intended for Debian, Ubuntu, and Kali Linux systems with `dpkg-query` available. On Windows, system information and the mocked automated tests can run, but package inventory reports that the operating system is unsupported.

Repository malware assessment additionally requires the `clamscan` executable
and an available ClamAV signature database. Safe repository scanning requires
POSIX no-follow directory-descriptor support; Windows can run the mocked tests,
but this repository malware mode reports `unavailable` there. Linux is the
validated target. LinuxSecMonitor does not install ClamAV or download/update
signatures.

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

For an opt-in repository inventory and ClamAV scan:

```bash
python main.py --scan-repo /path/to/repository
python main.py --scan-repo /path/to/repository --json
python main.py --scan-repo /path/to/repository --json --output repository-report.json
```

Repository JSON keeps the inventory fields at the top level and adds a separate
`malware_assessment` object. Text output labels the inventory and malware
assessment separately. Exit code `0` requires both a complete inventory and a
complete ClamAV scan with `no_detection`; a detection, unavailable scanner,
error, or incomplete coverage returns `1`. A report-file write failure returns
`2`. For read-only operation, choose an `--output` path outside the repository
being scanned; the CLI rejects an output path inside that tree. `--scan-repo`
does not run the host package inventory or OSV assessment.

### Scan and optionally install a local Debian package

The separate `--preinstall-deb` mode scans a local `.deb` and displays the scan
report before asking for explicit approval:

```bash
python main.py --preinstall-deb /path/to/downloaded-package.deb
python main.py --preinstall-deb /path/to/downloaded-package.deb --json
python main.py --preinstall-deb /path/to/downloaded-package.deb --json --output preinstall-report.json
```

This mode requires Linux, `dpkg-deb`, `clamscan`, and a usable ClamAV signature
database for a completed scan. Installation additionally requires `apt-get`
and the privileges needed by APT. LinuxSecMonitor does not elevate privileges
itself. It creates a private, size-limited snapshot and scans that snapshot;
after approval, it passes the same snapshot to APT using the equivalent of:

```text
apt-get install --no-remove -- /absolute/path/to/scanned-package.deb
```

APT receives that local file as the requested package and can obtain required
dependencies from the system's configured sources. `--no-remove` asks APT to
abort if its proposed transaction would remove packages; APT's own transaction
confirmation remains enabled. Review APT's plan carefully. Installation can
upgrade or add dependencies, access configured repositories, and execute
package maintainer scripts after the user approves. Scanning does not execute
package scripts.

Only a complete `no_detection` assessment reaches the confirmation prompt. The
user must type `INSTALL`; empty input, EOF, or any other response cancels. A
`detected` result blocks installation without offering a bypass. `incomplete`,
`error`, and `unavailable` results also block installation. A no-detection
result means only that ClamAV reported no known detection in the inspected
contents; it does not guarantee safety.

With `--json`, the final JSON report is written to stdout or to `--output`.
The pre-install scan summary, confirmation prompt, and APT output go to stderr,
so they do not contaminate JSON stdout. The JSON contains separate
`malware_assessment` and `installation` objects. The output path cannot alias
the `.deb` being scanned. The pre-install mode cannot be combined with
`--scan-deb` or `--scan-repo`.

Exit codes for this command:

- `0`: the user approved and APT returned success.
- `1`: scan blocked, installation cancelled/unavailable/failed, or APT returned
  a nonzero status.
- `2`: invalid CLI combination or JSON output could not be safely written.

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

Repository malware status is reported separately under `malware_assessment`:

| Status | Meaning |
| --- | --- |
| `detected` | ClamAV reported one or more signature findings. This is scanner evidence, not an assessment of exploitability. |
| `no_detection` | ClamAV completed the staged scan without a known detection. This does **not** prove the repository is safe. |
| `unavailable` | ClamAV or the safe filesystem capabilities/signature database were unavailable. |
| `incomplete` | Some files or nested content could not be scanned, or a configured limit was reached. |
| `error` | The scan could not be completed, for example because ClamAV timed out or failed unexpectedly. |

Inventory `status` and `coverage_complete` describe the inventory stage. The
separate `malware_assessment.status` and `malware_assessment.coverage_complete`
describe ClamAV scanning; success in one stage does not imply success in the
other.

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

Use separate disposable Debian and Ubuntu VMs for real-host validation. Take a VM snapshot first and run the scanner as a normal, non-root user. The scanner is read-only, but the JSON command writes `scan.json` in the project directory. Debian 12 validation is complete as recorded below; Ubuntu validation is still pending.

### Debian VM checklist (completed)

- [x] Confirm the VM is running Debian and note its release.
- [x] From the project directory, create and activate a virtual environment, install dependencies, and run both report formats:

  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  python -m pip install -r requirements.txt
  python main.py --diagnostics --json --output scan.json
  scan_exit_code=$?
  python -m json.tool scan.json
  python main.py
  ```

- [x] Record the detected distribution and release, whether package inventory succeeded, the package count, the assessment status and source, and the scanner's exit code (`scan_exit_code`).

#### Completed Debian 12 validation

The real CLI was validated on Debian GNU/Linux 12 (bookworm), running kernel `6.1.0-53-amd64`, on `x86_64` with Python `3.11.2`. Package inventory succeeded with 1,614 package entries, and the JSON scan exited with code `0`. The text report displayed system information, package inventory, and vulnerability assessment. The Debian OSV provider was selected for release 12; the JSON report had no assessment error and included 501 package entries with matching advisory evidence and 1,113 `no_known_match` entries. A subsequent scan successfully used the persistent advisory cache.

These results are observations from that Debian VM, not guarantees for other hosts or future scans. A `vulnerable` result means matching advisory evidence was found; it does not confirm exploitability. `no_known_match` does not prove that a package or system is safe.

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

**Ubuntu validation status: pending.** No real-host Ubuntu scan is recorded here.

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

- Host collection, package inventory, OSV assessment, `--scan-deb`, and repository
  inventory/scanning are read-only. The explicitly selected
  `--preinstall-deb` workflow can install the specified local package after
  confirmation; it never installs automatically.
- Scanning does not require root privileges. The later APT installation step
  requires the privileges APT needs. LinuxSecMonitor does not elevate privileges
  itself and does not run a privileged background service.
- It does not automatically remediate findings.
- A `vulnerable` result is limited to the evidence matched from the configured advisory source. The scanner does not detect every vulnerability or configuration weakness.
- `no_known_match` means only that no matching record was found in the queried data; it does **not** mean safe.
- Network failures, unsupported distributions, and uncertain package/version evidence are represented as errors, unsupported states, or items requiring review rather than silently treated as safe.
- Repository malware assessment stages regular files using no-follow directory descriptors, skips `.git`, links, junctions and non-regular entries, and applies limits of 100,000 files, 20,000 directories, 50 MiB per file, 512 MiB total staged data, 30 seconds for staging, and 120 seconds for ClamAV scanning. Limit alerts and skipped content make coverage incomplete. Time checks are cooperative for filesystem operations; they are not a hard bound on a blocked filesystem call.
- ClamAV scans only the temporary staged snapshot and may inspect supported nested archives. Unsupported or encrypted content, ClamAV errors, missing signatures, and timeouts do not produce a clean result. A `no_detection` result means only that this ClamAV run reported no known detection in the fully staged input; it does not guarantee that the repository is safe.
- Malware findings are separate from OSV vulnerability findings. A ClamAV signature match is evidence reported by the scanner, not a complete assessment of repository security or a claim about exploitability.

### Optional Debian EICAR check

The EICAR test string is a harmless antivirus test signature, not actual
malware. On a disposable Debian VM with `clamscan` and its signature database
already available, this creates a temporary test directory and scans it. It
does not download malware, install a package, or execute the test file:

```bash
eicar_dir="$(mktemp -d)"
trap 'rm -rf "$eicar_dir"' EXIT
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$eicar_dir/eicar.txt"
python main.py --scan-repo "$eicar_dir"
```

ClamAV signature names can vary. The expected behavior is a `detected` malware
assessment with a path relative to that temporary repository. Do not interpret
an unavailable, error, or incomplete result as a clean scan.

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
|   |-- repository_scanner.py
|   |-- repository_malware_scanner.py
|   `-- vulnerability_assessment.py
`-- tests/
    |-- test_system_info.py
    |-- test_package_scanner.py
    |-- test_repository_scanner.py
    |-- test_repository_malware_scanner.py
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
