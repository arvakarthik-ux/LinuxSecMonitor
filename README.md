# LinuxSecMonitor

LinuxSecMonitor is a command-line tool for collecting Linux host details, inventorying Debian-family packages, and comparing installed package versions with supported OSV vulnerability data. Host scans and assessment are read-only. Separate opt-in modes can scan a downloaded `.deb` without installing it, inventory and statically review a repository, or request an explicitly confirmed local-package installation after scanning. It does not claim complete vulnerability coverage or package safety.

## Key features

- Collects operating system, distribution and version when available, kernel version, CPU architecture, Python version, and hostname.
- Inventories installed Debian, Ubuntu, and Kali packages with `dpkg-query` where supported. Source package metadata is retained internally for Debian assessment.
- Performs conservative, distribution-aware vulnerability assessment using Ubuntu and Debian OSV records. Kali vulnerability matching is explicitly unsupported.
- Adds available OSV summaries, details, references, and Debian urgency as advisory context. Urgency is kept separate from severity.
- Writes human-readable text or structured JSON reports.
- Provides optional progress and timing diagnostics on standard error.
- Caches validated full Debian OSV advisory records on disk for 24 hours by default.
- Inventories local repository files and can separately scan a bounded snapshot with ClamAV; repository code is never executed.
- Runs bounded static heuristics over repository files to produce review leads for selected secrets, dependency sources, lifecycle scripts, and risky command patterns. These heuristics are not a malware verdict or a complete code audit.
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

The opt-in `--scan-repo` mode runs repository inventory, ClamAV malware
assessment, and a separate bounded static review. ClamAV scans eligible files
copied into private temporary storage; static checks read files using
no-follow POSIX directory descriptors. Neither stage runs scripts, hooks,
builds, package managers, Git commands, or other repository content. The
static stage reports heuristic review leads; it does not establish that a
repository is malicious or safe. These are separate passes over the supplied
path, not one atomic snapshot; do not allow an untrusted concurrent writer to
change the repository during a scan.

The assessment runs only after package inventory succeeds. Eligible Debian assessments query OSV on each run; package-to-advisory query results are not cached. Full advisory records are read from the persistent cache when valid and unexpired; otherwise, they are retrieved from OSV. Package inventory and assessment are read-only.

## Requirements and installation

Python 3.10 or newer is recommended. Full package inventory is intended for Debian, Ubuntu, and Kali Linux systems with `dpkg-query` available. On Windows, system information and the mocked automated tests can run, but package inventory reports that the operating system is unsupported.

Repository malware assessment additionally requires the `clamscan` executable
and an available ClamAV signature database. Safe repository scanning requires
POSIX no-follow directory-descriptor support; Windows can run the mocked tests,
but repository malware assessment and static repository review report
`unavailable` there. Linux is the validated target. LinuxSecMonitor does not
install ClamAV or download/update signatures.

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
python main.py --scan-repo /path/to/repository --include-generated
```

Repository JSON keeps the inventory fields at the top level and adds separate
`malware_assessment` and `repository_security_assessment` objects. Text output
labels the inventory, ClamAV assessment, and static review separately. The
static result includes heuristic findings, inspected file/byte counts, errors,
limitations, and coverage state. Its bounded checks include private-key and
token-like material (matched values are redacted), direct URL/VCS dependencies,
package lifecycle scripts, selected command patterns, and common build/CI
files. It is not a full secret scanner, malware detector, dependency
vulnerability scanner, or code audit. It examines regular files below the
supplied directory, including ignored and untracked files, and does not follow
links. It skips Git object/index data but reviews the repository's default
`.git/hooks` directory for active standard hook names. Executable hooks are
reported as review leads; their contents are never run. `.git/config` is read
with a size limit to identify a local custom `core.hooksPath` or include
directives. The scanner does not resolve included configuration or
system/global Git configuration, so alternate hook locations may remain
uninspected and are reported as a coverage limitation.

Static heuristics exclude Python bytecode (`.pyc` and `.pyo`) and common Python
cache directories (`__pycache__`, `.pytest_cache`, `.mypy_cache`, and
`.ruff_cache`) by default. The result reports `generated_paths_excluded` and
the text report displays that count. Use `--include-generated` to include
those paths in static review. This option affects only static heuristics:
the separate ClamAV pass still stages regular generated files when they fit
its limits. It does not follow links or inspect files ClamAV cannot scan, and
any such gaps remain reflected in that assessment's limitations/status.
An excluded generated path makes the static assessment `incomplete`; the
option is available when you need static heuristics to inspect those paths.

Static findings include a one-based source line when the matched byte pattern
has an exact offset. Reports include paths and rule evidence but never include
matched secret values. A finding can still be a test fixture or other benign
match; inspect the location and surrounding source locally.

Exit code `0` requires complete inventory, complete ClamAV coverage with
`no_detection`, and completed static review with no heuristic findings. Any
detection, review lead, unavailable scanner, error, or incomplete coverage
returns `1`. A report-file write failure returns `2`. A static finding is a
reason to inspect its evidence, not proof of malicious behavior. `--scan-repo`
does not run host package inventory or OSV assessment. It is a manual review
command: it does not intercept or block `git clone`, `pip install`, `npm
install`, `make`, or arbitrary shell commands. Review the report before you
choose to execute code or install dependencies.

For read-only operation, choose an `--output` path outside the repository being
scanned; the CLI rejects an output path inside that tree.

Static-review statuses are `completed` (the bounded pass completed without a
heuristic finding), `requires_review` (one or more review leads were found),
`incomplete` (an exclusion, limit, unreadable/changing file, or parse problem left a gap),
`error` (the requested path could not be safely inspected), and `unavailable`
(the platform lacks the required safe POSIX walk support). A completed static
pass is not a safety certification.
Finding severity labels are heuristic triage priorities; they are not CVSS
scores or a probability that the repository is malicious.

The static pass reviews only directly present, executable files with standard
Git hook names under the root `.git/hooks`; standard sample hooks are ignored.
Nested repositories, linked worktree metadata, custom hook directories, Git
configuration includes, and global or system Git configuration can redirect
hook execution and are not followed or executed by the scanner. Such cases are
reported as incomplete coverage. Before using Git with an untrusted
repository, inspect effective hook configuration
and origins yourself. This read-only inspection does not execute repository
hooks:

```bash
git -C /path/to/repository config --includes --show-origin --show-scope --get-all core.hooksPath
```

Repository review remains advisory and does not intercept subsequent Git
operations.

#### Guarded manual repository workflow

Run the review before deciding whether to run code or install dependencies:

```bash
python main.py --scan-repo /path/to/cloned-repository --json --output ../repository-review.json
python -m json.tool ../repository-review.json
```

Read all three result sections and investigate findings, errors, and
limitations. The scanner does not execute the repository, and it cannot
prevent a later command from doing so. It does not wrap Git, pip, npm, Cargo,
Go, Make, or a shell; the user must choose whether to proceed after reviewing
the report.

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
and the privileges needed by APT. Run LinuxSecMonitor as a normal user so the
package inspection remains unprivileged. After a complete scan and exact user
approval, it requests administrator authorization for installation only. It
creates a private, size-limited snapshot and scans that snapshot; after
approval, it passes the same snapshot to APT using the equivalent of:

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

As a separate check, the scanner reads the standard `preinst`, `postinst`,
`prerm`, `postrm`, and `config` maintainer scripts as bounded text. It reports
heuristic review leads for selected download-to-shell, destructive-device, and
startup-persistence write patterns. These leads are not ClamAV detections and
do not prove malicious behavior; the matched command text is omitted from the
report to avoid exposing embedded values. Oversized, unreadable, or changing
scripts make scan coverage incomplete. This is a small rule set, not a full
shell analysis or script sandbox.

Only a complete `no_detection` assessment reaches the confirmation prompt. The
user must type exactly `INSTALL`; lowercase input, extra spaces, empty input,
EOF, or any other response cancels. For a normal-user run, `sudo` is used only
after that confirmation. The snapshot remains private: only APT's sandbox
group receives directory traverse and file read access, and the workflow does
not make it world-readable or world-writable. If those permissions cannot be
set safely, installation is not attempted. A
`detected` result blocks installation without offering a bypass. `incomplete`,
`error`, and `unavailable` results also block installation. A no-detection
result means only that ClamAV reported no known detection in the inspected
contents; it does not guarantee safety.

When the APT v3 hook sees a maintainer-script review lead, it also requires
exact `INSTALL` approval even if ClamAV found no signature. The report keeps
that heuristic lead separate from ClamAV's `status`; declining or lacking a
terminal blocks the transaction. A complete scan with no signature and no
script review lead retains the existing automatic-continuation behavior.

This workflow scans only the explicitly supplied `.deb` snapshot. APT may
resolve and install additional dependencies from configured sources; those
dependency archives are not scanned by this command. The scope warning is
shown before the confirmation prompt. Once the user approves, APT's own hooks
and package configuration scripts may run; this is after the requested local
archive has been scanned, but dependencies and earlier APT hook behavior are
outside this scan's coverage. This is a controlled workflow for one specified
archive, not a gate for every package in an APT transaction.

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

### Experimental APT Pre-Install-Pkgs hook (manual, one-command testing)

LinuxSecMonitor also has an opt-in `--apt-preinstall-hook` mode for APT's
Pre-Install-Pkgs protocol version 3. On Debian 12, APT 2.6.1 can be asked to
use protocol version 3 for one invocation with command-line configuration
options. This does not write an APT configuration file:

Use only a disposable Debian 12 VM or snapshot. Run all commands below in the
same interactive Bash session. Build harmless packages with no maintainer
scripts, and install a trusted copy of the hook code in a unique, root-owned
temporary directory under `/opt`. The commands never reuse or remove a normal
`/opt/linuxsecmonitor` installation:

```bash
set -euo pipefail
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/package/DEBIAN" "$tmp_dir/package/usr/share/doc/linuxsecmonitor-apt-hook-smoke"
cat > "$tmp_dir/package/DEBIAN/control" <<'EOF'
Package: linuxsecmonitor-apt-hook-smoke
Version: 0.0.1
Architecture: all
Description: Harmless LinuxSecMonitor APT hook integration fixture
EOF
printf '%s\n' 'Harmless APT hook test fixture.' > \
  "$tmp_dir/package/usr/share/doc/linuxsecmonitor-apt-hook-smoke/README"
dpkg-deb --build "$tmp_dir/package" "$tmp_dir/linuxsecmonitor-apt-hook-smoke_0.0.1_all.deb"

hook_root="$(sudo mktemp -d /opt/linuxsecmonitor-apt-hook.XXXXXX)"
sudo install -d -o root -g root -m 0755 "$hook_root/scanner"
sudo install -o root -g root -m 0644 main.py "$hook_root/main.py"
sudo install -o root -g root -m 0644 scanner/*.py "$hook_root/scanner/"
sudo install -o root -g root -m 0644 \
  "$tmp_dir/linuxsecmonitor-apt-hook-smoke_0.0.1_all.deb" \
  "$hook_root/linuxsecmonitor-apt-hook-smoke_0.0.1_all.deb"
sudo chmod 0755 "$hook_root"
sudo namei -l "$hook_root/main.py"
sudo find "$hook_root" -printf '%u:%g %m %p\n'
sudo stat -c '%U:%G %a %n' /usr/bin/python3 \
  "$hook_root/linuxsecmonitor-apt-hook-smoke_0.0.1_all.deb"
sudo apt-config dump | grep -i 'DPkg::Pre-Install-Pkgs' || true
if dpkg-query -W -f='${db:Status-Abbrev}\n' linuxsecmonitor-apt-hook-smoke 2>/dev/null | grep -q '^ii'; then
  echo 'Stop: the smoke-test package is already installed.' >&2
  exit 1
fi
if dpkg-query -s linuxsecmonitor-apt-hook-eicar 2>/dev/null | grep -q '^Status: install ok installed$'; then
  echo 'Stop: the EICAR test package is already installed.' >&2
  exit 1
fi
sudo apt-get -s --no-remove install "$hook_root/linuxsecmonitor-apt-hook-smoke_0.0.1_all.deb"
```

`mktemp` creates a unique hook directory atomically; the package is staged only
inside that directory. This avoids overwriting an existing hook installation or
staged package. This creates only a root-owned code copy and local fixture; it does not create
or edit an APT configuration file. The hook is enabled only for each individual
`apt-get` invocation shown below through command-line `-o` options.

The simulation is only a transaction-plan check; it does not prove that the
hook runs. Proceed only if the plan contains the single new smoke-test package
and no unrelated installs, removals, or upgrades. Do not use `-y`.

Check that the interpreter, every code file and each parent directory in the
hook path are trusted and not writable by unprivileged users. Inspect the
configured hooks and the effective list after applying the exact temporary
command-line options below:

```bash
sudo apt-config dump | grep -i 'DPkg::Pre-Install-Pkgs' || true
hook_command="/usr/bin/python3 -B $hook_root/main.py --apt-preinstall-hook"
sudo apt-config \
  -o "DPkg::Pre-Install-Pkgs::=$hook_command" \
  -o 'DPkg::Tools::Options::/usr/bin/python3::Version=3' \
  dump | grep -i 'DPkg::Pre-Install-Pkgs'
read -r -p 'If the effective list is understood and LinuxSecMonitor is last, type ORDER-VERIFIED: ' hook_order
[[ "$hook_order" == ORDER-VERIFIED ]] || { echo 'Stop: hook order was not confirmed.' >&2; exit 1; }
```

APT applies command-line configuration after its configuration files. The
trailing `::` appends this hook to the existing list; it does not put it first
or replace existing hooks. APT runs `Pre-Install-Pkgs` commands in configured
list order. Therefore the effective dump must show the existing entries first
and LinuxSecMonitor last. Stop before either installation command if that order
is not clear, if an unexpected hook appears, or if you cannot account for what
each earlier hook does. In particular, an earlier `dpkg-preconfigure --apt`
can run a package `config` maintainer script before LinuxSecMonitor. The two
synthetic fixtures below contain no maintainer scripts, so they can test hook
invocation without running package-provided configuration code; this does not
establish a pre-execution guarantee for other packages. APT invokes these
hooks after obtaining archives and before its dpkg installation/configuration
phase, but the configured order still applies. Do not describe this as a
universal pre-execution security boundary.

The configuration semantics are documented in Debian's
[`apt.conf(5)`](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html):
command-line settings are applied after configuration files, and `::` appends
an item to a list.

Run one APT command with temporary `-o` options. The version option is keyed
to the hook executable's first word (`/usr/bin/python3`), as APT expects:

```bash
sudo apt-get --no-remove \
  -o "DPkg::Pre-Install-Pkgs::=$hook_command" \
  -o 'DPkg::Tools::Options::/usr/bin/python3::Version=3' \
  install "$hook_root/linuxsecmonitor-apt-hook-smoke_0.0.1_all.deb" 2>&1 | tee "$tmp_dir/clean-apt.log"
grep -F 'APT Pre-Install-Pkgs protocol version 3 accepted.' "$tmp_dir/clean-apt.log"
```

APT's normal transaction confirmation occurs before the pre-install hook. At
that prompt, proceed only after reviewing the simulation above. The hook's
`APT Pre-Install-Pkgs protocol version 3 accepted` line and per-archive report
show that it ran and parsed v3. Confirm the harmless package with
`dpkg-query -W linuxsecmonitor-apt-hook-smoke`.

For the detection/cancellation path, build an EICAR-only package (the EICAR
string is a harmless antivirus test signature, not real malware). Use a new
package name and do not add `preinst`, `postinst`, `prerm`, `postrm`, or `config`
files:

```bash
mkdir -p "$tmp_dir/eicar/DEBIAN" "$tmp_dir/eicar/usr/share/linuxsecmonitor-eicar"
cat > "$tmp_dir/eicar/DEBIAN/control" <<'EOF'
Package: linuxsecmonitor-apt-hook-eicar
Version: 0.0.1
Architecture: all
Description: Harmless antivirus test-signature fixture
EOF
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > \
  "$tmp_dir/eicar/usr/share/linuxsecmonitor-eicar/eicar.txt"
dpkg-deb --build "$tmp_dir/eicar" "$tmp_dir/linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb"
sudo install -o root -g root -m 0644 \
  "$tmp_dir/linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb" \
  "$hook_root/linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb"
dpkg-deb --control "$hook_root/linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb" "$tmp_dir/eicar-control"
if find "$tmp_dir/eicar-control" -maxdepth 1 -type f ! -name control -print -quit | grep -q .; then
  echo 'Stop: unexpected control files are present; do not install this fixture.' >&2
  exit 1
fi
```

First require LinuxSecMonitor itself to return `detected` with at least one
detection for that archive. A nonzero exit by itself is not enough because
errors and incomplete scans also return nonzero:

```bash
set +e
python3 -B "$hook_root/main.py" --scan-deb \
  "$hook_root/linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb" \
  --json --output "$tmp_dir/eicar-scan.json"
scan_exit=$?
set -e
python3 -m json.tool "$tmp_dir/eicar-scan.json"
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["status"] == "detected" and r["detections"], r' \
  "$tmp_dir/eicar-scan.json"
test "$scan_exit" -eq 1
```

If this check fails or ClamAV has no usable signatures, stop; do not run the
APT detection test. Simulate the EICAR fixture transaction and inspect it just
as for the clean fixture. Then run the APT command below. At APT's ordinary
transaction prompt, continue only after checking the plan. At LinuxSecMonitor's
detection prompt, enter `CANCEL` (not `INSTALL`). The hook must print that the
transaction was blocked and APT must exit nonzero. `Debug::pkgDPkgPM=1` asks APT
to show the actual command line whenever APT invokes dpkg; save the output and
inspect any matching line. If a match is ambiguous rather than clearly an
actual dpkg command line, treat the result as inconclusive and restore the
snapshot. Also confirm the EICAR package
is not installed. If APT lacks the detection prompt, the hook's blocked
message, or the expected debug evidence, stop and revert the VM snapshot.

```bash
sudo apt-get -s --no-remove install "$hook_root/linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb"
set +e
set -o pipefail
sudo apt-get --no-remove -o Debug::pkgDPkgPM=1 -o "DPkg::Pre-Install-Pkgs::=$hook_command" -o 'DPkg::Tools::Options::/usr/bin/python3::Version=3' install "$hook_root/linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb" 2>&1 | tee "$tmp_dir/eicar-apt.log"
apt_exit=$?
set -e
test "$apt_exit" -ne 0
grep -F 'APT Pre-Install-Pkgs protocol version 3 accepted.' "$tmp_dir/eicar-apt.log"
grep -F 'APT transaction blocked:' "$tmp_dir/eicar-apt.log"
if grep -E '(^|[[:space:]])(/usr/bin/)?dpkg[[:space:]]' "$tmp_dir/eicar-apt.log"; then
  echo 'Inconclusive: possible dpkg command line; inspect it and restore the VM snapshot if ambiguous.' >&2
  exit 1
fi
if dpkg-query -s linuxsecmonitor-apt-hook-eicar 2>/dev/null | grep -q '^Status: install ok installed$'; then
  echo 'Failure: the EICAR fixture is installed; revert the VM snapshot.' >&2
  exit 1
fi
```

For the last command, record its exit status in the interactive shell. It must
be nonzero after `CANCEL`. The hook marker and blocked message must both appear.
Verify that the package query is not `ii` and that the APT debug output contains
no dpkg command line. A matching but ambiguous line makes the result
inconclusive. If ClamAV does not detect the
EICAR fixture, the cancellation test is inconclusive and must not be replaced
with an assumption that it was blocked. Scanner error and incomplete-result
paths remain covered by mocked tests, not this real APT procedure.

After testing, the safest rollback is to revert the disposable VM snapshot.
That restores the package database and removes the temporary hook code and
staged fixtures together. If retaining the VM, first simulate package removal
and inspect the full plan:

```bash
sudo apt-get -s remove linuxsecmonitor-apt-hook-smoke
```

Proceed only if the simulation removes that test package and changes no other
packages. Then remove it explicitly and confirm it is no longer installed:

```bash
sudo apt-get remove linuxsecmonitor-apt-hook-smoke
dpkg-query -W -f='${db:Status-Abbrev}\n' linuxsecmonitor-apt-hook-smoke 2>/dev/null || true
```

Inspect the unique staged directory before cleanup. Remove only the exact files
copied by this procedure. Use `rmdir`, never recursive deletion, so unexpected
leftover content prevents directory removal. Never clean up `/opt/linuxsecmonitor`
or any path other than the exact `hook_root` shown by the current shell:

```bash
sudo find "$hook_root" -printf '%u:%g %m %p\n'
expected_entries="$(printf '%s\n' \
  'd scanner' \
  'f main.py' \
  'f linuxsecmonitor-apt-hook-smoke_0.0.1_all.deb' \
  'f linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb' \
  'f scanner/__init__.py' \
  'f scanner/apt_hook.py' \
  'f scanner/malware_scanner.py' \
  'f scanner/package_scanner.py' \
  'f scanner/repository_malware_scanner.py' \
  'f scanner/repository_scanner.py' \
  'f scanner/repository_security_scanner.py' \
  'f scanner/system_info.py' \
  'f scanner/vulnerability_assessment.py' | LC_ALL=C sort)"
actual_entries="$(sudo find "$hook_root" -mindepth 1 -printf '%y %P\n' | LC_ALL=C sort)"
if [[ "$actual_entries" != "$expected_entries" ]]; then
  echo 'Cleanup stopped: staging contents differ from this test’s expected files.' >&2
  echo 'Do not delete additional files; restore the disposable VM snapshot.' >&2
  exit 1
fi
if ! sudo rm -- "$hook_root/main.py" \
  "$hook_root/scanner/__init__.py" \
  "$hook_root/scanner/apt_hook.py" \
  "$hook_root/scanner/malware_scanner.py" \
  "$hook_root/scanner/package_scanner.py" \
  "$hook_root/scanner/repository_malware_scanner.py" \
  "$hook_root/scanner/repository_scanner.py" \
  "$hook_root/scanner/repository_security_scanner.py" \
  "$hook_root/scanner/system_info.py" \
  "$hook_root/scanner/vulnerability_assessment.py" \
  "$hook_root/linuxsecmonitor-apt-hook-smoke_0.0.1_all.deb" \
  "$hook_root/linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb"; then
  echo 'Cleanup failed while removing known test files; restore the VM snapshot.' >&2
  exit 1
fi
if ! sudo rmdir -- "$hook_root/scanner" "$hook_root"; then
  echo 'Cleanup failed because the staging directory is not empty; restore the VM snapshot.' >&2
  exit 1
fi
if ! rm -rf -- "$tmp_dir"; then
  echo 'Cleanup failed for the private test temporary directory; restore the VM snapshot.' >&2
  exit 1
fi
trap - EXIT
```

If `rmdir` fails or inspection shows any unexpected file, stop cleanup and
restore the VM snapshot rather than deleting additional content. If the test
package is not installed because APT was cancelled, skip its removal. No
LinuxSecMonitor APT hook entry requires removal because the procedure never
writes one.

Do not point a root-run APT hook at a checkout under a user's writable home
directory: Python imports and executes the hook code with root privileges
before the scanner can drop to APT's sandbox user. Keep the test VM disposable
or take a snapshot first. Review APT's proposed transaction; the clean-path
command above performs a real installation if APT and the hook both allow it.

The hook reads the complete v3 protocol from standard input, validates the
configuration and package-action records, and scans every scheduled `.deb`
archive with the existing package scanner. `**CONFIGURE**` and `**REMOVE**`
records do not refer to package archives and are not scanned. For each archive,
it compares package name, target version, architecture, and Multi-Arch identity
with APT's corresponding transaction record. Archive paths
must be absolute, regular, non-symlink files within configured size limits.
When the hook runs as root, it validates archive paths and ownership first,
then permanently drops its real, effective, and saved user/group IDs to APT's
`_apt` sandbox identity before running package parsing or ClamAV. Paths
containing spaces are supported by the protocol parser. During scanner calls,
the hook temporarily sets `PATH` to standard system binary directories so
`dpkg-deb` and `clamscan` are not resolved from the invoking user's current
directory or another inherited path entry. Malformed
transactions, identity mismatches, missing archives, file changes during scanning, unavailable
scanners, errors, and incomplete coverage cause a nonzero hook exit so APT
aborts. The hook compares archive identity before and after scanning and
requires root-protected paths when running as root. It cannot hold an open
handle for APT's later installation step, so a concurrent privileged process
could still replace an archive after the final check and before APT opens it.

APT proceeds automatically only when every archive has a complete
`no_detection` result and no maintainer-script review leads. `no_detection`
means ClamAV found no known signature; it does not prove that a package is
safe. A complete ClamAV scan can still report heuristic maintainer-script
review leads while retaining ClamAV status `no_detection`; those leads are not
confirmed malware. If any complete scan reports a malware detection or a
maintainer-script review lead, the hook displays the evidence and asks on
`/dev/tty` for the exact token `INSTALL`. Declining, any other input,
interruption, or no terminal aborts the transaction. Approval never bypasses
incomplete scans, errors, unavailable scanners, invalid transactions, or
package-identity mismatches. The hook does not execute package maintainer
scripts; APT/dpkg may run them later if installation is approved.

This is an experimental hook integration, not a permanent APT policy and not
an automatic APT configuration change. APT's v3 stream has no transaction
record count or checksum, so a stream truncated exactly at a valid record
boundary cannot be detected from the protocol alone. Validate hook invocation
and behavior in a disposable Debian VM before considering any broader use.

The documented command supplies temporary `-o` settings for one APT process;
it does not install or alter a permanent hook configuration. There is therefore
no persistent LinuxSecMonitor hook entry to remove after this procedure. If
you separately choose to create a permanent configuration file, back up that
specific file first and remove only the exact LinuxSecMonitor entry/file during
recovery; do not delete unrelated APT hook configuration. To stop a blocked
transaction, let the hook fail closed and inspect its report and APT error.

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

### Controlled Kali validation (pending)

Kali is supported for `dpkg-query` package inventory, but its vulnerability
assessment is explicitly unsupported. The Windows test results do not validate
Kali filesystem behavior, ClamAV behavior, or APT protocol compatibility. Use a
disposable Kali VM or snapshot, run as a normal user, and first record the
installed tool versions and existing hook configuration:

```bash
python3 --version
apt-get --version
command -v dpkg-query dpkg-deb clamscan
apt-config dump | grep -i 'DPkg::Pre-Install-Pkgs'
```

Then exercise read-only modes against known local inputs, without installing a
package or running repository code:

```bash
python3 main.py --diagnostics --json --output kali-host-report.json
python3 -m json.tool kali-host-report.json
python3 main.py
python3 main.py --scan-deb /path/to/already-downloaded-package.deb
python3 main.py --scan-repo /path/to/local-repository
```

Record inventory status/count, vulnerability status (`unsupported` is expected
for Kali), ClamAV signature state, repository static-review status, coverage,
and exit codes. Do not treat `no_detection` as safety proof. Do not run the APT
hook smoke test on Kali until its APT version, protocol-v3 behavior, existing
hook order, and package-configuration-script behavior have been reviewed on
that VM. No real Kali validation is recorded here.

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

### Threat model and boundaries

The scanner treats package archives and repository contents as untrusted data
and avoids executing them during inspection. It assumes the running OS, Python
interpreter, LinuxSecMonitor source, and trusted system tools have not already
been compromised. It is not a sandbox against a kernel flaw, a privileged local
attacker, a malicious/compromised ClamAV or `dpkg-deb`, or every parser/resource
exhaustion attack. The APT hook drops to `_apt` before package parsing/scanning,
but it must import and run its own Python code as root first; that installation
path and its parents must therefore be root-controlled. Earlier APT hooks may
run before this hook, so it cannot promise that package-controlled scripts have
not already run. Repository scanning is an advisory manual workflow and does
not intercept future execution or dependency installation.

- Host collection, package inventory, OSV assessment, `--scan-deb`, and repository
  inventory/scanning are read-only. The explicitly selected
  `--preinstall-deb` workflow can install the specified local package after
  confirmation; it never installs automatically.
- Scanning does not require root privileges. The pre-install workflow requests
  administrator authorization only after a complete `no_detection` result and
  the exact `INSTALL` confirmation. It does not run a privileged background
  service.
- It does not automatically remediate findings.
- A `vulnerable` result is limited to the evidence matched from the configured advisory source. The scanner does not detect every vulnerability or configuration weakness.
- `no_known_match` means only that no matching record was found in the queried data; it does **not** mean safe.
- Network failures, unsupported distributions, and uncertain package/version evidence are represented as errors, unsupported states, or items requiring review rather than silently treated as safe.
- Repository malware assessment stages regular files using no-follow directory descriptors, skips `.git`, links, junctions and non-regular entries, and applies limits of 100,000 files, 20,000 directories, 50 MiB per file, 512 MiB total staged data, 30 seconds for staging, and 120 seconds for ClamAV scanning. Limit alerts and skipped content make coverage incomplete. Time checks are cooperative for filesystem operations; they are not a hard bound on a blocked filesystem call.
- Repository static review uses no-follow POSIX directory descriptors, skips Git object/index data, and does not follow links. It reviews direct standard executable hooks in `.git/hooks` and limited local Git configuration, while reporting external configuration and hook paths as coverage limitations. It excludes `.pyc`/`.pyo` files and common Python cache directories by default; `--include-generated` opts them into the static heuristic pass. The excluded-path count is reported. Its current limits are 50,000 files, 10,000 directories, 20,000 entries per directory, depth 128, 2 MiB per file, 64 MiB total read, and a cooperative 20-second deadline. These limits bound ordinary traversal and reading but are not an OS-enforced CPU/memory sandbox or a hard deadline for a blocked filesystem call.
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
|   |-- repository_security_scanner.py
|   `-- vulnerability_assessment.py
`-- tests/
    |-- test_system_info.py
    |-- test_package_scanner.py
    |-- test_repository_scanner.py
    |-- test_repository_malware_scanner.py
    |-- test_repository_security_scanner.py
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
