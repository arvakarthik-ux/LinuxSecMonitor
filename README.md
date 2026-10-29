# LinuxSecMonitor

LinuxSecMonitor is a command-line tool for collecting Linux host details, inventorying Debian-family packages, and comparing installed package versions with supported OSV vulnerability data. Host scans and assessment are read-only. Separate opt-in modes can scan a downloaded `.deb` without installing it, inventory and statically review a repository, or request an explicitly confirmed local-package installation after scanning. It does not claim complete vulnerability coverage or package safety.

## Key features

- Collects operating system, distribution and version when available, kernel version, CPU architecture, Python version, and hostname.
- Inventories installed Debian, Ubuntu, and Kali packages with `dpkg-query` where supported. Source package metadata is retained internally for Debian assessment.
- Performs conservative, distribution-aware vulnerability assessment using Ubuntu and Debian OSV records. Kali vulnerability matching is explicitly unsupported.
- Adds available OSV summaries, details, references, and Debian urgency as advisory context. Urgency is kept separate from severity.
- Writes human-readable text or structured JSON reports.
- Provides optional progress and timing diagnostics on standard error.
- Provides read-only `--doctor` checks for supported-host status, tool availability, and effective APT hook counts without displaying hook contents.
- Caches validated full Debian OSV advisory records on disk for 24 hours by default.
- Inventories local repository files and can separately scan a bounded snapshot with ClamAV; repository code is never executed.
- Runs bounded static heuristics over repository files to produce review leads for selected secrets, dependency sources, lifecycle scripts, and risky command patterns. These heuristics are not a malware verdict or a complete code audit.
- Offers `--safe-run` to review a repository and require exact interactive approval before one explicit command; this is a user-mediated wrapper, not automatic execution interception or a sandbox.
- Can scan a local `.deb` without installing it, with separate manual pre-install and experimental APT-hook workflows. The manual workflow requires complete no-detection coverage; the APT hook requires explicit terminal approval for every transaction and never allows incomplete scans.

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

OSV query responses are limited to 16 MiB per batch and full advisory responses
to 8 MiB each. JSON nesting deeper than 128 levels is rejected. Oversized or
excessively nested responses produce an assessment error; they are not treated
as an empty advisory result.

## Requirements and installation

Python 3.11 or newer is required. Python 3.10 reached end of life on 2026-10-01 and no longer receives security fixes ([final Python 3.10 security release](https://www.python.org/downloads/release/python-31022/)). Debian 12 and newer supported Ubuntu/Kali releases provide suitable Python versions; Ubuntu 22.04's system Python 3.10 does not meet this requirement unless a separately maintained Python 3.11+ interpreter is available. Full package inventory is intended for Debian, Ubuntu, and Kali Linux systems with `dpkg-query` available. On Windows, system information and the mocked automated tests can run, but package inventory reports that the operating system is unsupported.

Install the CLI into a Python virtual environment without changing system APT
configuration:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/linuxsecmonitor --help
```

The installed command exposes the CLI. System APT integration remains opt-in;
the installation command below explicitly changes `/etc/apt/apt.conf.d` and
creates an ownership receipt under `/var/lib/linuxsecmonitor`.
Use `python -m pip install '.[test]'` in the virtual environment to add pytest.

Use `linuxsecmonitor --doctor` inside the environment to check read-only
platform and tool prerequisites. To stop using the command in the current
shell, deactivate the virtual environment. To uninstall only LinuxSecMonitor
from that environment, run:

```bash
.venv/bin/python -m pip uninstall linuxsecmonitor
```

This removes the Python distribution and its console entry point; it leaves
the virtual environment and other packages intact. To restore the command,
run `.venv/bin/python -m pip install .` again. Since this installation does not
enable a system hook or service, uninstalling it requires no APT configuration
recovery.

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

The same CLI forms work in PowerShell when `python` resolves to the intended interpreter, or with the Windows launcher, for example `py main.py --json`. The implemented report options include `--json`, `-o`/`--output`, and `--diagnostics`. `--output` requires `--json`. Diagnostics go to standard error so JSON written to standard output remains parseable. A completed package scan returns exit code `0`; a package-inventory failure returns `1`; a JSON output-file write failure returns `2`.

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
limitations. The standalone `--scan-repo` mode does not execute the repository
and cannot prevent a later command from doing so. It does not wrap Git, pip,
npm, Cargo, Go, Make, or a shell; the user must choose whether to proceed after
reviewing the report.

#### Explicit command review wrapper

`--safe-run` scans a repository before launching one command that the user
supplies explicitly:

```bash
python main.py --safe-run /path/to/repository -- python -m pip install .
python main.py --safe-run /path/to/repository --json --output ../review.json -- make build
```

The wrapper runs repository inventory, ClamAV assessment, and static review.
It blocks if any stage is incomplete or unavailable, and blocks a ClamAV
detection. If coverage is complete and static heuristics report review leads,
the user can inspect them and type exactly `RUN` to continue. It also requires
that confirmation when no findings were reported. Without an interactive
terminal, the command is not started. JSON mode sends the human preview to
standard error and writes the final review and command outcome as JSON; command
arguments are deliberately omitted from the report. In JSON mode, child stdout
and stderr are routed to standard error so standard output remains valid JSON.
In text mode, child output uses the current terminal. The command's exit status
is returned (signals map to 128 plus the signal number); cancellation returns
3 and incomplete review or launch failure returns 1. Keep output reports
outside the repository being scanned.

This is an explicit user-mediated wrapper, not a sandbox or an enforcement
boundary. It runs the command with an argument vector and without a shell, but
the selected program can itself start shells or child processes. Direct Git,
shell, build, and package-manager commands still bypass the wrapper. A
concurrent writer can also change repository contents after review. Do not
describe `--safe-run` as automatic protection for normal APT or repository
operations.

### Scan and optionally install a local Debian package

The separate `--preinstall-deb` mode scans a local `.deb` and displays the scan
report before asking for explicit approval:

```bash
python main.py --preinstall-deb /path/to/downloaded-package.deb
python main.py --preinstall-deb /path/to/downloaded-package.deb --json
python main.py --preinstall-deb /path/to/downloaded-package.deb --json --output preinstall-report.json
```

This mode requires Linux, `dpkg-deb`, `clamscan`, and a usable ClamAV signature
database for a completed scan. A ClamAV warning that its virus database is
older than seven days makes coverage incomplete; LinuxSecMonitor does not
update signatures. It also reads the package's `Source` metadata and queries
the configured OSV provider for the current host distribution where a provider
is supported. Kali vulnerability assessment is explicitly unsupported;
Debian and Ubuntu use their respective release-specific matching logic. An
OSV error or unsupported result is included in the report and does not mean
that no vulnerability exists. Installation additionally requires `apt-get`
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
contents; it does not guarantee safety. The separate vulnerability assessment
is advisory in this manual workflow: its findings, `requires_review`,
`unsupported`, or `error` state are shown before the same explicit `INSTALL`
decision. The command does not claim that a package without a matching OSV
record is safe.

### Inspect a downloaded `.deb` without installing it

Use `--scan-deb` for a report without the optional installation step:

```bash
python main.py --scan-deb ./downloaded-package.deb
python main.py --scan-deb ./downloaded-package.deb --json --output package-report.json
```

The report contains separate malware and vulnerability assessment results.
The vulnerability query uses the current host's distribution and release, and
the package's binary and source identity when available. If source identity is
missing or malformed, Debian matching requires review rather than substituting
the binary version. Kali is explicitly unsupported for automated OSV matching.
OSV network errors and incomplete or unsupported results remain visible and
produce a nonzero exit status. Exit status zero requires complete malware
coverage with no detection and a conclusive vulnerability result (`no_known_match`,
`fixed`, `not_affected`, or `mixed`); `no_known_match` is not a safety claim.
This operation does not install the archive or execute package scripts.

The APT v3 hook always requires exact `INSTALL` approval after a complete
transaction review, including when no detection or script review lead exists.
If a complete scan reports a signature detection or a maintainer-script review
lead, the report displays it before the same approval prompt. The report keeps
heuristic leads separate from ClamAV's `status`; declining or lacking a
terminal blocks the transaction. Incomplete scans, errors, and unavailable
scanners cannot be approved through this hook.

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
so they do not contaminate JSON stdout. The JSON contains a
`malware_assessment` object (including nested `vulnerability_assessment`) and
an `installation` object. The output path cannot alias
the `.deb` being scanned. The pre-install mode cannot be combined with
`--scan-deb` or `--scan-repo`.

Exit codes for this command:

- `0`: the user approved and APT returned success.
- `1`: scan blocked, installation cancelled/unavailable/failed, or APT returned
  a nonzero status.
- `2`: invalid CLI combination or JSON output could not be safely written.

### Experimental APT Pre-Install-Pkgs hook (manual, temporary-config testing)

LinuxSecMonitor also has an opt-in `--apt-preinstall-hook` mode for APT's
Pre-Install-Pkgs protocol version 3. On Debian 12, APT 2.6.1 can be given a
temporary configuration file passed only to the test commands. The procedure
below clears and rebuilds only the `DPkg::Pre-Install-Pkgs` list so LinuxSecMonitor runs
before the currently configured hooks. It does not modify permanent APT
configuration:

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
hook_command="/usr/bin/python3 -B $hook_root/main.py --apt-preinstall-hook"
cat > "$tmp_dir/apt-hook-order.conf" <<EOF
#clear DPkg::Pre-Install-Pkgs;
DPkg::Pre-Install-Pkgs {
  "$hook_command";
  "/usr/bin/apt-listchanges --apt || test \$? -lt 10";
  "/usr/sbin/dpkg-preconfigure --apt || true";
};
DPkg::Tools::Options::/usr/bin/python3::Version "3";
EOF
sudo install -o root -g root -m 0644 \
  "$tmp_dir/apt-hook-order.conf" "$hook_root/apt-hook-order.conf"
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
sudo apt-get -s -c "$hook_root/apt-hook-order.conf" --no-remove install \
  "$hook_root/linuxsecmonitor-apt-hook-smoke_0.0.1_all.deb"
```

`mktemp` creates a unique hook directory atomically; the package, scanner copy,
and temporary APT config are staged only inside that directory. This avoids
overwriting an existing hook installation or staged package. The config is
root-owned and supplied with `apt-get -c` for the test commands; no permanent
APT configuration file is edited.

The simulation is only a transaction-plan check; it does not prove that the
hook runs. Proceed only if the plan contains the single new smoke-test package
and no unrelated installs, removals, or upgrades. Do not use `-y`.

Check that the interpreter, every code file and each parent directory in the
hook path are trusted and not writable by unprivileged users. The supplied
Debian output showed exactly `apt-listchanges` followed by
`dpkg-preconfigure`; verify this remains true and check for any pre-invocation
hooks. The temporary config reorders only those two hooks after LinuxSecMonitor.
Stop if an additional or different pre-install hook is configured, or if any
pre-invocation hook exists and its behavior has not been reviewed:

```bash
existing_hooks="$(sudo apt-config dump | grep -F 'DPkg::Pre-Install-Pkgs::' || true)"
expected_existing="$(printf '%s\n' \
  'DPkg::Pre-Install-Pkgs:: "/usr/bin/apt-listchanges --apt || test $? -lt 10";' \
  'DPkg::Pre-Install-Pkgs:: "/usr/sbin/dpkg-preconfigure --apt || true";')"
if [[ "$existing_hooks" != "$expected_existing" ]]; then
  echo 'Stop: configured pre-install hooks differ from the reviewed Debian list.' >&2
  exit 1
fi
if sudo apt-config dump | grep -qiE '^(DPkg|APT)::Pre-Invoke(::| |$)'; then
  echo 'Stop: a pre-invocation hook is configured; review it before testing.' >&2
  exit 1
fi
effective_hooks="$(sudo apt-config -c "$hook_root/apt-hook-order.conf" dump | grep -F 'DPkg::Pre-Install-Pkgs::')"
printf '%s\n' "$effective_hooks"
expected_effective="$(printf '%s\n' \
  "DPkg::Pre-Install-Pkgs:: \"$hook_command\";" \
  'DPkg::Pre-Install-Pkgs:: "/usr/bin/apt-listchanges --apt || test $? -lt 10";' \
  'DPkg::Pre-Install-Pkgs:: "/usr/sbin/dpkg-preconfigure --apt || true";')"
[[ "$effective_hooks" == "$expected_effective" ]] || {
  echo 'Stop: effective temporary hook list is not in the required order.' >&2
  exit 1
}
read -r -p 'If the effective order is understood and verified, type ORDER-VERIFIED: ' hook_order
[[ "$hook_order" == ORDER-VERIFIED ]] || { echo 'Stop: hook order was not confirmed.' >&2; exit 1; }
```

APT reads the temporary `-c` file after its system config. `#clear` removes the
existing `DPkg::Pre-Install-Pkgs` list for that APT process, then the file
recreates the exact reviewed hooks with LinuxSecMonitor first, followed by
`apt-listchanges` and `dpkg-preconfigure`. APT runs these hooks in configured
list order before invoking dpkg. Thus, for these commands and the verified
configuration, `dpkg-preconfigure --apt` runs only after the LinuxSecMonitor
decision. If the scan blocks, later hooks are not run. The synthetic fixtures
contain no maintainer scripts. This is not a universal pre-execution barrier:
it does not cover other APT entry points, changed local configuration, other
hook types that execute package code, or concurrent privileged processes.

Debian documents the `#clear` directive, config-file loading, and hook order in
[`apt.conf(5)`](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html).

Run one APT command with the temporary config. Protocol version 3 is selected
for `/usr/bin/python3` by the tool option in that config:

```bash
sudo apt-get -c "$hook_root/apt-hook-order.conf" --no-remove \
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
sudo apt-get -s -c "$hook_root/apt-hook-order.conf" --no-remove install \
  "$hook_root/linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb"
set +e
set -o pipefail
sudo apt-get -c "$hook_root/apt-hook-order.conf" --no-remove \
  -o Debug::pkgDPkgPM=1 \
  install "$hook_root/linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb" \
  2>&1 | tee "$tmp_dir/eicar-apt.log"
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

#### Maintainer-script marker cancellation check

The EICAR case checks signature detection. This separate test checks whether
declining a maintainer-script review lead prevents that script from running.
Use only the same disposable Debian VM/snapshot and temporary hook config.
If the synthetic postinst runs, it creates a marker and appends a harmless
`true` cron entry to a unique hidden filename. Run this only in the disposable
VM; if either file appears, restore the snapshot immediately.

    marker_package=linuxsecmonitor-apt-hook-marker
    marker_file="$tmp_dir/maintainer-script-ran"
    disabled_cron_file=/etc/cron.d/.linuxsecmonitor-apt-cancel-disabled
    test ! -e "$marker_file"
    test ! -e "$disabled_cron_file"
    if dpkg-query -s "$marker_package" >/dev/null 2>&1; then
      echo 'Stop: marker-test package name is already installed.' >&2
      exit 1
    fi
    mkdir -p "$tmp_dir/marker/DEBIAN" \
      "$tmp_dir/marker/usr/share/doc/$marker_package"
    cat > "$tmp_dir/marker/DEBIAN/control" <<'EOF'
    Package: linuxsecmonitor-apt-hook-marker
    Version: 0.0.1
    Architecture: all
    Description: Harmless maintainer-script cancellation fixture
    EOF
    cat > "$tmp_dir/marker/DEBIAN/postinst" <<EOF
    #!/bin/sh
    printf '%s\n' '*/10 * * * * root true' >> /etc/cron.d/.linuxsecmonitor-apt-cancel-disabled
    printf '%s\n' 'ran' > '$marker_file'
    EOF
    chmod 0755 "$tmp_dir/marker/DEBIAN/postinst"
    printf '%s\n' 'Harmless cancellation marker fixture.' > \
      "$tmp_dir/marker/usr/share/doc/$marker_package/README"
    dpkg-deb --build "$tmp_dir/marker" \
      "$tmp_dir/linuxsecmonitor-apt-hook-marker_0.0.1_all.deb"
    sudo install -o root -g root -m 0644 \
      "$tmp_dir/linuxsecmonitor-apt-hook-marker_0.0.1_all.deb" \
      "$hook_root/linuxsecmonitor-apt-hook-marker_0.0.1_all.deb"

Before invoking APT, require the scanner to report complete no-detection
coverage and the startup-persistence-write review lead. This verifies that the
hook should prompt without depending on ClamAV recognizing a signature:

    set +e
    python3 -B "$hook_root/main.py" --scan-deb \
      "$hook_root/linuxsecmonitor-apt-hook-marker_0.0.1_all.deb" \
      --json --output "$tmp_dir/marker-scan.json"
    marker_scan_exit=$?
    set -e
    python3 - "$tmp_dir/marker-scan.json" <<'PY'
    import json, sys
    report = json.load(open(sys.argv[1], encoding="utf-8"))
    assert report["status"] == "no_detection", report
    assert report["coverage_complete"] is True, report
    assert any(item["rule_id"] == "startup-persistence-write"
               for item in report["maintainer_script_findings"]), report
    PY
    test "$marker_scan_exit" -eq 0
    command -v strace >/dev/null || {
      echo 'Stop: strace is required; do not install it for this test.' >&2
      exit 1
    }

Simulate and inspect the plan. At APT's ordinary confirmation, answer yes only
after confirming it names this single local package. At LinuxSecMonitor's
prompt, enter CANCEL. The hook must accept v3, show the heuristic lead, and
block the transaction:

    sudo apt-get -s -c "$hook_root/apt-hook-order.conf" --no-download --no-remove install \
      "$hook_root/linuxsecmonitor-apt-hook-marker_0.0.1_all.deb"
    set +e
    set -o pipefail
    sudo strace -f -qq -e trace=execve -o "$tmp_dir/marker-execve.log" \
      /usr/bin/apt-get -c "$hook_root/apt-hook-order.conf" --no-download --no-remove \
      install "$hook_root/linuxsecmonitor-apt-hook-marker_0.0.1_all.deb" \
      2>&1 | tee "$tmp_dir/marker-apt.log"
    marker_apt_exit=$?
    set -e
    test "$marker_apt_exit" -ne 0
    grep -F 'APT Pre-Install-Pkgs protocol version 3 accepted.' "$tmp_dir/marker-apt.log"
    grep -F 'startup-persistence-write' "$tmp_dir/marker-apt.log"
    grep -F 'APT transaction blocked:' "$tmp_dir/marker-apt.log"
    test ! -e "$marker_file"
    test ! -e "$disabled_cron_file"
    marker_package_state="$(dpkg-query -W -f='${db:Status-Abbrev}' linuxsecmonitor-apt-hook-marker 2>/dev/null || true)"
    test -z "$marker_package_state"
    if sudo grep -F 'dpkg-preconfigure' "$tmp_dir/marker-execve.log"; then
      echo 'Failure: dpkg-preconfigure ran; restore the VM snapshot.' >&2
      exit 1
    fi
    if sudo grep -E 'execve\("[^"]*/dpkg", .*"(--unpack|--configure|--install|--remove|--purge)"' \
      "$tmp_dir/marker-execve.log"; then
      echo 'Failure: dpkg package processing ran; restore the VM snapshot.' >&2
      exit 1
    fi

Count this as evidence only if every check passes: APT exits nonzero; the v3,
review-lead, and blocked messages appear; no preconfiguration or dpkg package
processing exec is recorded; the package has no dpkg status entry; and both
marker paths remain absent. If a marker exists or trace/output is ambiguous,
restore the snapshot immediately. This evidence applies only to the exact APT
binary, temporary config, and hook order used in that VM.

#### Separate maintainer-script approval check

Run this only after restoring a clean VM snapshot. In a new interactive
session, repeat the setup above through building and staging the synthetic
marker package. It intentionally executes the harmless test
`postinst` after explicit approval, so it writes the marker and the disabled
cron fixture. Confirm the simulator lists only this package. At APT's ordinary
confirmation, review the plan and answer yes; at LinuxSecMonitor's review-lead
prompt, type exactly `INSTALL`:

    sudo apt-get -s -c "$hook_root/apt-hook-order.conf" --no-download --no-remove install \
      "$hook_root/linuxsecmonitor-apt-hook-marker_0.0.1_all.deb"
    set +e
    set -o pipefail
    sudo strace -f -qq -e trace=execve -o "$tmp_dir/marker-approval-execve.log" \
      /usr/bin/apt-get -c "$hook_root/apt-hook-order.conf" --no-download --no-remove \
      install "$hook_root/linuxsecmonitor-apt-hook-marker_0.0.1_all.deb" \
      2>&1 | tee "$tmp_dir/marker-approval-apt.log"
    approval_apt_exit=$?
    set -e
    test "$approval_apt_exit" -eq 0
    grep -F 'APT Pre-Install-Pkgs protocol version 3 accepted.' "$tmp_dir/marker-approval-apt.log"
    grep -F 'startup-persistence-write' "$tmp_dir/marker-approval-apt.log"
    grep -F 'Explicit INSTALL approval received; APT may continue.' "$tmp_dir/marker-approval-apt.log"
    test "$(cat "$marker_file")" = ran
    sudo dpkg-query -s "$marker_package" | grep -F 'Status: install ok installed'
    sudo grep -F "/var/lib/dpkg/info/$marker_package.postinst" \
      "$tmp_dir/marker-approval-execve.log"
    test -e "$disabled_cron_file"

Count this only if APT exits zero, the exact approval message appears, the
marker content is `ran`, the package status is `install ok installed`, and the
trace shows its postinst was executed. This proves approval continued into
configuration for this exact VM setup; it does not establish safety of any
other package. Revert the VM snapshot immediately afterward to remove the
installed fixture and its cron file. Do not retain the VM state or treat this
as a normal-host installation procedure.

After testing, the safest rollback is to revert the disposable VM snapshot.
That restores the package database and removes the temporary hook code and
staged fixtures together. The manual cleanup below applies only if the smoke
package was installed and the marker approval check was not run. If the marker
approval check was run, restore the VM snapshot as instructed above; the
smoke-only cleanup below is not sufficient. If retaining a VM after only the
smoke test, first simulate package removal and inspect the full plan:

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
  'f apt-hook-order.conf' \
  'f main.py' \
  'f linuxsecmonitor-apt-hook-smoke_0.0.1_all.deb' \
  'f linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb' \
  'f linuxsecmonitor-apt-hook-marker_0.0.1_all.deb' \
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
  "$hook_root/apt-hook-order.conf" \
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
  "$hook_root/linuxsecmonitor-apt-hook-eicar_0.0.1_all.deb" \
  "$hook_root/linuxsecmonitor-apt-hook-marker_0.0.1_all.deb"; then
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
records do not refer to package archives. A configure action is accepted only
when a matching package name, target version, architecture, and Multi-Arch
archive action is present in the same transaction; otherwise the transaction
is blocked. Removal actions are blocked because their maintainer scripts cannot
be reviewed from the transaction archives. For each archive, the hook compares
package name, target version, architecture, and Multi-Arch identity with APT's
corresponding transaction record. Archive paths
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

APT may continue only after every archive has a complete assessment, every
configure action has a matching scanned archive, no removal action is present,
and the user types exact `INSTALL` at the terminal. `no_detection` means
ClamAV found no known signature; it does not prove that a package is safe. A
complete ClamAV scan can still report heuristic maintainer-script
review leads while retaining ClamAV status `no_detection`; those leads are not
confirmed malware. After every complete review, the hook displays the report
and asks on `/dev/tty` for the exact token `INSTALL`, including when there are
no findings. Declining, any other input, interruption, or no terminal aborts
the transaction. Approval never bypasses
incomplete scans, errors, unavailable scanners, invalid transactions, or
package-identity mismatches. The hook does not execute package maintainer
scripts; APT/dpkg may run them later if installation is approved.

The hook also runs one transaction-level OSV assessment using the package
source identities from the inspected archives. On supported Debian/Ubuntu
systems, assessment errors or `requires_review` block the transaction. An
unsupported distribution is reported explicitly; exact `INSTALL` approval can
still continue after the malware checks pass. A vulnerability finding is
reported for the user's decision and does not itself prevent an explicit
approval. OSV coverage is limited to the configured data sources and package
mappings; this is not a comprehensive vulnerability guarantee. Real APT
cancellation and approval remain unverified until the documented disposable
Debian transaction tests pass.

This is an experimental hook integration, not a permanent APT policy and not
an automatic APT configuration change. APT's v3 stream has no transaction
record count or checksum, so a stream truncated exactly at a valid record
boundary cannot be detected from the protocol alone. Validate hook invocation
and behavior in a disposable Debian VM before considering any broader use.

The documented command supplies temporary `-o` settings for one APT process;
it does not install or alter a permanent hook configuration. There is therefore
no persistent LinuxSecMonitor hook entry created by that test procedure.

### APT hook lifecycle

After installing LinuxSecMonitor into a system Python environment and checking
`linuxsecmonitor --doctor`, inspect the integration state:

```bash
linuxsecmonitor --apt-integration status
```

The following commands change persistent system configuration and require
root. `install` creates only `/etc/apt/apt.conf.d/00linuxsecmonitor` and a
receipt at `/var/lib/linuxsecmonitor/apt-integration.json`. It refuses to
overwrite an existing hook or receipt. Review the exact paths and retain a
system backup before running it. The interpreter and imported hook modules
must be root-owned and not writable by group or other users; a checkout or
virtual environment in a user's home directory is rejected. The candidate
configuration is checked with APT's own `apt-config` parser before activation.
To create a root-owned runtime, build a wheel as an ordinary user, then install
that wheel into an isolated system-owned virtual environment (ensure the
distribution's `python3-venv` prerequisite is available):

```bash
python3 -m pip wheel --no-deps --no-build-isolation --wheel-dir ./wheelhouse .
sudo python3 -m venv /opt/linuxsecmonitor
sudo /opt/linuxsecmonitor/bin/pip install --no-deps ./wheelhouse/linuxsecmonitor-0.1.0-py3-none-any.whl
sudo /opt/linuxsecmonitor/bin/linuxsecmonitor --doctor
sudo /opt/linuxsecmonitor/bin/linuxsecmonitor --apt-integration install
```

These commands create persistent files under `/opt`, `/etc/apt`, and
`/var/lib`; review them before running. The prebuilt wheel should be verified
and stored where only administrators can replace it before the privileged pip
install. A virtual environment used for ordinary development should not be
used as the privileged hook runtime:

```bash
sudo /opt/linuxsecmonitor/bin/linuxsecmonitor --apt-integration status
sudo /opt/linuxsecmonitor/bin/linuxsecmonitor --apt-integration disable
sudo /opt/linuxsecmonitor/bin/linuxsecmonitor --apt-integration enable
sudo /opt/linuxsecmonitor/bin/linuxsecmonitor --apt-integration uninstall
```

`disable` removes the unchanged managed hook but retains its receipt so
`enable` can reconstruct it. `uninstall` removes only the unchanged managed
hook and that receipt; it does not remove ClamAV, Python packages, reports, or
other APT configuration. If the hook was edited, replaced, or became a
symlink, removal stops and preserves it for manual review. If installation is
interrupted, its own partial receipt/hook writes are rolled back when possible;
inspect `--apt-integration status` and the two paths before recovery. Status
`conflict` requires manual investigation. These commands have unit coverage
against temporary directory roots; persistent system installation and the APT
transaction behavior have not been verified in the current environment.

To stop a blocked transaction, let the hook fail closed and inspect its report
and APT error. Do not remove unrelated APT hook configuration during recovery.

### Threat model and coverage limits

The APT hook is intended to provide a user-visible review point for supported
APT `Pre-Install-Pkgs` v3 archive transactions, with failure on incomplete
inspection and exact interactive approval before APT proceeds. The managed
`00linuxsecmonitor` filename puts it first among ordinary `apt.conf.d` drop-ins;
Debian documents that these files load in alphanumeric order and that
`Pre-Install-Pkgs` commands run in order before dpkg, aborting when one fails.
This ordering is necessary because `dpkg-preconfigure --apt` may execute
package `config` scripts. A `Pre-Install-Pkgs` hook supplied earlier through
the `APT_CONFIG` environment variable, an explicit `-c` file, or command-line
configuration can still run first or replace the list. Direct `dpkg`, other
package managers, APT invocations that bypass or override the hook, and
commands run before this hook are outside coverage. Removing or editing the
hook, replacing its executable or interpreter, or changing root-owned APT
configuration defeats it. A malicious privileged user can bypass or disable
the tool.

Repository scanning is opt-in and advisory. `--safe-run` gates only the one
command explicitly passed through that wrapper. It does not intercept cloned
repositories or act as a sandbox; direct shells, editors, build tools,
dependency managers, subprocesses launched elsewhere, and concurrent repository
changes are outside its enforcement. Vulnerability matching is limited to
supported Debian/Ubuntu OSV data and package mappings. ClamAV detects known
signatures and selected limits; heuristic script checks are review leads.
Neither no-match nor no-detection proves a package or repository safe, and the
tool does not provide comprehensive malware detection or system protection.

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

Use `--doctor` for a read-only prerequisite check:

```bash
python main.py --doctor
python main.py --doctor --json
```

It reports the detected distro, Python support, package/deb scanning
prerequisites, tool version lines, and counts of effective `DPkg::Pre-Install-Pkgs`
and `DPkg::Pre-Invoke` entries. It intentionally omits hook command contents
because APT settings can contain credentials. It makes no configuration
changes. Exit status 0 means the host is recognized and inventory, `.deb`
inspection, and ClamAV executables are available; status 1 means unsupported
host or missing prerequisite. A ClamAV version line does not prove that a real
scan succeeds or that signatures are current. Hook counts do not prove v3
protocol compatibility, safe hook order, or cancellation timing.

## Tests

Install the project requirements, then run the deterministic offline suite:

```bash
python -m pytest -v
```

GitHub Actions runs the offline suite and compile check on Python 3.11 through
3.14 for pushes and pull requests. Python 3.10 is excluded because it reached
end of life on 2026-10-01. The live OSV tests remain opt-in and are not part of
that workflow.

The unit tests mock operating-system commands and OSV responses, so they do not require `dpkg-query` or a live network. On Windows, the project's virtual environment can be used with:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## Manual Debian and Ubuntu Validation

### Automated real APT transaction tests (disposable guest only)

`tests/integration/test_apt_preinstall_guest.py` provides opt-in tests for a
clean package approval, a maintainer-script review lead that is canceled, the
same kind of review lead that is approved, incomplete-coverage denial, and
lifecycle recovery/preservation. The transaction scenarios use ordinary
`apt-get install`, the installed LinuxSecMonitor lifecycle, a real ClamAV scan,
OSV assessment, a PTY-backed terminal prompt, `strace`, package database
snapshots, and per-scenario evidence files. It refuses to run unless the guest
is Debian/Ubuntu, root, has the root-owned disposable marker below, has the
trusted system CLI installed, has no pre-invoke hooks, and has a private
evidence directory. The test installs, disables, re-enables, and uninstalls
only its own APT integration; it removes only the unique fixture package and
markers it creates.

Do not run this on the main Kali host. Use a fresh Debian/Ubuntu VM snapshot for
each scenario. The approved scenario installs its purpose-built test package
briefly and the harness purges only that unique package after it records the
installed state and maintainer-script trace. The APT package scan must complete
with real ClamAV and a usable OSV provider; scan or provider failure is recorded
as a failed test, never converted to a simulated success.

In the disposable guest, install the project into a root-owned runtime and
install pytest in that runtime. Then create the explicit guest marker and a
private evidence directory:

```bash
sudo install -d -o root -g root -m 0700 /var/tmp/linuxsecmonitor-apt-evidence
printf '%s\n' linuxsecmonitor-disposable-apt-guest-v1 \
  | sudo tee /run/linuxsecmonitor-disposable-apt-test >/dev/null
sudo chown root:root /run/linuxsecmonitor-disposable-apt-test
sudo chmod 0644 /run/linuxsecmonitor-disposable-apt-test
```

Run exactly one transaction command on a fresh snapshot, choosing one scenario:

```bash
sudo env \
  LINUXSECMONITOR_RUN_REAL_APT=1 \
  LINUXSECMONITOR_REAL_APT_SCENARIO=finding-cancel \
  LINUXSECMONITOR_SYSTEM_CLI=/opt/linuxsecmonitor/bin/linuxsecmonitor \
  LINUXSECMONITOR_APT_EVIDENCE_DIR=/var/tmp/linuxsecmonitor-apt-evidence \
  /opt/linuxsecmonitor/bin/python -m pytest -q \
  /opt/linuxsecmonitor-source/tests/integration/test_apt_preinstall_guest.py \
  -k cancellation
```

Use `safe-approve` with `-k safe_package_approval`, `finding-approve` with
`-k finding_approval`, or `incomplete-block` with
`-k incomplete_coverage_blocks` on separate fresh snapshots. The incomplete
fixture contains an in-package symlink and must be rejected before dpkg. Run
the lifecycle case on a separate fresh snapshot with scenario `lifecycle` and
`-k lifecycle_recovery`; it covers install, repeated install, disable, recovery
by enable, repeated enable, uninstall, and preservation of unrelated config.
Review the JSON summary,
`.apt.log`, and `.execve.log` files in the evidence directory. The integration
tests remain unverified until each command is run successfully on its target
OS. Without `LINUXSECMONITOR_RUN_REAL_APT=1` and the exact scenario name, all
five tests are skipped in the ordinary suite. Lifecycle recovery models the
owned-receipt/missing-hook state; it does not inject a process kill between
individual installer writes.

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

APT 3.3.3's upstream `apt.conf(5)` documents protocol version 3, including its
architecture and Multi-Arch fields and the `DPkg::Tools::Options::<command>::Version`
setting. Kali's APT package tracker lists `apt 3.3.3+kali1` as synced with
Debian, with a Kali-specific source-list modernization change. This documents
the upstream capability but does not establish behavior of the installed Kali
binary; use the abort-only local protocol probe below to verify that binary.
See [APT 3.3.3 `apt.conf(5)`](https://sources.debian.org/src/apt/3.3.3/doc/apt.conf.5.xml)
and the [Kali APT package tracker](https://pkg.kali.org/pkg/apt/news/).

#### Abort-only protocol-v3 probe (not an installation test)

This probe records APT's actual hook stream and intentionally fails before
package processing. It uses a synthetic package containing only a control file
and documentation text, an always-failing second pre-install hook, and a
private `dpkg` executable guard selected through `DPkg::Path`. APT runs
`DPkg::Pre-Invoke` before `DPkg::Pre-Install-Pkgs`, so this procedure does not
use a failing Pre-Invoke hook. If the probe returns unexpectedly, the second
pre-install hook stops APT before `dpkg-preconfigure`; if the pre-install hook
is skipped, `DPkg::Path` makes the private guard fail instead of launching the
system `dpkg`. This order is visible in APT's
[`pkgDPkgPM::Go()` source](https://github.com/Debian/apt/blob/3.3.3/apt-pkg/deb/dpkgpm.cc);
`DPkg::Path` defines the execution PATH documented in
[`apt.conf(5)`](https://sources.debian.org/src/apt/3.3.3/doc/apt.conf.5.xml).
Use only a disposable Kali VM or snapshot. If any precondition or result
differs, stop and restore the snapshot.

Run in one Bash session. These commands create two unique temporary
directories and do not modify permanent APT configuration:

```bash
set -Eeuo pipefail
command -v apt-get apt-config dpkg-deb dpkg-query python3 strace tee namei >/dev/null
test -x /usr/bin/false
apt-get --version | grep -Eq '^apt 3\.3\.3\+kali1 '

hooks="$(sudo apt-config dump | grep -F 'DPkg::Pre-Install-Pkgs::' || true)"
expected='DPkg::Pre-Install-Pkgs:: "/usr/sbin/dpkg-preconfigure --apt || true";'
[[ "$hooks" == "$expected" ]] || { echo "Stop: unexpected pre-install hooks" >&2; exit 1; }
if sudo apt-config dump | grep -qiE '::Pre-Invoke(::| |$)'; then
  echo "Stop: existing Pre-Invoke hooks need review" >&2; exit 1
fi
dpkg_binary="$(sudo apt-config dump | grep -F 'Dir::Bin::dpkg ' || true)"
if [[ -n "$dpkg_binary" && "$dpkg_binary" != 'Dir::Bin::dpkg "dpkg";' ]]; then
  echo "Stop: APT's dpkg executable is not the expected PATH-searched name" >&2; exit 1
fi
if dpkg-query -W -f='${db:Status-Abbrev}\n' linuxsecmonitor-apt-v3-probe 2>/dev/null | grep -q '^ii'; then
  echo "Stop: fixture package is already installed" >&2; exit 1
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/linuxsecmonitor-apt-v3-build.XXXXXX")"
probe="$(mktemp -d /var/tmp/linuxsecmonitor-apt-v3.XXXXXX)"
sudo chown root:root "$probe"
sudo chmod 0755 "$probe"
sudo install -d -o root -g root -m 0755 "$probe/archives"
mkdir -p "$work/pkg/DEBIAN" "$work/pkg/usr/share/doc/linuxsecmonitor-apt-v3-probe"
cat > "$work/pkg/DEBIAN/control" <<'EOF'
Package: linuxsecmonitor-apt-v3-probe
Version: 0.0.1
Section: misc
Priority: optional
Architecture: all
Maintainer: Local test fixture
Description: Harmless APT protocol probe fixture
EOF
printf '%s\n' 'Harmless protocol probe fixture.' > "$work/pkg/usr/share/doc/linuxsecmonitor-apt-v3-probe/README"
deb="$work/linuxsecmonitor-apt-v3-probe_0.0.1_all.deb"
dpkg-deb --build "$work/pkg" "$deb"
dpkg-deb -e "$deb" "$work/control-check"
[[ "$(find "$work/control-check" -mindepth 1 -maxdepth 1 -printf '%f\n')" == control ]] || {
  echo "Stop: fixture has unexpected control files" >&2; exit 1
}

cat > "$work/probe.py" <<'PY'
import os
import sys

data = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
try:
    fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as capture:
        capture.write(data)
except OSError as error:
    print(f"LSM_PROBE_CAPTURE_ERROR: {error}", file=sys.stderr, flush=True)
    raise SystemExit(24)

lines = data.splitlines()
if len(data) > 8 * 1024 * 1024 or not lines or lines[0] != b"VERSION 3":
    print("LSM_PROBE_NOT_VERSION_3", flush=True)
    raise SystemExit(23)
try:
    separator = lines.index(b"")
except ValueError:
    print("LSM_PROBE_MALFORMED_STREAM", flush=True)
    raise SystemExit(23)

print("LSM_PROBE_VERSION_3_CAPTURED", flush=True)
for record in lines[separator + 1:]:
    fields = record.decode("utf-8", "replace").split(maxsplit=8)
    if len(fields) != 9:
        print("LSM_PROBE_MALFORMED_ACTION", flush=True)
        raise SystemExit(23)
    action = fields[8]
    print(
        f"LSM_ACTION name={fields[0]} old={fields[1]} new={fields[5]} "
        f"arch={fields[6]} operation={os.path.basename(action) if action.startswith('/') else action}",
        flush=True,
    )
# Intentional failure: APT must abort at this first hook.
raise SystemExit(23)
PY
sudo install -o root -g root -m 0644 "$deb" "$probe/linuxsecmonitor-apt-v3-probe_0.0.1_all.deb"
sudo install -o root -g root -m 0644 "$work/probe.py" "$probe/probe.py"
sudo install -d -o root -g root -m 0755 "$probe/dpkg-guard"
printf '%s\n' '#!/bin/sh' 'if [ "$#" -eq 1 ]; then case "$1" in --assert-*|--print-architecture|--print-foreign-architectures|--version) exec /usr/bin/dpkg "$@";; esac; fi' 'echo LSM_DPKG_GUARD_INVOKED >&2' 'exit 97' > "$work/dpkg"
sudo install -o root -g root -m 0755 "$work/dpkg" "$probe/dpkg-guard/dpkg"
cat > "$work/apt.conf" <<EOF
#clear DPkg::Pre-Install-Pkgs;
DPkg::Pre-Install-Pkgs {
  "/usr/bin/python3 -B $probe/probe.py $probe/protocol-v3.bin";
  "/usr/bin/false";
  "/usr/sbin/dpkg-preconfigure --apt || true";
};
DPkg::Tools::Options::/usr/bin/python3::Version "3";
DPkg::Path "$probe/dpkg-guard:/usr/sbin:/usr/bin:/sbin:/bin";
Dir::Bin::dpkg "dpkg";
Dir::Cache::archives "$probe/archives";
EOF
sudo install -o root -g root -m 0644 "$work/apt.conf" "$probe/apt.conf"

effective="$(sudo apt-config -c "$probe/apt.conf" dump | grep -F 'DPkg::Pre-Install-Pkgs::')"
printf '%s\n' "$effective"
printf '%s\n' "$effective" | grep -F "/usr/bin/python3 -B $probe/probe.py $probe/protocol-v3.bin"
printf '%s\n' "$effective" | grep -F 'DPkg::Pre-Install-Pkgs:: "/usr/bin/false";'
printf '%s\n' "$effective" | grep -F 'DPkg::Pre-Install-Pkgs:: "/usr/sbin/dpkg-preconfigure --apt || true";'
sudo apt-config -c "$probe/apt.conf" dump | grep -F "DPkg::Path \"$probe/dpkg-guard:/usr/sbin:/usr/bin:/sbin:/bin\";"
sudo apt-config -c "$probe/apt.conf" dump | grep -F "Dir::Cache::archives \"$probe/archives\";"
sudo apt-config -c "$probe/apt.conf" dump | grep -F 'DPkg::Tools::Options::/usr/bin/python3::Version "3";'
sudo apt-config -c "$probe/apt.conf" dump | grep -F 'Dir::Bin::dpkg "dpkg";'
sudo namei -l /usr/bin/python3 /usr/bin/apt-get /usr/bin/strace \
  "$probe/apt.conf" "$probe/probe.py" "$probe/dpkg-guard/dpkg" \
  "$probe/linuxsecmonitor-apt-v3-probe_0.0.1_all.deb"

# Simulation must show the fixture only. Do not continue if it plans any
# unrelated install, removal, or configuration.
sudo apt-get -s -c "$probe/apt.conf" --no-download --no-remove install "$probe/linuxsecmonitor-apt-v3-probe_0.0.1_all.deb" | tee "$work/simulation.log"
if grep -E '^(Inst|Remv|Conf) ' "$work/simulation.log" | grep -v 'linuxsecmonitor-apt-v3-probe'; then
  echo "Stop: simulation contains an unrelated package change" >&2; exit 1
fi
grep -F 'linuxsecmonitor-apt-v3-probe' "$work/simulation.log"
read -r -p 'If the simulation lists only the fixture, type RUN-ABORT-ONLY-PROBE: ' answer
[[ "$answer" == RUN-ABORT-ONLY-PROBE ]] || { echo "Cancelled"; exit 1; }
# At the APT confirmation prompt, type y only after checking it still names
# this fixture; otherwise type n and stop.

# This attempts an APT transaction but has two failure barriers before dpkg.
# strace is required to distinguish actual execs from APT debug text.
set +e
sudo strace -f -qq -e trace=execve -o "$probe/execve.log" /usr/bin/apt-get \
  -c "$probe/apt.conf" --no-download --no-remove -o Debug::pkgDPkgPM=1 \
  install "$probe/linuxsecmonitor-apt-v3-probe_0.0.1_all.deb" 2>&1 | tee "$work/probe.log"
apt_status=${PIPESTATUS[0]}
set -e
[[ "$apt_status" -ne 0 ]] || { echo "Stop: APT unexpectedly succeeded; restore snapshot" >&2; exit 1; }
grep -F 'LSM_PROBE_VERSION_3_CAPTURED' "$work/probe.log"
sudo test -s "$probe/protocol-v3.bin"
sudo python3 - "$probe/protocol-v3.bin" <<'PY'
import sys

data = open(sys.argv[1], "rb").read(8 * 1024 * 1024 + 1)
if len(data) > 8 * 1024 * 1024 or not data.startswith(b"VERSION 3\n"):
    raise SystemExit("Captured protocol is not a bounded VERSION 3 stream")
lines = data.splitlines()
separator = lines.index(b"")
actions = [line.decode("utf-8", "replace").split(maxsplit=8)
           for line in lines[separator + 1:]]
if not any(len(row) == 9 and row[0] == "linuxsecmonitor-apt-v3-probe"
           and row[5] == "0.0.1" and row[6] == "all"
           and row[8].startswith("/") and row[8].endswith(".deb")
           for row in actions):
    raise SystemExit("Fixture archive identity is absent from protocol v3")
print("VERSION 3 and the fixture archive action were captured.")
PY

# A guard invocation means APT did not reach the probe as expected. A
# preconfigure execution or real dpkg package-processing argument is unsafe.
if grep -F 'LSM_DPKG_GUARD_INVOKED' "$work/probe.log"; then
  echo "Inconclusive: dpkg guard was invoked; APT did not follow the expected hook path." >&2
  exit 1
fi
if sudo grep -F "execve(\"$probe/dpkg-guard/dpkg\"" "$probe/execve.log" | grep -E '"(--unpack|--configure|--install|--remove|--purge)"'; then
  echo "Inconclusive: the dpkg guard received package-processing arguments." >&2
  exit 1
fi
if sudo grep -F 'execve("/usr/sbin/dpkg-preconfigure"' "$probe/execve.log"; then
  echo "Inconclusive: dpkg-preconfigure ran; restore the snapshot" >&2; exit 1
fi
if sudo grep -E 'execve\("[^\"]*/dpkg", .*"(--unpack|--configure|--install|--remove|--purge)"' "$probe/execve.log"; then
  echo "Inconclusive: dpkg package processing ran; restore the snapshot" >&2; exit 1
fi
if dpkg-query -W -f='${db:Status-Abbrev}\n' linuxsecmonitor-apt-v3-probe 2>/dev/null | grep -q '^ii'; then
  echo "Failure: fixture is installed; restore the snapshot" >&2; exit 1
fi
echo "Pass only if v3 was captured, APT failed, and strace shows no dpkg package-processing call."
```

The captured stream's configuration section may contain local APT settings; do
not share `protocol-v3.bin`. Missing `strace` is a stop condition; do not
install it for this test. The procedure does not test scanner detections,
approval, or installation. It also cannot establish a universal
pre-execution barrier.

On success, inspect the trace and confirm there is no `dpkg-preconfigure`
exec and no `dpkg` invocation with package-processing arguments. If the local
APT cache contains a copy of the fixture, compare it byte-for-byte with the
staged package. Confirm the archive cache contains only its expected `lock`,
empty `partial` directory, and optional identical fixture copy. Then verify
the probe directory contains exactly `apt.conf`, `archives`, `dpkg-guard`,
`execve.log`, the fixture `.deb`, `probe.py`, and `protocol-v3.bin`:

```bash
expected_probe="$(printf '%s\n' apt.conf archives dpkg-guard execve.log \
  linuxsecmonitor-apt-v3-probe_0.0.1_all.deb probe.py protocol-v3.bin | LC_ALL=C sort)"
actual_probe="$(sudo find "$probe" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
[[ "$actual_probe" == "$expected_probe" ]] || {
  echo 'Unexpected probe directory contents; restore the VM snapshot.' >&2; exit 1;
}
sudo find "$probe/archives" -mindepth 1 -maxdepth 1 -printf '%y %f\n' \
  | grep -vE '^(f lock|d partial|f linuxsecmonitor-apt-v3-probe_0\.0\.1_all\.deb)$' && {
  echo 'Unexpected APT cache file; restore the VM snapshot.' >&2; exit 1;
} || true
if sudo test -e "$probe/archives/linuxsecmonitor-apt-v3-probe_0.0.1_all.deb"; then
  sudo cmp -- "$probe/linuxsecmonitor-apt-v3-probe_0.0.1_all.deb" \
    "$probe/archives/linuxsecmonitor-apt-v3-probe_0.0.1_all.deb"
fi
if sudo test -d "$probe/archives/partial"; then
  sudo find "$probe/archives/partial" -mindepth 1 -maxdepth 1 -printf '%y %f\n' \
    | grep -v '^f lock$' && {
      echo 'Unexpected partial-download file; restore the VM snapshot.' >&2; exit 1;
    } || true
fi
expected_work="$(printf '%s\n' apt.conf control-check dpkg linuxsecmonitor-apt-v3-probe_0.0.1_all.deb pkg probe.py probe.log simulation.log | LC_ALL=C sort)"
actual_work="$(find "$work" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
[[ "$actual_work" == "$expected_work" ]] || {
  echo 'Unexpected build directory contents; restore the VM snapshot.' >&2; exit 1;
}
```

Review the `namei -l` output as a precondition. `/var/tmp` may be the standard
root-owned sticky, world-writable directory; the newly created probe directory
and every item beneath it must be root-owned and not writable by unprivileged
users. The Python interpreter, APT, strace, and their non-sticky parent
directories must also be root-owned and protected. If any check fails, do not
run the transaction attempt.

Only after both comparisons succeed, remove the exact created files and
directories. Never use wildcards or recursive deletion:

```bash
sudo rm -- "$probe/apt.conf" "$probe/execve.log" \
  "$probe/linuxsecmonitor-apt-v3-probe_0.0.1_all.deb" \
  "$probe/probe.py" "$probe/protocol-v3.bin" \
  "$probe/dpkg-guard/dpkg"
sudo rm -f -- "$probe/archives/lock" \
  "$probe/archives/linuxsecmonitor-apt-v3-probe_0.0.1_all.deb"
if sudo test -d "$probe/archives/partial"; then
  sudo rm -f -- "$probe/archives/partial/lock"
  sudo rmdir "$probe/archives/partial"
fi
sudo rmdir "$probe/dpkg-guard" "$probe/archives" "$probe"
rm -- "$work/apt.conf" "$work/dpkg" "$work/linuxsecmonitor-apt-v3-probe_0.0.1_all.deb" \
  "$work/probe.py" "$work/probe.log" "$work/simulation.log" \
  "$work/control-check/control" \
  "$work/pkg/DEBIAN/control" \
  "$work/pkg/usr/share/doc/linuxsecmonitor-apt-v3-probe/README"
rmdir "$work/control-check" \
  "$work/pkg/DEBIAN" "$work/pkg/usr/share/doc/linuxsecmonitor-apt-v3-probe" \
  "$work/pkg/usr/share/doc" "$work/pkg/usr/share" "$work/pkg/usr" "$work/pkg" "$work"
```

If any entry is unexpected or cleanup fails, stop and restore the VM snapshot;
do not broaden cleanup or remove anything outside these directories.

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
and exit codes. Do not treat `no_detection` as safety proof. Do not run a
scanner-enabled or installation-allowing hook test until the abort-only probe
has established the installed APT's protocol-v3 behavior and the local hook
order. The probe does not establish a universal pre-execution barrier. No real
Kali validation is recorded here.

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
path and its parents must therefore be root-controlled. The managed `00`
drop-in precedes ordinary later `apt.conf.d` pre-install hooks, but an earlier
`APT_CONFIG` file or explicit APT configuration override can change that order
or bypass the hook. The system configuration must be reviewed before enabling
it. Repository scanning is an advisory manual workflow and does not intercept
future execution or dependency installation.

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
- Repository inventory reports a bounded list of skipped entry paths and reason codes (`symlink_or_junction`, `non_regular_entry`, `invalid_file_size`, `individual_file_size_limit`, `total_size_limit`, `file_count_limit`, or `inventory_error`) so expected exclusions can be distinguished from read failures. At most 100 path details are included; further omissions are counted. Because paths can reveal repository layout, treat reports as potentially sensitive. Older reports without these additive fields remain supported.
- Repository ClamAV and static-review sections separately report known skipped entries and bounded path/reason details, including encrypted or scan-limit alerts, symlinks/special files, generated paths excluded from static review, and observed read or size failures. Each section counts distinct affected paths; `skipped_entry_details_omitted` counts additional reason records beyond the 100-detail cap. Entries not reached after a traversal limit are not assigned invented paths or counts; the incomplete status and limitation remain authoritative. `.git` internals excluded by scope are not counted as scan skips. Text renderers omit these additive fields when reading older reports that lack them.
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
|   |-- diagnostics.py
|   |-- execution_guard.py
|   |-- apt_hook.py
|   |-- apt_lifecycle.py
|   |-- system_info.py
|   |-- package_scanner.py
|   |-- repository_scanner.py
|   |-- repository_malware_scanner.py
|   |-- repository_security_scanner.py
|   `-- vulnerability_assessment.py
`-- tests/
    |-- test_system_info.py
    |-- test_diagnostics.py
    |-- test_execution_guard.py
    |-- test_apt_lifecycle.py
    |-- integration/test_apt_preinstall_guest.py
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
