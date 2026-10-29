# LinuxSecMonitor Project Audit

Audit date: 2026-10-28

## Repository state

- Repository root: `/home/kali/LinuxSecMonitor`.
- Remote `origin`: `https://github.com/arvakarthik-ux/LinuxSecMonitor.git` (fetch and push URLs).
- Development branch: `codex/linuxsecmonitor-completion`, created from the existing `codex-skip-entry-reporting` branch after reviewing all local and remote refs. It currently points to `2c1f341` and has not been pushed.
- Preserved branches include `codex-package-script-review` (`52133ba`), `codex-skip-entry-reporting` (`2c1f341`), and `main` (`30bc8bb`). The local `main` ref is 37 commits behind `origin/main`; it was not changed.
- The active branch includes the newer existing commits `a2b0c53`, `58d63ab`, and `2c1f341`, which were not in the original checkout. The older branch was preserved.
- The worktree `/tmp/linuxsecmonitor-skip-report` is registered but its directory is missing; Git reports it as prunable. It was not pruned or deleted.
- At audit start, the only untracked working-tree file was `kali-host-report.json` (host scan output). It was not opened for content, changed, staged, or committed. The ignored `scan.json` artifact is also treated as user data. New development files are listed in the post-audit update below.
- No CI workflow, packaging metadata, installer, or uninstall implementation was found in the project file listing.

## Environment and exact baseline test run

Environment observations: Kali GNU/Linux Rolling 2026.3; Python 3.14.7; APT 3.3.3+kali1; dpkg 1.23.11+kali; project virtual environment has pytest 9.1.1. `requirements.txt` declares only `pytest>=7.0`; scanner modules use the Python standard library and external system tools.

Commands executed for this audit:

```text
pwd
git rev-parse --show-toplevel
git remote -v
git status --porcelain=v2 --branch
git branch -avv
git log --oneline --decorate --all -12
git worktree list --porcelain
rg --files -g '!*.pyc' -g '!__pycache__' -g '!.venv/**' -g '!.git/**'
python3 --version
.venv/bin/python -m pip show pytest
.venv/bin/python -B -m pytest -q -p no:cacheprovider
docker info --format 'Server={{.ServerVersion}} OS={{.OperatingSystem}} Rootless={{.SecurityOptions}}'
docker image ls --format '{{.Repository}}:{{.Tag}} {{.ID}}'
```

Observed current-branch baseline: **384 passed, 2 skipped, 0 failed in 16.82s**. Both skips are opt-in live OSV integration tests (`tests/integration/test_debian_osv_live.py` and `tests/integration/test_ubuntu_osv_live.py`); their environment guards were not enabled. This is a unit/mocked suite result, not proof of live OSV, real APT, or privileged installation behavior.

An earlier checkout before incorporating the newer existing branch commits ran 378 passed and 2 skipped. The current baseline above is the relevant one for this development branch.

APT validation availability checks found the host is Kali, not the README's Debian 12 target. Docker is installed but the daemon socket is inaccessible; QEMU is installed but no provisioned Debian guest image was found. No real APT integration test was run. The existing README describes a disposable Debian 12 temporary-config test; it does not claim that this audit ran that procedure.

## Features supported by code and tests

The following are code-inspection findings with related unit-test coverage; the baseline test run supports those tests passing, but not every target-host behavior:

- Host OS, distribution, kernel, architecture, Python version, and hostname collection (`scanner/system_info.py`).
- Debian-family package inventory via `dpkg-query`, with malformed/incomplete inventory reporting (`scanner/package_scanner.py`).
- Ubuntu OSV and Debian source-package OSV assessment, release-aware matching, Debian version ordering, bounded network calls, validated advisory records, and a 24-hour Debian advisory cache (`scanner/vulnerability_assessment.py`). Kali assessment is explicitly unsupported.
- Bounded `.deb` inspection with `dpkg-deb`, safe extraction into temporary storage, ClamAV scanning, metadata and maintainer-script heuristic inspection (`scanner/malware_scanner.py`). Scripts are read, not executed, during scanning.
- A guarded one-archive `--preinstall-deb` flow and an experimental `--apt-preinstall-hook` path in `main.py`.
- Repository inventory, staged-file ClamAV scanning, and bounded static heuristics, with symlink/path/size limits and coverage statuses (`scanner/repository_scanner.py`, `scanner/repository_malware_scanner.py`, `scanner/repository_security_scanner.py`).
- Human-readable and JSON report paths, CLI diagnostics, and exit statuses, with unit coverage in `tests/test_main.py`.
- The newer branch commits add better repository coverage reporting, generated-path exclusions, and shell comment-only-line handling. These changes are included on the development branch and covered by the baseline suite.

## Features present but not adequately validated

- **APT hook timing and cancellation:** the code parses Pre-Install-Pkgs v3, scans archive actions, and returns nonzero for malformed/error/incomplete cases. Unit tests cover mocked parser and decision paths. No disposable Debian/Kali APT transaction was run. In particular, cancellation has not been proven to prevent a real maintainer script from executing.
- **APT approval:** exact `INSTALL` approval behavior is unit-tested with a fake terminal; real terminal and APT interaction is unverified.
- **APT archive handling:** archive identity checks and scanning are unit-tested, but dependency transactions, upgrades, concurrent APT activity, real missing archives, and actual scanner failures through APT remain unverified end to end.
- **ClamAV operation:** the code has timeout/error/coverage handling, and tests mock scanner outcomes. This audit did not establish that the installed ClamAV binary has usable signatures or that a real fixture scan succeeds.
- **Live vulnerability sources:** OSV integration tests were skipped; live advisory availability and current data were not verified.
- **Host operation:** the Kali baseline tests are mainly mocked. The audit did not run a full host scan or report its package inventory.
- **Historical README validation:** README text records Debian 12 host validation, but that historical statement was not reproduced in this audit and is not treated as current runtime evidence.

## Partial and missing requirements

- Repository checks are advisory `--scan-repo` operations. They do not intercept `git clone`, shell commands, build tools, or package-manager lifecycle execution. Git hooks are reviewed heuristically but are not an enforcement boundary.
- There is no managed system APT-hook setup/status/enable/disable/uninstall or configuration-restoration command. The local Python package can be installed into and removed from a virtual environment; that lifecycle is documented and was runtime-tested after the initial audit. `--doctor` is read-only diagnostics, not system-hook management.
- At initial audit, CI, packaging metadata, and an installed CLI entry point were absent. Follow-up added `.github/workflows/tests.yml`, PEP 621 setuptools metadata, and the `linuxsecmonitor` console command. The workflow has not run on GitHub.
- No supported Kali vulnerability provider exists. Other distributions are explicitly unsupported for package inventory/assessment where applicable.
- At initial audit the APT hook accepted archive-less `**CONFIGURE**` and `**REMOVE**` records without scanning. Follow-up source review identified this could allow maintainer-script-capable operations without archive review. The hook was subsequently changed to reject every removal and every configure action without a matching transaction archive; a matching configure remains covered by the archive scan. This is unit-tested, but real APT transaction behavior remains unverified.
- Follow-up review found clean transactions returned success without a user decision. The hook now requires exact interactive `INSTALL` approval for every fully scanned transaction, including clean ones; detections and heuristic review leads remain visible, while any incomplete/error result blocks before prompting. Unit tests cover clean approval and no-terminal cancellation. Actual APT-to-dpkg timing is still unverified.

## Security weaknesses and coverage limits

- APT `Pre-Install-Pkgs` is documented by Debian as a command list run before dpkg invocation. Its stream reports archive actions and `**CONFIGURE**`/`**REMOVE**` actions, and protocol v3 adds architecture and Multi-Arch fields. The implementation requests v3 via `DPkg::Tools::Options` in the documented temporary config. This is evidence from code and Debian's `apt.conf(5)`, not a demonstrated transaction on this host.
- Any APT hook configured before LinuxSecMonitor, including another `Pre-Install-Pkgs` command or another hook type such as `Pre-Invoke`, may run first. Debian documents that `dpkg-preconfigure --apt` runs package `config` scripts before installation ([`dpkg-preconfigure(8)`](https://manpages.debian.org/bookworm/debconf/dpkg-preconfigure.8.en.html)). The README's disposable procedure checks for other hooks and orders LinuxSecMonitor before `apt-listchanges` and `dpkg-preconfigure`; no such ordering was verified in a real APT transaction.
- Direct `dpkg`, alternate package front ends, other APT commands without the temporary config, and concurrent privileged package operations are not covered by the documented test.
- The Pre-Install-Pkgs stream has no total-record count/checksum. Exact-boundary truncation cannot be detected from the stream alone, as documented by the project.
- The manual local-package workflow does not cover dependency archives installed from repositories. APT hook coverage of all archives in its transaction remains to be demonstrated by integration testing.
- `--scan-repo` does not prevent a later user or tool from executing repository code. The scanner is not a sandbox or complete static analysis.
- ClamAV `no_detection` and OSV `no_known_match` are limited to their data and coverage; neither proves safety.
- Resource bounds and cooperative timeouts do not provide kernel-level CPU/memory isolation or hard deadlines for every filesystem operation.
- Persistent APT-hook setup/uninstall recovery is absent. The separate local virtualenv package lifecycle has been validated, but does not configure or restore system APT settings.

## Compatibility observations

- At audit start the code declared Python 3.10+ support. Python 3.10 reached upstream end of life on 2026-10-01; its final security release confirms no more security updates ([Python 3.10.22 release](https://www.python.org/downloads/release/python-31022/)). The implementation, package metadata, diagnostics, README, and CI matrix now require Python 3.11+ to avoid claiming support for an unmaintained interpreter.
- A compatibility check found `python3.10` through `python3.13` unavailable in the current environment; only Python 3.14.7 is locally installed. `pip check` reported no broken requirements. CI targets 3.11–3.14, but it has not been run on GitHub. Ubuntu 22.04's system Python is below the new minimum; the README calls this out.
- After raising the minimum, `tests/test_diagnostics.py` passed **6 tests**, including explicit Python 3.10 rejection and 3.11 acceptance; the offline full suite passed **424 passed, 2 skipped**. A temporary wheel build from a clean copied source tree succeeded and its generated metadata stated `Requires-Python: >=3.11`. A disposable virtualenv using system site packages passed `pip install --dry-run --no-build-isolation --no-deps .`; Ruby's YAML parser accepted the pinned workflow. `actionlint` is unavailable. Initial packaging checks failed in the project venv because isolated build dependencies could not resolve PyPI, then because that venv lacks setuptools with build isolation disabled; a direct system pip attempt was refused by Kali's PEP 668 externally-managed-environment guard. No system package install was attempted.
- After those compatibility changes, the full suite was rerun with both live OSV tests enabled and approved network access: **426 passed in 39.54s**. The live cases passed along with the offline suite.
- CI now pins `actions/checkout` to `3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1) and `actions/setup-python` to `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` (v7.1.0), verified against their official release commit pages. Pinning makes the action code references immutable; this project's workflow has not executed on GitHub.
- Kali package inventory is supported in code, but Kali vulnerability assessment is unsupported. The current host's APT version differs from the Debian 12 version targeted by the hook procedure.
- Repository safe-walk functionality requires POSIX no-follow directory descriptor support; Windows behavior is intentionally unavailable/mocked for those scans.
- OSV live integration requires network access and was skipped.

## Prioritized implementation and validation plan

1. Establish real APT ordering and cancellation in a disposable Debian 12 VM using synthetic packages. Include a marker-writing maintainer script triggered by a static review lead; require marker absence, no dpkg invocation, nonzero APT exit, and no configured package after cancellation. Test approval separately with a harmless package.
2. Validate the new configure/remove fail-closed policy in real APT transactions, then test missing archives, scanner failure, interruption, noninteractive operation, and unsupported protocols.
3. Add a documented safe execution wrapper that scans a repository, reports scope, requires explicit approval, and invokes a command as an argv vector with `shell=False`; document that this is a user-mediated wrapper, not system-wide enforcement.
4. Expand deterministic `.deb` synthetic fixtures for malformed archives, unusual paths, missing metadata, resource limits, and heuristic script findings; keep package scripts inert during all scan tests.
5. Add operational setup/status/disable/uninstall design only after integration validation; keep persistent system configuration opt-in and require explicit authorization before applying it.
6. Add CI for non-privileged tests and later test supported Python versions. Run compileall, full pytest, `git diff --check`, and secret/sensitive-artifact review before any local commit or release proposal.

## Audit conclusion

LinuxSecMonitor has substantial implemented functionality and a passing deterministic suite. It is **not production-ready as an automatic APT or repository pre-execution protection system**: the APT cancellation timing is unverified on a real disposable transaction, repository scanning does not intercept execution, and persistent setup/recovery lifecycle commands are absent. No APT system configuration was changed, no package was installed, and no GitHub push was performed.

## Post-audit development update

After recording the baseline, a user-mediated `--safe-run REPOSITORY -- COMMAND...` entry point was added. It runs the existing inventory, ClamAV snapshot, and static-review stages, blocks incomplete scans and ClamAV detections, requires exact `RUN` approval before starting commands, uses an argv vector with `shell=False`, and does not serialize command arguments into its report. Cancellation and approval were exercised with harmless marker commands in temporary test directories. Latest focused verification: **96 passed** across `tests/test_execution_guard.py` and `tests/test_main.py`.

This wrapper does not intercept direct commands, provide a sandbox, or protect against repository changes by a concurrent writer. This addition does not change the APT validation status or implement persistent setup/uninstall.

A read-only `--doctor` command was also added. It reports supported-host and Python status, tool availability/version summaries, and counts effective `DPkg::Pre-Install-Pkgs` / `DPkg::Pre-Invoke` entries without emitting configured hook commands. APT settings are captured only to count entries and are not serialized. It states that tool versions and hook counts do not prove signature freshness or safe APT timing. Its diagnostics and CLI tests passed: **91 passed** in the focused run after correcting a test override for an empty command map.

Additional post-audit runtime evidence:

- A synthetic `.deb` was built with `dpkg-deb --build` and scanned through `main.py --scan-deb ... --json`. Build exit was 0; scan exit was 0; status was `no_detection`; coverage was complete; static maintainer-script review reported `startup-persistence-write`; the script's marker remained absent. The package was not installed and its script was not executed.
- After adding stale-database warning handling, a second minimal synthetic `.deb` with no maintainer scripts was built in a temporary directory and scanned by the actual CLI. `dpkg-deb --build` exited 0; `main.py --scan-deb ... --json` exited 0 with `status=no_detection`, `coverage_complete=true`, and the real `dpkg-deb + ClamAV clamscan` backend. It was not installed.
- Follow-up runtime validation built another harmless synthetic `.deb` and passed a real protocol-v3 input stream to a separate `main.py --apt-preinstall-hook` process. The hook accepted v3, scanned the archive with dpkg-deb and ClamAV, returned `no_detection` with complete coverage and a `startup-persistence-write` review lead, then blocked because no controlling terminal supplied approval (exit 1). The postinst marker remained absent. Separate real hook-process invocations returned exit 1 for a v2 header, a missing archive, an archive-less configure action, and a removal action. These validate executable-level fail-closed behavior, not APT invocation timing or a real APT cancellation.
- After the clean-transaction approval change, a fresh synthetic package without maintainer scripts was built with `dpkg-deb --build` (exit 0) and passed through a real hook CLI subprocess with a valid v3 stream. The real `dpkg-deb + ClamAV clamscan` path returned `no_detection`; because the subprocess had no controlling terminal, the hook exited 1 with `explicit terminal approval was not received`. `dpkg-query` confirmed the fixture package was not installed. This is hook-process evidence only; the fixture had no maintainer script and APT itself was not invoked.
- A later package-scanner hardening bounds `dpkg-deb --field` output to 64 KiB, terminates the process after the existing 60-second command limit, and rejects invalid UTF-8. Unit tests cover oversized metadata and timeout. A harmless synthetic `.deb` was built and scanned through the CLI after this change: build exit 0, scan exit 0, `no_detection`, complete coverage, real `dpkg-deb + ClamAV clamscan` backend.
- Added `tests/test_apt_hook_cli.py` to preserve process-level checks for unsupported protocol version, archive-less configure/remove actions, and a missing archive. The focused hook suites reported **77 passed**; the final suite after adding these four tests reported **413 passed, 2 skipped, 0 failed in 16.21s**.
- The first run of `tests/test_apt_hook_cli.py` had 1 failure and 3 passes because its assertion expected the same capitalization in two different block messages. The assertion was corrected; focused hook rerun passed. This was a test expectation issue, not a production-code adjustment.
- Vulnerability provider responses were previously read without byte bounds. Added limits of 16 MiB for query batches, 8 MiB for a full advisory, and 128 levels of JSON nesting, with provider errors on violation. Tests cover oversized Ubuntu and Debian responses, oversized Debian advisory hydration, and excessive JSON nesting. Focused vulnerability suites passed **113 tests**. Live OSV remained unavailable/skipped, so current remote-service behavior and actual response sizes remain unverified.
- Package scanning previously ignored successful-run ClamAV stderr, including its stale-database warning. It now makes coverage incomplete when ClamAV reports a database older than seven days and preserves detection evidence if a signature also matches. Tests cover clean and detected stale-database outcomes. The installed ClamAV on this host reports database build time 26 Oct 2026, within seven days of the 28 Oct 2026 audit date; this is host-specific evidence, not a future guarantee.
- Added `pyproject.toml` with the `linuxsecmonitor = main:main` console entry point. Installed the project without dependencies into a disposable temporary virtual environment and ran `linuxsecmonitor --help` successfully. This verifies package build and command wiring only; it does not install system hooks or establish an end-user setup/recovery lifecycle.
- Follow-up local lifecycle check installed the project into a disposable virtual environment, ran the installed command's help, uninstalled it and verified the entry point/package were absent, then reinstalled and ran help again. Install, uninstall, and reinstall all succeeded. The environment and generated build metadata were cleaned up; no system APT configuration was touched.
- An initial OSV limit-test run reported 1 failure and 112 passes because Python's JSON decoder accepts deep arrays; the test had assumed the decoder itself rejects them. The implementation now checks nesting before parsing, and the focused suite passed 113 tests. The final complete suite after this change reported **417 passed, 2 skipped, 0 failed in 16.72s**.
- ClamAV reports version/signature database `1.4.6/28165`. `clamscan --version` reported `ClamAV 1.4.6/28165/Mon Oct 26 11:57:07 2026`. `sigtool --info /var/lib/clamav/daily.cvd` reported build time `26 Oct 2026 06:27 +0000`, version 28165, and `Verification OK`. This establishes that this host had a recent database at audit time, not that future signatures will remain current.
- Actual `--doctor --json` output on Kali reported `supported_host`, Python 3.14 supported, package inventory and `.deb` prerequisites available, APT hook prerequisites available, one pre-install hook, and zero pre-invoke hooks. No hook command contents were included. This does not verify hook protocol/timing.
- The real CLI scanned a harmless temporary repository with the installed scanners. Inventory, ClamAV, and static review all reported complete, with ClamAV `no_detection`. With no controlling terminal the command was cancelled (exit 3); its marker remained absent.
- Two attempts to exercise actual CLI approval through the tool PTY also cancelled because `/dev/tty` was unavailable to the child process. They are failed/inconclusive approval integration attempts, not passes. The unit test did use an injected terminal to approve and launch a harmless real child process, which created its marker. No APT transaction or package installation was run.
- The README temporary-configuration procedure includes Debian VM cancellation checks using synthetic packages with marker-writing postinst scripts. It requires APT v3 acceptance, a blocked/nonzero transaction, no preconfigure/dpkg package-processing exec in `strace`, no configured package status, and absent markers. The procedure was reviewed but **not executed** because no disposable Debian VM was available.
- The README also defines a separate approval transaction on a clean snapshot. It requires exact `INSTALL` approval, successful APT exit, marker content, configured package status, and a trace showing the synthetic postinst executed, followed by immediate snapshot rollback. This procedure is also **not executed**.
- After bounding OSV responses, the complete suite reported 417 passed, 2 skipped. Packaging then passed and the complete suite again reported 417 passed, 2 skipped. After stale-ClamAV-warning handling, the full suite reported 419 passed, 2 skipped. The later clean-transaction approval change passed the focused hook suite (**78 passed**) and full suite (**420 passed, 2 skipped**). The metadata-output cap passed the focused package scanner suite (**29 passed**) and the latest full suite (**422 passed, 2 skipped, 0 failed in 21.18s**). The first focused run after the clean-approval change reported two failures because tests expected the previous auto-continue behavior; those tests now supply or omit approval as intended. `PYTHONPYCACHEPREFIX=/tmp/linuxsecmonitor-final-pycache python -m compileall -q main.py scanner tests` and `git diff --check` both exited 0 after the latest scanner changes; the diff check was rerun after the report update. The pattern-based secret scan emitted no matching file paths; the existing `kali-host-report.json` was excluded and not inspected.
- A disposable guest was still unavailable. An approved attempt to fetch Debian 12's cloud image from `https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2` produced only a truncated 196,608-byte QCOW file; `qemu-img check` reported reference regions beyond EOF. Fetching `SHA512SUMS` failed with `curl: (6) Could not resolve host: cloud.debian.org`. The incomplete image was not booted or used for validation.
- Environment recheck after the latest change still found no `/dev/kvm`; `/var/run/docker.sock` exists but `docker info` fails with `operation not permitted`. No disposable VM runtime became available.
- The live OSV integration tests were first run without network elevation and both failed because DNS resolution for OSV was unavailable; the exact error was `Temporary failure in name resolution`. After network approval, the focused integration command passed **2 passed in 6.84s**. The complete suite without network approval then again reported **2 failed, 422 passed** for those same DNS failures. With network access approved, the full suite ran with both live flags and passed **424 passed in 22.03s**. The live tests exercised fixed Debian 12 OpenSSH/CVE-2024-6387 and Ubuntu 22.04 bash/CVE-2022-3715 fixture assessments against current OSV data; they do not establish complete advisory coverage for either distribution.
- A further actual CLI JSON-mode safe-run scan reported valid JSON on stdout, the human preview on stderr, cancellation status, exit 3, and no marker execution.
- Added files: `.github/workflows/tests.yml`, `PROJECT_AUDIT.md`, `pyproject.toml`, `scanner/diagnostics.py`, `scanner/execution_guard.py`, `tests/test_apt_hook_cli.py`, `tests/test_diagnostics.py`, and `tests/test_execution_guard.py`. Modified files: `README.md`, `main.py`, `scanner/apt_hook.py`, `scanner/malware_scanner.py`, `scanner/vulnerability_assessment.py`, `tests/test_apt_hook.py`, `tests/test_debian_assessment.py`, `tests/test_main.py`, `tests/test_malware_scanner.py`, and `tests/test_vulnerability_assessment.py`. `PROJECT_FINAL_REPORT.md` records the current validation summary.

## Follow-up development: `.deb` vulnerability assessment

The audit found that standalone `.deb` scanning returned only malware results,
despite the project already having distro-aware OSV assessment logic. The
manual `.deb` workflows now collect the Debian `Source` control field where
present, conservatively infer source identity only when that field is omitted,
and attach a separate `vulnerability_assessment` report based on the host's
detected distribution and release. Missing or malformed Debian source identity
is kept as `requires_review`; the binary version is not substituted. Kali
remains explicitly unsupported. OSV assessment failures are reported without
including arbitrary exception text. `--scan-deb` now exits nonzero when the
vulnerability result is unsupported, incomplete, erroneous, or vulnerable.
The explicit `--preinstall-deb` confirmation remains a user decision after both
results are displayed; its malware completeness gate is unchanged.

Changed files in this follow-up: `scanner/malware_scanner.py`, `main.py`,
`tests/test_malware_scanner.py`, `tests/test_main.py`, `README.md`,
`PROJECT_COMPLETION_CHECKLIST.md`, and `PROJECT_FINAL_REPORT.md`.

Evidence after this change:

- Focused package/CLI run: **123 passed**. A later `tests/test_main.py` run
  after adding a pre-install report assertion passed **91 tests**.
- Current offline full suite: **431 passed, 2 skipped in 21.08s**. Current
  live-enabled full suite: **433 passed in 18.83s**; both opt-in OSV tests
  passed with approved network access.
- `PYTHONPYCACHEPREFIX=/tmp/linuxsecmonitor-completion-pycache python -m compileall -q main.py scanner tests` exited 0. Both staged and unstaged `git diff --check` exited 0.
- A real synthetic `.deb` with only documentation was built (exit 0) and
  scanned on Kali using `dpkg-deb` and ClamAV. Malware result was
  `no_detection`, coverage complete; vulnerability result was `unsupported`
  for `Kali GNU/Linux Rolling`; CLI exited 1 as documented.
- A separate synthetic `.deb` had a harmless `postinst` that would write a
  marker. `--scan-deb` reported `no_detection` and vulnerability `unsupported`,
  exited 1, and the marker remained absent. The package was not installed.
- The Debian source mapping path is unit-tested with a mocked assessor. Actual
  Debian/Ubuntu `.deb` CLI assessment remains unverified because no such guest
  is available. APT transaction-level OSV assessment has since been added to
  the hook: package source identities are aggregated once per transaction;
  assessment errors and `requires_review` block, while unsupported platform
  status is shown and requires explicit approval to continue. The real APT
  cancellation and approval behavior remains unverified.

### Latest validation rerun (2026-10-29)

- APT hook focused tests: 81 passed.
- Offline full suite: 434 passed, 2 skipped in 20.78s.
- Live-enabled OSV suite: 436 passed in 27.15s; network access was approved.
- Compilation and staged/unstaged `git diff --check`: exit 0.
- The APT assessment unit tests use a mocked provider. No real APT transaction
  ran, and cancellation/approval remain unverified for the reasons recorded in
  `PROJECT_COMPLETION_CHECKLIST.md` and `PROJECT_FINAL_REPORT.md`.

The older runtime bullet above that records `--scan-deb` exit 0 describes the
CLI before this follow-up added OSV status to its success decision. It is
historical evidence for the earlier malware-only CLI behavior, not the current
exit status policy.

## Fresh-session verification (2026-10-29)

The current checkout was re-inspected after a session change. The worktree
still has the staged and unstaged changes described by `git status`; the
untracked `PROJECT_COMPLETION_CHECKLIST.md` and `kali-host-report.json` were
preserved, and the host report was not opened. No guest process, Debian image,
overlay, seed image, SSH key, or VM transaction log was found under the
project, `/tmp`, or `/var/tmp`. The only `.deb` found in the user test
directory was the existing harmless EICAR test artifact; it was not installed.
There is no `/dev/kvm`, and `cloud.debian.org` did not resolve. APT cancellation
and approval therefore remain untested.

Current validation:

- Offline full suite: **434 passed, 2 skipped in 39.65s**.
- Live-enabled full suite: **436 passed in 42.22s**, including both live OSV
  tests.
- Targeted APT hook/CLI, diagnostics, malware, execution guard, Debian and
  general vulnerability assessment, and main CLI tests: **335 passed in
  22.40s**.
- `main.py --help`, read-only `--doctor --json`, `pip check`, compilation,
  `git diff --check`, and `git diff --cached --check` exited 0. Pip warned that
  its cache directory is not writable and that LinuxSecMonitor is not installed
  in the current virtual environment. The project defines no lint or formatter
  tool/configuration.
- Doctor reports Kali 2026.3, Python 3.14, APT 3.3.3, ClamAV 1.4.6/database
  28165, one Pre-Install-Pkgs entry, and zero Pre-Invoke entries. These host
  observations do not establish Debian compatibility, APT protocol behavior,
  hook order, or cancellation timing.

The earlier `db: unbound variable`, SCP destination, SSH startup-delay, and
slow `.deb` scan reports have no corresponding saved logs in the repository or
available VM artifacts. Their original causes remain undetermined. The current
README package-status query quotes `${db:Status-Abbrev}` to protect it from
shell expansion, but this cannot establish that the earlier command used the
same form. No code change was made in this revalidation. No host APT
configuration, host package state, or persistent system setting was changed.
The project remains **NOT READY for controlled real-world APT testing** until
the documented cancellation and approval tests run in a disposable Debian
guest and produce package-state and execution-trace evidence.

## Disposable Debian preparation and scan blocker (2026-10-29)

The missing-VM blocker was partially cleared. The official Debian 12 generic
cloud image was downloaded to `/tmp`; its SHA-512 matched Debian's published
`SHA512SUMS`, and `qemu-img check` found no errors. The first download hit its
120-second limit at 73%; resuming the partial file completed it. A NoCloud
seed and ephemeral Ed25519 SSH key were created under
`/tmp/linuxsecmonitor-debian-validation`. QEMU user networking exposed SSH
only on `127.0.0.1`; no bridge or host APT setting was involved. The guest
booted as Debian GNU/Linux 12 (Bookworm), Python 3.11.2. ClamAV, freshclam,
strace, and apt-listchanges were installed in that disposable overlay after
`apt-get update` fetched 26.4 MB. The freshclam service populated `daily.cvd`;
ClamAV reported `1.4.6/28168/Thu Oct 29 06:24:16 2026`.

The guest's system hook list was observed as `apt-listchanges` followed by
`dpkg-preconfigure`, with no `DPkg::Pre-Invoke` entry. `apt-config -c` with the
test-only root-owned configuration showed the LinuxSecMonitor command first,
then those two hooks. This verifies effective configuration output only; no
real transaction ran to observe execution order.

A new local fixture `linuxsecmonitor-apt-hook-marker_0.0.1_all.deb` was built
for the test. Its `preinst` and `postinst` only write markers; `postinst` also
writes a hidden cron file containing a `true` command to trigger static review.
The existing EICAR artifact was not used. The new package was copied into the
guest's root-owned hook directory and scanned, never installed.

The real CLI scan reproduced the slow-scan issue: it returned `scan_exit=1`
and reported **`ClamAV timed out while scanning package contents.`** Concurrent
process evidence showed `clamscan` at approximately 99.5% CPU after 42 seconds;
it continued until the scanner's 120-second timeout. The report included the
expected `startup-persistence-write` lead and OSV `no_known_match`, but
`coverage_complete` was false. This was a genuine incomplete scan, not a clean
result. Since the hook uses this same scanner path, it is expected to hit the
timeout before prompting; no APT run confirmed this. Neither requested
transaction was run. There is no APT cancellation or approval exit
status, marker result, package-state comparison, or dpkg execution trace.

A separate overlay booted with `-accel tcg,thread=multi -smp 2` panicked in the
guest kernel with `IO-APIC + timer doesn't work`. The failed QEMU process was
stopped. The setup and probe overlays both passed `qemu-img check`; neither
remains open and no QEMU process is running. Do not substitute a mocked
scanner or weakened signature database to bypass this performance blocker.

Host SSH first rejected `/etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf` for
unsafe permissions; `ssh -F /dev/null` avoided that unrelated client config.
The guest took about a minute to reach cloud-init/sshd, reproducing startup
delay. The earlier SCP destination error has no saved log, but SCP with the
explicit remote directory path succeeded. The current package-status query
quotes `${db:Status-Abbrev}` correctly; the earlier variable error has no
saved command to reproduce. The slow `.deb` scan was reproduced as the
120-second ClamAV timeout and is not claimed fixed.

The offline full suite passed **434 tests with 2 skips in 23.68s**; the
live-enabled suite passed **436 in 30.32s**; the focused relevant suite passed
**335 in 23.50s**. Compilation, `pip check`, CLI help, diagnostics, and both
staged and unstaged diff checks completed successfully. No host package
operation or persistent host modification occurred. A Debian guest with
hardware acceleration or equivalent real ClamAV performance is the specific
remaining prerequisite; then perform cancellation and approval from separate
fresh overlays sharing this prepared baseline.

The current pyproject also built successfully to a wheel from a clean `/tmp`
source copy using system Python 3.14.7/setuptools 78.1.1. Wheel metadata
declared Python `>=3.11` and the `linuxsecmonitor = main:main` entry point;
installing into a temporary venv and running `linuxsecmonitor --help` worked.
An initial no-isolation build using the project venv failed because that venv
does not contain setuptools. Ruby parsed the GitHub Actions YAML; GitHub CI was
not executed.

## Final implementation continuation (2026-10-29)

Added `scanner/apt_lifecycle.py` and the `--apt-integration` lifecycle CLI.
The managed hook uses a dedicated APT drop-in and root-owned receipt, refuses
conflicting or edited configuration, validates generated configuration with
`apt-config`, checks that its interpreter/modules are root-owned and not
group/world-writable, and rolls back ordinary partial-write failures. Eight
temporary-root tests pass for idempotence, preservation, conflict handling,
rollback, runtime trust, and APT parser acceptance. System lifecycle changes
were not applied; process-termination recovery remains unverified.

The ClamAV hard-timeout result now has `status=incomplete` with
`coverage_complete=false`. The deadline was not raised. A new local host test
package with a harmless `postinst` marker built successfully (`dpkg-deb
--build`, exit 0) and scanned through the real scanner as `no_detection` with
complete coverage. Its marker remained absent and `dpkg-query` reported the
package absent before and after. This is a host `.deb` scan, not an APT test.
The Debian 12 guest TCG timeout is not fixed: its prior `clamscan` run reached
the 120-second limit near 100% of one emulated CPU. KVM remains unavailable;
the attempted multithreaded TCG guest panicked.

Final reruns: focused lifecycle/APT/scanner/CLI command **229 passed in
24.01s**; offline suite **444 passed, 2 skipped in 17.58s**; live OSV suite
**446 passed in 22.89s**. A final wheel built from a clean temporary source
copy, installed into a temporary virtual environment, and its CLI help ran.
`pip check`, compileall, both staged and unstaged `git diff --check`, and Ruby
workflow YAML parsing exited 0. GitHub Actions was not run. Detailed status and
test evidence are in `PROJECT_FINAL_REPORT.md` and
`PROJECT_COMPLETION_CHECKLIST.md`.

**Final verdict: IMPLEMENTED — INTEGRATION TESTS STILL BLOCKED.** Neither real
APT cancellation nor approval was run. Host APT configuration/package state
was not changed; no package was installed; no commit, push, or release occurred.

### Latest revalidation addendum (2026-10-29)

APT lifecycle follow-up corrected the managed filename to
`00linuxsecmonitor` so it is loaded before ordinary later APT drop-ins, and
corrected protocol-v3 selection to APT's command-specific
`DPkg::Tools::Options::<command>::Version` option. Install/enable now inspect
the effective merged hook list using `apt-config` and roll back if the
managed hook is not first; `status` reports a conflict in that case. Tests
exercise a simulated later `#clear` and rollback. This does not cover
caller-supplied APT overrides.

An opt-in Debian/Ubuntu integration harness now defines three real APT
transactions (safe approval, finding cancellation, finding approval), guarded
by a root-owned disposable guest marker and recording APT output, package
state, markers, effective configuration, and `strace`. These tests were not
run: they were correctly skipped on Kali. `/dev/kvm` is absent, Docker daemon
access is denied, and the earlier Debian 12 TCG ClamAV test remained bounded
by the documented 120-second timeout. Therefore neither APT cancellation nor
approval nor privileged guest lifecycle operations are verified.

Latest offline suite: **453 passed, 5 skipped in 22.32s**. Latest live OSV
suite: **455 passed, 3 skipped in 24.98s**; the three remaining skips are the
opt-in real APT transactions. `compileall`, `pip check`, Ruby workflow YAML
parsing, and staged/unstaged `git diff --check` passed. The project venv lacks
the `build` module; system Python 3.14.7 successfully built a wheel via
`pip wheel --no-deps --no-build-isolation`, which installed into a temporary
venv and exposed a working CLI help entry point. GitHub Actions was not run.
No host APT settings/package state, commit, push, or release occurred.

Readiness remains **IMPLEMENTED — INTEGRATION TESTS STILL BLOCKED**.

### Harness and scanner follow-up (2026-10-29)

Lifecycle `install` and `enable` are now idempotent only for byte-identical
LinuxSecMonitor-owned state; malformed, modified, or unowned files continue to
be refused. Temporary-root lifecycle tests passed.

The opt-in guest harness now includes five independent scenarios: safe
approval, finding cancellation, finding approval, incomplete-coverage denial,
and lifecycle install/enable/disable/uninstall/recovery. The incomplete case
uses a harmless `.deb` containing a symlink whose target remains inside the
package. The lifecycle case snapshots unrelated APT configuration and package
state, checks root ownership/modes, refuses/preserves a conflicting managed
filename, repeats operations, and restores the receipt-without-hook state by
enabling. It does not inject a process kill between installer writes. All five
remain unexecuted on a guest.

The incomplete fixture was built and passed through the actual Kali scanner
path using `dpkg-deb` and `clamscan`: observed `status=incomplete`,
`coverage_complete=false`, and the explicit symlink-coverage limitation. It
was not installed and this is not an APT transaction.

Scanner inspection confirms one ClamAV subprocess invocation per `.deb`
assessment, after two `dpkg-deb` archive streams extract the control and data
trees. There is no duplicate ClamAV pass or repeated daemon initialization in
the single-package path. The prior guest's roughly 99.5% CPU usage until the
120-second deadline points to CPU-bound ClamAV work under TCG; a fresh local
fixture scan took about 10 seconds. Existing evidence cannot separate the
ClamAV database/scan cost from the TCG emulation multiplier. The hard timeout
was left unchanged. QEMU is present but `/dev/kvm` and disposable images are
absent; Docker daemon access and host `strace` are unavailable.

Latest re-run: offline **453 passed, 7 skipped (22.09s)**, live OSV-enabled
**455 passed, 5 skipped (26.97s)**, focused APT/lifecycle **98 passed, 5
skipped (0.94s)**. The current wheel built, installed in a clean temporary
venv, passed `pip check`, and ran CLI help (SHA-256
`29ef62ff0dc95d8a1c404dd051166b87835c7219966cc801e6007077e92d03a6`).
APT guest and lifecycle operations remain unverified; actual GitHub Actions was
not run.

Final suite rerun after all follow-up edits: offline **453 passed, 7 skipped
in 17.87s** and live OSV-enabled **455 passed, 5 skipped in 20.97s**.
`compileall`, staged/unstaged diff checks, `pip check`, workflow YAML parsing,
and the read-only CLI APT status check passed. Host status was
`not_installed`; no lifecycle changes were made.

Pre-push rerun: offline **453 passed, 7 skipped in 17.15s**; live OSV-enabled
**455 passed, 5 skipped in 19.76s**. A fresh wheel build/venv install,
installed CLI help, wheel module inspection, and isolated `pip check` passed.
The five guest scenarios and actual GitHub Actions remain unverified.
