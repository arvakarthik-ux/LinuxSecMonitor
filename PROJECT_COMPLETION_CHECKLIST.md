# LinuxSecMonitor Completion Checklist

Updated: 2026-10-29

This checklist records implementation and validation status from the current
checkout. Status labels distinguish code from evidence: IMPLEMENTED, UNIT
TESTED, INTEGRATION TESTED, VERIFIED ON TARGET OS, BLOCKED BY ENVIRONMENT, and
NOT IMPLEMENTED. Unit tests alone do not establish real package-manager behavior.

## Repository and verification baseline

- [x] **COMPLETE — Repository state rechecked (2026-10-29).** Repository root
  is `/home/kali/LinuxSecMonitor`, branch is
  `codex/linuxsecmonitor-completion`, and HEAD is
  `ac139b08a48d7159663aa42a9e2ed3541db27d17`. At the start of the current
  focused pass, ten files had unstaged modifications and there were no staged
  or untracked files; all ten were preserved. This pass also modified the
  vulnerability assessor and its two tests. No
  staged files or untracked non-ignored files are present at final status.
  Private host reports were not opened or modified. No commit or push occurred.
- [x] **HISTORICAL BASELINE — Offline test run from earlier pass.** Command:
  `.venv/bin/python -B -m pytest -q -p no:cacheprovider`; result:
  **434 passed, 2 skipped in 20.78s**. The skipped tests are the opt-in live
  Debian/Ubuntu OSV integration tests. See the exact test files for scope.
- [x] **HISTORICAL BASELINE — Live OSV run from earlier pass.** Command:
  `LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider`;
  result: **436 passed in 27.15s** with approved network access.
- [x] **COMPLETE — Compilation and diff checks.**
  `PYTHONPYCACHEPREFIX=/tmp/linuxsecmonitor-completion-pycache python -m compileall -q main.py scanner tests`
  exited 0. `git diff --check` and `git diff --cached --check` exited 0.
- [x] **COMPLETE — Dependency consistency.** `.venv/bin/python -m pip check`
  exited 0 with “No broken requirements found.” Only Python 3.14.7 is available
  in the current environment; other CI matrix versions are unverified here.

## Feature status

| Area | Status | Present at inspection / changed | Evidence so far | Remaining work and risk |
|---|---|---|---|---|
| Linux host information and package inventory | PARTIAL | `scanner/system_info.py`, `scanner/package_scanner.py`; diagnostics added in `scanner/diagnostics.py` | 431-test offline suite; current-host `--doctor` evidence recorded in `PROJECT_FINAL_REPORT.md` | Verify actual supported Debian and Ubuntu releases; preserve distinction between unsupported, empty, and failed inventory. |
| OSV vulnerability assessment | PARTIAL | Debian/Ubuntu assessment, bounded requests and Debian advisory cache in `scanner/vulnerability_assessment.py`; Kali explicitly unsupported; `.deb` CLI/manual-preinstall and APT hook now call the existing assessor | Current offline suite 434 passed/2 skipped; live-enabled suite 436 passed including two real OSV tests; APT aggregation/blocking behavior has mocked unit coverage; current Kali synthetic `.deb` reports unsupported | Debian/Ubuntu package CLI and APT runtime assessment still need actual distro validation. No claim of complete OSV coverage. |
| `.deb` archive inspection | PARTIAL | `scanner/malware_scanner.py` captures binary and Debian source identity; `main.py` includes OSV in `--scan-deb` and `--preinstall-deb` | Focused package/CLI suite previously 123 passed; live Kali synthetic `.deb` scan reported ClamAV `no_detection`, OSV `unsupported`, exit 1; marker-script fixture remained absent | Debian/Ubuntu assessment needs actual distro runtime validation. Continue adversarial archive-path/size tests. |
| APT pre-install hook | IMPLEMENTED; UNIT TESTED; Kali guest E2E BLOCKED | Protocol v3 parser, identity/path validation, fail-closed malware handling, transaction-level vulnerability assessment, package/action summary, exact `INSTALL` prompt; terminal opens before dropping to `_apt` and approval wait is bounded at 300 seconds | Focused APT/lifecycle tests pass; direct hook execution is not an APT transaction. Kali's unsupported vulnerability status is shown and remains distinct from a clean result. | Run clean approval, cancellation, incomplete denial, multi-archive, failure and hook-order scenarios in a disposable Kali guest; no Kali guest is available here. |
| Repository inspection and pre-execution | PARTIAL | Existing inventory/static scanners plus explicit `--safe-run` in `scanner/execution_guard.py` | Harmless marker child cancellation/approval and focused tests recorded in audit/final reports | This is an opt-in wrapper, not automatic interception or a sandbox. Document and test unsupported paths, repository mutation races, worktrees, submodules and bypasses. |
| ClamAV integration | IMPLEMENTED; UNIT TESTED; TCG PERFORMANCE BLOCKED | `scanner/malware_scanner.py` includes availability, bounded subprocesses, stale-signature warnings, incomplete states, and opt-in per-stage timing/child CPU/RSS diagnostics | Latest harmless local Kali `.deb` completed malware inspection in 12.191s ClamAV wall / 12.161s child CPU, with 989632 KiB completed-child RSS high-water; empty-directory scan took 11.892s / 11.875s CPU and 989064 KiB RSS high-water. | ClamAV initialization/database loading dominates even an empty scan on this host. The previous TCG guest timeout has not been reproduced with new instrumentation and remains unresolved; no security coverage or timeout was weakened. |
| Text and JSON reporting / CLI | PARTIAL | `main.py` supports host reports, `.deb`, repository scan, `--safe-run`, `--doctor`, JSON/text output; `.deb` reports now include a separate OSV result | Offline suite: **434 passed, 2 skipped**; live-enabled suite: **436 passed**; real synthetic Kali `.deb` scan recorded | Continue review of unsupported, incomplete and error exit semantics; verify secret/data minimization. |
| Setup, enable/disable, uninstall and recovery | IMPLEMENTED; UNIT TESTED; target integration BLOCKED BY ENVIRONMENT | `scanner/apt_lifecycle.py` and `--apt-integration status/install/enable/disable/uninstall`; first-order `00` drop-in, dedicated file/receipt, strict ownership/hash checks, conflict refusal, idempotence and failed-install rollback | Temporary-root lifecycle tests, CLI root-refusal tests, and isolated `apt-config` order/config parsing tests; persistent host configuration untouched | Real root installation, file ownership/permissions on supported distributions and interruption recovery after process death remain unverified. Explicit APT config overrides can reorder/bypass the hook. |
| Packaging and CI | PARTIAL | `pyproject.toml`, Python 3.11–3.14 workflow with pinned action SHAs | Local wheel/install smoke check recorded earlier; workflow YAML parsed | GitHub CI has not run; non-3.14 matrix jobs unverified. |
| Kali primary target | IMPLEMENTED; UNIT TESTED; GUEST E2E BLOCKED | Kali `os-release` detection, `dpkg-query` inventory, diagnostics, Debian `.deb` inspection, ClamAV, APT hook and lifecycle code | Kali-specific unit coverage and the current offline suite; no real Kali APT transaction or privileged lifecycle evidence | Kali OSV assessment is explicitly unsupported: no Kali-specific authoritative provider or validated package/version mapping is configured. Do not apply Debian/Ubuntu advisory matches to Kali. |
| Security review and release readiness | PARTIAL — NOT READY for general deployment | Reports document race and enforcement limitations; current APT integration remains experimental | Staged diff reviewed earlier; latest `git diff --check` passed | Complete threat/coverage review and VM tests. No publish or persistent security configuration before explicit authorization. |

## Disposable Kali APT environment blocker

The primary host currently has QEMU and `qemu-img`, but no `/dev/kvm`, no Kali
image in the checked temporary or conventional VM-image locations, and no
VirtualBox, libvirt, VMware, or container guest frontend. Docker is installed
but daemon access is denied. The main Kali system must not be used for
installation tests. A disposable Kali VM/snapshot with hardware acceleration
or equivalent ClamAV throughput is required. No image was downloaded during
this work.

## Remaining required verification

The only release-critical verification still blocked is running the five
real-APT and lifecycle scenarios in disposable Kali snapshots. No additional
implementation feature is required by the frozen Kali-first scope. Secondary
Debian/Ubuntu compatibility must not be inferred from Kali tests, but is not a
prerequisite for limited Kali use.

## Fresh-session revalidation (2026-10-29)

## Final focused implementation update (2026-10-29)

- [x] **UNIT TESTED — Approval terminal lifecycle fixed.** The hook opens and
  retains `/dev/tty` before permanently dropping privileges to `_apt`, avoiding
  an attempt to open the user's terminal after the drop. Terminal input is
  bounded to 300 seconds; unavailable terminal, timeout, EOF, or malformed
  input denies approval. Focused APT, malware and lifecycle tests passed:
  **249 passed in 2.01s** across focused vulnerability, APT hook/CLI, lifecycle
  and malware scanner selection.
- [x] **UNIT TESTED — ClamAV timings added.** `--diagnostics --scan-deb`
  reports package metadata, archive extraction and ClamAV durations, child CPU
  time, the completed-child RSS high-water mark, scanner exit/timeout status,
  and a bounded stderr excerpt on scanner errors. RSS is not a memory time
  series. A failing diagnostics callback cannot change the scan result.
- [x] **MEASURED LOCALLY — Harmless package scan.** On Kali, ClamAV completed a
  harmless synthetic `.deb` scan with `no_detection`, complete malware
  coverage, and process exit 1 because Kali vulnerability assessment is
  unsupported. Package creation took 0.032s; scan total was 12.448s; ClamAV
  took 12.413s wall and 12.383s CPU. The package was never installed.
- [x] **MEASURED LOCALLY — ClamAV startup cost.** A separate empty-directory
  scan took 11.892s wall and 11.875s CPU, returned 0, loaded ClamAV 1.4.6
  signature database build 28165, and had child maximum RSS 989064 KiB. This
  indicates substantial per-process engine/database initialization cost on
  the host; it does not measure or resolve the earlier QEMU TCG multiplier.
- [x] **SOURCE REVIEW — Kali vulnerability data.** Kali's official Package
  Tracker provides package change/version information, not validated Kali
  affected/fixed-version advisories for this inventory mapping. Kali's
  rolling-vs-Debian data shows divergent package versions. Kali assessment
  therefore remains explicitly UNSUPPORTED; Debian/Ubuntu results are not
  relabeled as Kali findings.
- [ ] **BLOCKED — Real Kali APT approval/cancellation/lifecycle.** No Kali guest
  image or `/dev/kvm` is available, and Docker daemon access is denied. The
  existing five guest scenarios were not run. No host APT settings or installed
  packages were changed.
- [ ] **BLOCKED — Prior TCG timeout root cause.** Local measurements establish
  high ClamAV database/engine cost even on an empty directory, but without a
  suitable accelerated Kali guest they cannot quantify the TCG multiplier or
  establish whether the old guest's complete timeout was solely emulation.
- [x] **FINAL LOCAL REGRESSION —** `.venv/bin/python -B -m pytest -q -p
  no:cacheprovider` — **459 passed, 7 skipped in 24.45s**. The five real guest
  tests and two opt-in live OSV tests did not run. Compilation, `pip check`,
  staged/unstaged diff checks and workflow YAML parsing passed.
- [x] **FINAL PACKAGING —** Current tracked source and existing working edits
  were copied to a temporary build tree; wheel built successfully, installed
  into a fresh temporary virtual environment, and installed CLI `--help` and
  `pip check` passed. Wheel SHA-256:
  `1b0101d12a072bc77c197a2c213c08eef11c707053e45895b80b3d5247bf74c0`.
- [ ] **NOT RUN —** No live OSV requests and no GitHub Actions execution.
  Actual Kali APT cancellation/approval/lifecycle transactions remain
  unverified; no commit, push, package installation, or persistent host APT
  modification occurred.

- [x] **COMPLETE — Repository state re-inspected.** Branch remains
  `codex/linuxsecmonitor-completion`. Existing staged and unstaged project
  changes were preserved. `kali-host-report.json` remains untracked user data
  and was not opened or modified. No commit, push, or release was made.
- [x] **COMPLETE — Offline suite rerun.**
  `.venv/bin/python -B -m pytest -q -p no:cacheprovider` —
  **434 passed, 2 skipped in 39.65s**. The skips are the opt-in live OSV tests.
- [x] **COMPLETE — Live OSV suite rerun.**
  `LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider` —
  **436 passed in 42.22s**. Both live OSV tests completed successfully.
- [x] **COMPLETE — Requested targeted areas rerun.** APT hook and CLI,
  diagnostics, malware scanning, execution guard, Debian assessment,
  vulnerability assessment, and main CLI tests — **335 passed in 22.40s**.
- [x] **COMPLETE — Read-only checks.** `--help`, `--doctor --json`,
  `pip check`, compilation, staged/unstaged diff checks all exited 0. Doctor
  reports Kali 2026.3, Python 3.14, APT 3.3.3, ClamAV 1.4.6/database 28165,
  one configured Pre-Install-Pkgs entry, zero Pre-Invoke entries, and explicitly
  warns hook counts do not establish protocol support or ordering. Pip emitted
  a cache ownership warning and reports the project package itself is not
  installed in this venv. No lint/formatter tool or configuration is defined.
- [ ] **BLOCKED — Debian guest APT cancellation and approval.** Reinspection
  found no QEMU process, disk image, overlay, seed image, SSH key, guest log,
  or VM transaction trace under the project, `/tmp`, or `/var/tmp`. The only
  package artifact found was the existing harmless EICAR test `.deb` in
  `/home/kali/linuxsecmonitor-test.npOPWP`; it was preserved and not installed.
  `/dev/kvm` is absent and `cloud.debian.org` DNS lookup fails. No guest was
  created or booted, so there is no cancellation, approval, marker, package
  status, or maintainer-script trace evidence. Host `--doctor` is read-only;
  no host APT configuration or package state was changed.
- [x] **COMPLETE — Earlier transient-error evidence reviewed.** Repository
  documentation contains no saved logs for the earlier `db: unbound variable`,
  SCP destination error, SSH startup delay, or slow `.deb` scan, so their
  original causes cannot be established. The current documented package
  status query single-quotes `${db:Status-Abbrev}` so Bash does not interpret
  it as a shell variable. The old VM-side SCP/SSH and scan timings remain
  unverified and are not treated as resolved by this review.

No automated lint or formatting command was available in the project config.
This revalidation does not change the project readiness verdict: it remains
not ready for controlled real-world APT testing until an isolated Debian guest
is available and both transactions produce the required observable evidence.

## Disposable Debian continuation (2026-10-29)

- [x] **COMPLETE — Fresh tests rerun.** Offline full suite: **434 passed, 2
  skipped in 23.68s**. Live-enabled OSV suite: **436 passed in 30.32s**.
  Targeted APT hook/CLI, diagnostics, malware, execution guard, Debian and
  general vulnerability assessment, and main CLI tests: **335 passed in
  23.50s**. Compilation, `pip check`, CLI help, read-only doctor, and staged
  and unstaged diff checks completed successfully. Pip emitted its cache
  ownership warning. No lint/formatter config is present.
- [x] **COMPLETE — Official Debian guest image verified.** Downloaded the
  official Debian 12 generic cloud image to `/tmp`; its SHA-512 matched the
  official `SHA512SUMS`, and `qemu-img check` found no errors. The initial
  120-second download timed out at 73%; a resumed transfer completed. The
  image was booted in isolated QEMU user networking with SSH bound only to
  loopback. Guest identity was Debian 12 Bookworm, Python 3.11.2. No host APT
  configuration or package state was changed.
- [x] **COMPLETE — Guest prerequisites and order inspected.** Inside the
  disposable setup overlay only, `apt-get update` succeeded and ClamAV 1.4.6,
  freshclam, `strace`, and apt-listchanges were installed. The freshclam
  service downloaded a current database; `clamscan --version` reported
  database 28168 dated 2026-10-29. Guest `apt-config dump` showed the existing
  pre-install order `apt-listchanges`, then `dpkg-preconfigure`, with no
  pre-invoke hook. The test-only `apt-get -c` config reported LinuxSecMonitor
  first, then those two hooks. This verifies effective configuration output,
  not execution order in an APT transaction.
- [ ] **BLOCKED — Real cancellation and approval transactions.** A new harmless
  marker `.deb` was built; it writes only marker files under `/var/tmp` and a
  hidden cron file containing `true` if its scripts execute. It was not
  installed. Running the real project `--scan-deb` against it in Debian
  returned exit 1 with `ClamAV timed out while scanning package contents`.
  Guest process inspection showed `clamscan` consuming about 100% of one
  emulated CPU until the scanner's 120-second timeout. The report also showed
  the expected `startup-persistence-write` review finding and OSV
  `no_known_match`; coverage was incomplete. Because the hook uses this same
  scanner path, it is expected to hit the timeout before prompting; no APT
  run confirmed this. No cancellation or approval APT
  transaction, marker check, package-state comparison, or dpkg execution trace
  was performed. No transaction overlays were created.
- [x] **COMPLETE — Emulation blocker characterized.** QEMU software emulation
  without KVM booted the setup guest but was too slow for ClamAV. A separate
  probe using `-accel tcg,thread=multi -smp 2` panicked in the Debian kernel
  with `IO-APIC + timer doesn't work`. That probe process was stopped. Both
  guest overlays passed `qemu-img check` afterward and no QEMU process remains.
  The probe does not establish product behavior.
- [x] **COMPLETE — Prior command issues reviewed.** Host SSH first rejected its
  global `20-systemd-ssh-proxy.conf` for unsafe permissions; using `ssh -F
  /dev/null` avoided that unrelated host client config. The guest took about a
  minute to reach cloud-init/sshd, reproducing startup delay. The earlier SCP
  destination error was not in saved logs; the current explicit destination
  `debian@127.0.0.1:/home/debian/linuxsecmonitor-source/` worked. The package
  status format in the current README is single-quoted and does not expand as a
  shell variable. The slow scan is reproduced as the 120-second ClamAV timeout
  under TCG; it is not treated as fixed.
- [x] **COMPLETE — Packaging and workflow checks.** Building with
  `.venv/bin/python -m pip wheel --no-deps --no-build-isolation ...` first
  failed because the project venv has no `setuptools` (`Cannot import
  setuptools.build_meta`). Building the same clean source copy with system
  Python 3.14.7 and its setuptools 78.1.1 succeeded. The wheel metadata reports
  `Requires-Python: >=3.11` and `linuxsecmonitor = main:main`. Installing that
  wheel into a temporary venv and running `linuxsecmonitor --help` succeeded.
  Ruby YAML parsing of `.github/workflows/tests.yml` succeeded. GitHub Actions
  itself was not run.

APT integration remains unverified and the readiness verdict remains **NOT
READY for controlled real-world APT testing**. The next prerequisite is a
Debian guest with working hardware acceleration or equivalent performance for
the real ClamAV scan. Then create separate fresh overlays from the same
verified setup baseline and complete both marker transactions with prompt,
exit status, package-state, and `strace` evidence. Keep the image, overlays,
keys, fixture, and reports under `/tmp`; no host-level changes were made.

## Final implementation continuation (2026-10-29)

- [x] **COMPLETE — ClamAV timeout semantics hardened.** A ClamAV scan timeout
  now returns `status=incomplete` and `coverage_complete=false`, retaining the
  actionable timeout detail. The configured 120-second deadline was not
  increased. Existing bounded archive extraction and one ClamAV pass over the
  extracted snapshot remain intact. A local host scan of a freshly built
  harmless marker-script `.deb` completed as `no_detection` with complete
  coverage; the post-install marker stayed absent and `dpkg-query` showed the
  package absent before and after. This distinguishes the local scanner path
  from the recorded Debian guest TCG timeout; it does not validate Debian APT.
- [x] **COMPLETE — Lifecycle implementation and isolated tests.** Added
  `scanner/apt_lifecycle.py` and `--apt-integration status|install|enable|
  disable|uninstall`. System-changing CLI actions require root. The installer
  uses a dedicated APT drop-in and state receipt, rejects conflicts and
  modified files, checks generated config with `apt-config`, validates the
  privileged runtime's ownership, and rolls back ordinary partial-write
  failures. Temporary-root lifecycle tests cover repeated operations,
  unrelated-hook preservation, pre-existing conflicts, symlinks, edited files,
  rollback, runtime path trust, and APT config parsing. **Persistent install,
  process-kill recovery, permissions on Debian, and live hook ordering remain
  unverified.** No host configuration was changed.
- [x] **COMPLETE — Final automated test suites.** Focused APT hook/CLI,
  lifecycle, malware/package scanning, and main CLI command:
  **229 passed in 24.01s**. Offline full suite:
  `.venv/bin/python -B -m pytest -q -p no:cacheprovider` —
  **444 passed, 2 skipped in 17.58s**. Live OSV suite:
  `LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider` —
  **446 passed in 22.89s**. The two skips are only in the offline run and are
  the opt-in provider tests.
- [x] **COMPLETE — Packaging and static checks.** Final wheel built from a
  clean `/tmp` source copy, installed into a new temporary venv, and its
  `linuxsecmonitor --help` entry point ran. Wheel includes `scanner/apt_lifecycle.py`.
  The project and isolated-venv `pip check` commands reported no broken
  requirements. Compilation, staged/unstaged `git diff --check`, and Ruby YAML
  parsing of the CI workflow exited 0. GitHub Actions was not run.
- [ ] **BLOCKED — Real APT transactions.** No real APT cancellation or approval
  was run. The previously recorded Debian 12 QEMU TCG scan timed out at 120
  seconds while `clamscan` used approximately one emulated CPU; the attempted
  multithreaded TCG guest panicked. `/dev/kvm` is absent in this session. The
  local host fixture scan is not a substitute for either APT transaction.

- [x] **UNIT TESTED — APT hook order model.** The lifecycle now uses
  `00linuxsecmonitor`; an isolated `APT_CONFIG`/`apt-config dump` regression
  test verified it appears before a simulated `70debconf` preconfigure hook
  and the main APT config. This checks APT's effective config model only; it is
  not a real transaction on Debian/Ubuntu. The user-controlled `APT_CONFIG`
  environment or explicit `apt-get -c` can still alter or replace hook order.
- [x] **UNIT TESTED — No-overwrite race resistance.** Atomic lifecycle file
  publication now uses same-directory hard-link creation so a concurrent
  destination file causes `EEXIST` rather than being replaced; a regression
  test confirms an existing administrator file remains unchanged.

## Latest engineering continuation (2026-10-29)

- **IMPLEMENTED; UNIT TESTED — APT lifecycle order validation.** The managed
  hook now uses `00linuxsecmonitor`, before ordinary later `apt.conf.d`
  drop-ins, and requests protocol v3 through APT's command-specific
  `DPkg::Tools::Options::<command>::Version` setting. Installation and enable
  verify the effective merged hook list with `apt-config`; unsafe order rolls
  back the new hook/receipt. Tests also verify a later `#clear
  DPkg::Pre-Install-Pkgs` is detected. This does not prevent a caller from
  providing a different APT config or explicit command-line override.
- **IMPLEMENTED; UNIT TESTED — Incomplete coverage is visible in APT reports.**
  Hook text output prints `Coverage complete: yes/no`; a regression test checks
  incomplete coverage is explicitly rendered and the transaction blocks.
- **IMPLEMENTED — Opt-in guest harness added; BLOCKED BY ENVIRONMENT — real
  transactions.** `tests/integration/test_apt_preinstall_guest.py` defines
  separate clean-approval, finding-cancellation, and finding-approval cases.
  It refuses to run without a disposable guest marker, root-owned runtime,
  private evidence directory, Debian/Ubuntu, ClamAV, and `strace`. It captures
  terminal output, APT status, package-database changes, script markers,
  configuration digest, and exec trace. It was collected and skipped in this
  Kali host run; no real APT transaction or lifecycle guest install was
  performed.
- **UNIT TESTED — Latest offline suite:**
  `.venv/bin/python -B -m pytest -q -p no:cacheprovider` — **453 passed,
  5 skipped in 22.32s**. Three skips are opt-in real APT guest cases; two are
  opt-in live OSV cases.
- **INTEGRATION TESTED — Latest live OSV suite:**
  `/usr/bin/zsh -lc 'LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider'` —
  **455 passed, 3 skipped in 24.98s**. The real APT guest cases remained
  skipped. This is provider integration coverage, not complete OSV advisory
  coverage.
- **UNIT TESTED — Packaging and local checks:** `.venv/bin/python -m build`
  could not run because `build` is absent. A wheel was then built successfully
  with `/usr/bin/python3 -m pip wheel --no-deps --no-build-isolation
  --wheel-dir /tmp/linuxsecmonitor-current-wheel .` (exit 0; SHA-256
  `f8224bf2789e95b12e087b8e1186e83e8261c3ec1d465e75628b572829d645f0`). The
  18-file wheel installed in a clean temporary venv, contained the APT
  lifecycle/hook and malware modules, and its installed CLI `--help` ran.
  Isolated `pip check`, compileall, Ruby YAML parsing, and both staged and
  unstaged `git diff --check` exited 0. GitHub Actions itself was not run.
- **BLOCKED BY ENVIRONMENT — Debian APT E2E.** `/dev/kvm` is absent. Docker's
  socket exists but this user cannot access the daemon. The documented Debian
  12 TCG ClamAV scan timed out at the 120-second bounded deadline; this was
  not re-run because no acceleration/performance condition changed. No host
  APT config or package database was changed.

Current readiness remains **IMPLEMENTED — INTEGRATION TESTS STILL BLOCKED**.
Do not label APT cancellation, APT approval, or privileged lifecycle as
integration-tested until separate guest scenarios produce evidence.

## Follow-up harness review (2026-10-29)

- **IMPLEMENTED; UNIT TESTED — Idempotent managed lifecycle operations.** A
  repeated `install` returns success only for the exact hook and receipt
  already recorded for the requested interpreter; an unowned/malformed
  existing path is still refused. A repeated `enable` similarly succeeds
  only when the recorded hook bytes match. The lifecycle regression suite
  covers repeated install/enable/disable/uninstall, conflict preservation, and
  rollback.
- **IMPLEMENTED — Guest test scenarios expanded; BLOCKED BY ENVIRONMENT —
  guest execution.** The real APT harness now has five separate scenarios:
  clean approval, finding cancellation, finding approval, incomplete scan
  denial, and lifecycle/preservation/recovery. The incomplete fixture is a
  harmless valid `.deb` with an in-package symlink; the hook is expected to
  report incomplete coverage and stop before dpkg. The lifecycle scenario
  checks file owner/modes, conflicting hook preservation, repeated lifecycle
  actions, and the receipt-without-hook recovery state. It does not kill the
  installer mid-write; process-kill recovery remains unverified.
- **INTEGRATION TESTED — Local real scanner fixture, not APT.** The new
  symlink-containing fixture was built with `dpkg-deb` and scanned on Kali
  using real `dpkg-deb` and ClamAV. Observed `status=incomplete`,
  `coverage_complete=false`, and the explicit skipped-link limitation. It was
  never installed. This validates the fixture and scanner status only.
- **UNIT TESTED — Re-run results:** offline suite **453 passed, 7 skipped in
  22.09s**; live OSV-enabled suite **455 passed, 5 skipped in 26.97s**; focused
  APT/lifecycle suite **98 passed, 5 skipped in 0.94s**. The five guest cases
  skipped because this is Kali, not an explicitly marked Debian/Ubuntu guest;
  the two additional offline skips are the disabled live OSV tests.
- **UNIT TESTED — Latest packaging.** Wheel SHA-256
  `29ef62ff0dc95d8a1c404dd051166b87835c7219966cc801e6007077e92d03a6` built
  with system Python/setuptools, installed in a fresh temporary venv, passed
  `pip check`, and its installed `linuxsecmonitor --help` exited 0.
- **BLOCKED BY ENVIRONMENT — VM diagnosis.** QEMU and qemu-img are present,
  but `/dev/kvm` is absent, no VM image was found in `/tmp` or `/var/tmp`,
  Docker socket access is denied, and host `strace`/other VM frontends are
  absent. The previous ClamAV process used roughly 99.5% of one TCG-emulated
  CPU until the 120-second bound. The code has one ClamAV process per package
  scan and no duplicate ClamAV pass; the bottleneck occurs in the scan itself.
  A fresh local real scan of the small symlink fixture took about 10 seconds,
  so ClamAV database/scan CPU work plus TCG emulation remains the plausible
  cause; available evidence does not separate those costs precisely. No
  timeout was increased and no scan was skipped.

Debian APT cancellation, approval, incomplete-scan transaction, lifecycle
guest operations, and process-kill recovery are still **BLOCKED BY
ENVIRONMENT**. The safe next environment is a fresh Debian 12/Ubuntu VM with
working KVM or a physical/hosted hardware-accelerated runner; restore a clean
snapshot before each scenario and use the README harness commands.


Final rerun after the follow-up edits: offline **453 passed, 7 skipped in
17.87s**; live OSV-enabled **455 passed, 5 skipped in 20.97s**. Compilation,
both diff checks, `pip check`, YAML parsing, and read-only host integration
status also passed. The status reports `not_installed`; no lifecycle operation
was performed on Kali.

Pre-push verification rerun (2026-10-29): offline **453 passed, 7 skipped in
17.15s**; live OSV-enabled **455 passed, 5 skipped in 19.76s**. The current
wheel was rebuilt and installed into a fresh temporary venv; CLI help, wheel
contents, isolated `pip check`, compilation, YAML parsing, and staged/unstaged
diff checks passed. GitHub Actions and the five real APT/lifecycle guest tests
remain unverified.

Final verdict: **IMPLEMENTED — INTEGRATION TESTS STILL BLOCKED**. The APT hook
and lifecycle have unit/process-level coverage, but the security-tested MVP
definition is not met until separate real Debian cancellation and approval
transactions complete with package-state and maintainer-script evidence.

## Revalidation on 2026-10-29

- **UNIT TESTED — Offline suite:** `.venv/bin/python -m pytest -q -p
  no:cacheprovider` — **453 passed, 7 skipped in 22.20s**.
- **BLOCKED BY ENVIRONMENT — Real guest scenarios:** the five tests in
  `tests/integration/test_apt_preinstall_guest.py` were collected separately;
  **5 skipped in 0.01s** because no explicit marked supported guest was
  available. Cancellation, both approval cases, incomplete-scan denial, and
  lifecycle recovery therefore have no new guest evidence.
- **UNIT TESTED — Packaging and local checks:** a wheel built from a temporary
  archive of the tracked tree (SHA-256
  `ec630fd1e1acc2b193d85f940b4cb8a7361c93d33d0790b86e69f48370ed7fd4`),
  installed into a fresh virtual environment, and passed CLI `--help` plus
  `pip check`. The project venv also passed `pip check`; compileall, local
  Actions YAML parsing, and staged/unstaged `git diff --check` exited 0.
  Live OSV tests were not run because they make external requests; GitHub
  Actions was not run.
- **BLOCKED BY ENVIRONMENT — Guest and ClamAV:** this host has QEMU and
  `qemu-img`, but no `/dev/kvm` and no Debian/Ubuntu image under `/tmp` or
  `/var/tmp`; Docker daemon access is denied. QEMU TCG is available, and prior
  guest evidence showed ClamAV using roughly one emulated CPU through the
  bounded 120-second timeout. This round did not reproduce the guest scan, so
  the exact share of ClamAV work versus emulation remains unmeasured. No image
  was downloaded and no host APT/package state changed.
- **Repository state:** branch `codex/linuxsecmonitor-completion`, HEAD
  `ac139b0`; the working tree was clean before these documentation updates.
  No commit, push, or release occurred.

Readiness remains **IMPLEMENTED — INTEGRATION TESTS STILL BLOCKED**. Use five
fresh guest snapshots with KVM or equivalent throughput, root access, the
documented test prerequisites, and local evidence storage to complete the
blocked checks.

## Kali primary-target update (2026-10-29)

- Kali is the primary supported platform for host information, installed
  package inventory, `.deb` inspection, ClamAV assessment, diagnostics, and
  the opt-in APT integration. These implementation paths have unit coverage;
  no disposable Kali guest transaction or privileged lifecycle run is yet
  **INTEGRATION TESTED** or **VERIFIED ON TARGET OS**.
- The guest harness now accepts Kali, Debian, and Ubuntu. On Kali it records
  and requires visible `unsupported` vulnerability status before approval.
  This is deliberate: Kali package versions and identifiers have not been
  validated against an authoritative Kali advisory source. Debian/Ubuntu OSV
  results must not be applied to Kali.
- **UNIT TESTED — Current run:** offline suite **453 passed, 7 skipped in
  18.13s**; Kali-related inventory/diagnostics/assessment/CLI tests **227
  passed in 19.75s**; the five real-APT scenarios were collected and **5
  skipped in 0.03s** because no marked guest was available.
- **PACKAGING CHECKED — Current tree:** wheel built and installed into a fresh
  temporary virtual environment; CLI help and `pip check` passed (SHA-256
  `10562038653e7a1fbe2570c8e98151599e3cba2be5963dff2fdcc5a2eaffa37d`).
  Compileall, workflow YAML parsing, and diff checks passed. Live OSV was not
  run; GitHub Actions was not run.
- The host has QEMU and `qemu-img`, but no `/dev/kvm`, local Kali VM image, or
  installed VM frontend. Docker daemon access is denied. QEMU TCG is available;
  prior ClamAV evidence hit the bounded 120-second timeout under TCG. No image
  download, host APT change, or package installation was attempted.
- Minimum remaining setup: provide a disposable Kali guest/snapshot with root
  access, working APT/dpkg, ClamAV and usable signatures, `strace`, Python 3.11+
  with the project and pytest installed in a root-owned runtime, and a private
  evidence directory. Use one clean snapshot per scenario and keep evidence
  local. Hardware acceleration or equivalent ClamAV throughput is needed to
  avoid repeating the known TCG timeout.
- **Final status:** IMPLEMENTED and UNIT TESTED for available local coverage;
  no feature is VERIFIED IN A DISPOSABLE KALI ENVIRONMENT or VERIFIED END TO
  END. Kali vulnerability matching is UNSUPPORTED. Real Kali APT/lifecycle
  verification is BLOCKED by the missing guest and acceleration resources.
