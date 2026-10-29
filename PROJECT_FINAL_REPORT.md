# LinuxSecMonitor Development and Validation Report

Date: 2026-10-28

## Repository and release state

- Repository: /home/kali/LinuxSecMonitor; origin points to https://github.com/arvakarthik-ux/LinuxSecMonitor.git.
- Current branch: codex/linuxsecmonitor-completion, based on the existing codex-skip-entry-reporting tip 2c1f341.
- Local compatibility environment: Python 3.14.7; Python 3.10–3.13 interpreters were unavailable. `pip check` reported no broken requirements. The CI workflow targets 3.11–3.14 but has not run on GitHub. Python 3.10 reached end of life on 2026-10-01 ([final Python 3.10 security release](https://www.python.org/downloads/release/python-31022/)); the project now requires Python 3.11+.
- Existing branches and the missing-directory registered worktree were preserved. The original codex-package-script-review branch remains at 52133ba; local main was not changed.
- Changes are uncommitted and local. Nothing was pushed or merged.
- kali-host-report.json and ignored scan.json were not read for content, changed, staged, committed, or overwritten.
- No persistent APT configuration or system service was changed. No package was installed. No actual package maintainer script was executed.

## Implemented in this work

- Added --safe-run REPOSITORY -- COMMAND... as a user-mediated repository review wrapper.
- Added read-only --doctor checks for supported host, Python, tool availability/version summaries, and effective APT hook counts. Hook command contents are omitted.
- The wrapper runs repository inventory, ClamAV snapshot assessment, and static security review before asking for exact RUN approval. Incomplete coverage and ClamAV detections block execution. No controlling terminal means cancellation.
- Commands are passed as an argv list with shell=False. Command arguments are omitted from the report to avoid recording command-line secrets.
- Text/JSON outcomes identify review state, command status, command return code, and limitations. JSON output paths inside the scanned repository are rejected.
- Added unit tests for approval/cancellation marker behavior, fail-closed assessment errors, malware detections, CLI parsing/output behavior, and command-argument omission.
- Added diagnostics tests for unsupported distributions, missing tools, timeouts, and avoiding disclosure of APT configuration values.
- After APT code review, changed the hook to reject removal actions and configure actions without a matching transaction archive. A configure action with matching package/version/architecture/Multi-Arch is covered by that archive scan. Added regressions for configure-only, remove-only, orphan configure, and matching configure records.
- Changed the APT hook to require exact interactive `INSTALL` approval for every fully scanned transaction, including clean transactions. Incomplete/error outcomes remain fail-closed and cannot be approved. Added tests for clean approval and cancellation when no terminal is available.
- Added process-level CLI tests for malformed protocol, missing archives, configure-only transactions, and remove-only transactions. These run the actual hook CLI process without invoking APT or dpkg.
- Bounded OSV query response bodies to 16 MiB, full advisory bodies to 8 MiB, and JSON nesting to 128 levels. Oversized/deep input returns an assessment error. Added offline tests for Ubuntu and Debian query responses, Debian advisory hydration, and excessive nesting.
- ClamAV's stale-signature warning on a successful package scan now makes coverage incomplete rather than allowing `no_detection`; actual detections are retained with incomplete coverage. Tests cover both outcomes. The host's installed daily database reported build time 26 Oct 2026 on the audit date 28 Oct 2026.
- Bounded `dpkg-deb --field` metadata output to 64 KiB, added a watchdog using the existing 60-second metadata command limit, and reject invalid UTF-8. Oversized-output and timeout tests fail closed without treating incomplete metadata as a package identity.
- Added `pyproject.toml` with the `linuxsecmonitor` console entry point and optional test extra. Installed it in a temporary virtual environment without dependencies, then verified the installed command's `--help` output. This does not add system hooks or persistent configuration.
- Documented the local virtualenv installation/removal path and verified install, command execution, uninstall, and reinstall in a disposable temporary virtualenv. This does not implement a persistent APT-hook lifecycle.
- Added an offline GitHub Actions workflow for Python 3.11 through 3.14. It installs project test requirements, compiles source/tests, and runs the deterministic suite. Python 3.10 was removed from the matrix after its end-of-life date was verified. The workflow was not run on GitHub.
- Pinned the CI actions to verified immutable upstream commits for checkout v7.0.1 and setup-python v7.1.0. The workflow itself remains unexecuted on GitHub.
- Raised the declared and diagnosed minimum Python version from 3.10 to 3.11 after Python 3.10 reached end of life. Updated documentation and CI matrix; Ubuntu 22.04's system interpreter now requires a separately maintained Python 3.11+ to run this tool.
- Added PROJECT_AUDIT.md with the initial code-vs-test audit, repository history, environment, risks, and prioritized work.

Modified files:

- README.md
- main.py
- scanner/apt_hook.py
- scanner/malware_scanner.py
- scanner/vulnerability_assessment.py
- tests/test_apt_hook.py
- tests/test_debian_assessment.py
- tests/test_main.py
- tests/test_malware_scanner.py
- tests/test_vulnerability_assessment.py
- tests/test_debian_assessment.py

Added files:

- .github/workflows/tests.yml
- PROJECT_AUDIT.md
- PROJECT_FINAL_REPORT.md
- scanner/diagnostics.py
- scanner/execution_guard.py
- pyproject.toml
- tests/test_apt_hook_cli.py
- tests/test_diagnostics.py
- tests/test_execution_guard.py

## Tests and commands actually run

Baseline on the development branch before implementation:

    .venv/bin/python -B -m pytest -q -p no:cacheprovider
    384 passed, 2 skipped, 0 failed in 16.82s

The two skips were opt-in live Debian and Ubuntu OSV tests. They were not enabled.

After implementation, the focused suite first reported 93 passed and 2 failed because the fake terminal test double overwrote its input when receiving the prompt and a CLI error test expected an exception although the CLI correctly returned exit code 2. After a JSON output routing change, another focused run reported 95 passed and 1 failed because a CLI test double did not accept the new json_output keyword. Both test-harness issues were corrected; no production behavior was weakened. Latest focused rerun:

    .venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_execution_guard.py tests/test_main.py
    96 passed, 0 failed in 17.02s

Final deterministic suite:

    .venv/bin/python -B -m pytest -q -p no:cacheprovider
    419 passed, 2 skipped, 0 failed in 13.99s

After the APT hook was changed to require explicit approval even for a complete clean scan, the focused hook suite and full suite were rerun:

    .venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_apt_hook.py tests/test_apt_hook_cli.py
    78 passed in 0.78s

    .venv/bin/python -B -m pytest -q -p no:cacheprovider
    420 passed, 2 skipped in 17.11s

The first focused run after that behavior change had 2 failures and 76 passes because two tests expected the previous clean auto-continue behavior. The tests now assert no-terminal cancellation and exact `INSTALL` approval. The full rerun passed. The two skipped tests remain the opt-in live OSV integrations.

After bounding metadata subprocess output, the package scanner suite and full suite were rerun:

    .venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_malware_scanner.py
    29 passed in 0.18s

    .venv/bin/python -B -m pytest -q -p no:cacheprovider
    422 passed, 2 skipped, 0 failed in 21.18s

The focused tests cover a forced metadata timeout, output above the 64 KiB limit, and invalid UTF-8. The two skips remain the opt-in live OSV integrations.

The live OSV tests were run separately. Without network approval, both failed at DNS resolution with `Temporary failure in name resolution`. With network access approved:

    LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider tests/integration
    2 passed in 6.84s

The complete suite was then run with both live flags and network access approved:

    LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider
    424 passed in 22.03s

An unapproved-network full-suite attempt reported 2 failed and 422 passed, with both failures caused by the same DNS restriction. The successful live fixtures cover one Debian 12 OpenSSH advisory and one Ubuntu 22.04 bash advisory; they are not evidence of comprehensive vulnerability database coverage.

After raising the Python minimum to 3.11, the compatibility tests and offline suite were rerun:

    .venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_diagnostics.py
    6 passed

    .venv/bin/python -B -m pytest -q -p no:cacheprovider
    424 passed, 2 skipped

A temporary virtualenv with system site packages passed `pip install --dry-run --no-build-isolation --no-deps .`; a wheel built from a clean temporary source copy contained `Requires-Python: >=3.11`; Ruby's YAML parser accepted the pinned workflow. `actionlint` was unavailable. Two packaging attempts in the project venv failed due unavailable network build dependencies and then missing setuptools. Direct system pip was refused by PEP 668, with no override attempted. No system installation was performed.

After the compatibility update, the complete suite was rerun with both live OSV tests enabled and approved network access:

    LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider
    426 passed in 39.54s

After that suite run, a documentation-only lifecycle check installed the project into a disposable virtualenv, ran `linuxsecmonitor --help`, uninstalled it and verified the command/package were gone, then reinstalled and ran help again. Install, uninstall, and reinstall succeeded; the temporary environment and generated build metadata were removed. No system APT configuration was changed.

Focused APT hook suite after fail-closed action handling:

    .venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_apt_hook_cli.py tests/test_apt_hook.py
    77 passed in 0.71s

The first process-test run reported 1 failed and 3 passed because its assertion expected identical capitalization in malformed-input and normal block messages. The assertion was corrected to check the fail-closed wording case-insensitively; production code was not changed for this test failure.

The initial bounded-response focused run reported 1 failed and 112 passed because a deep-JSON test expected Python's standard decoder to reject nesting that it accepts. A pre-decode nesting limit was added, and the focused vulnerability suites then passed 113 tests.

Focused package scanner suite after stale ClamAV database handling:

    .venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_malware_scanner.py
    27 passed in 0.13s

The package installation check ran in a new temporary virtual environment:

    package_env="$(mktemp -d /tmp/linuxsecmonitor-package-test.XXXXXX)"
    python3 -m venv --system-site-packages "$package_env"
    "$package_env/bin/python" -m pip install --no-build-isolation --no-deps .
    "$package_env/bin/linuxsecmonitor" --help

The wheel built and installed successfully; the installed command displayed help and exited 0. The generated `build/` and `linuxsecmonitor.egg-info/` directories were absent before the check and removed afterward.

Compilation check (bytecode cache redirected to a temporary directory so existing project caches were not overwritten):

    python -m compileall -q main.py scanner tests
    exit code: 0

git diff --check exited 0. python main.py --help displayed the new --safe-run command and preserved existing CLI modes. A pattern-based secret scan printed no matching changed file paths; the existing host report was excluded and not inspected.

The focused diagnostics and CLI run reported 91 passed after one initial test failure exposed an empty-command-map fallback bug. The implementation now distinguishes an explicit empty mapping from omitted overrides.

## Runtime evidence

### Synthetic .deb inspection

A harmless local .deb was built using dpkg-deb --build. Its synthetic postinst would create a unique marker and an inert, disabled cron filename if executed. The package was scanned, never installed.

Observed result:

    dpkg-deb build exit: 0
    LinuxSecMonitor scan exit: 0
    status: no_detection
    coverage_complete: true
    maintainer-script review lead: startup-persistence-write
    marker_created: false

This demonstrates inspection of that synthetic archive and that this scan run did not execute its maintainer script. It is not a general proof that all archive contents are safe.

After the stale-signature-warning change, a second clean synthetic `.deb` (no maintainer scripts) was built in a private temporary directory and scanned through `main.py --scan-deb ... --json`. Observed: build exit 0, scan exit 0, `no_detection`, complete coverage, and the real ClamAV backend. The package was not installed. This confirms the currently fresh local signatures do not trigger the new incomplete-coverage path.

An additional unprivileged runtime harness built a synthetic package with a marker-writing `postinst`, then invoked `main.py --apt-preinstall-hook` as a subprocess with a valid protocol-v3 stream pointing to that archive. Observed: `dpkg-deb` build exit 0 (with benign rootless-build/control-file warnings); hook accepted v3; scanner returned complete `no_detection`; the heuristic review lead appeared; missing terminal approval caused an explicit blocked message and hook exit 1; marker remained absent. The package was never installed. Four further subprocess cases (malformed v2 header, missing archive, configure-only action, and remove-only action) each returned exit 1 with a blocked message. This exercises the hook executable and scanner path, but bypasses APT itself and does not prove dpkg is never invoked by a real transaction.

After the metadata output bound, another harmless synthetic package was built (`dpkg-deb --build` exit 0) and scanned through `main.py --scan-deb ... --json`. Observed: scan exit 0, `no_detection`, complete coverage, and actual `dpkg-deb + ClamAV clamscan` backend. The package was not installed. This confirms the bounded metadata reader works with a real package control record on this host.

ClamAV reported 1.4.6/28165 and successfully scanned the synthetic package and a harmless one-file repository fixture. A no_detection result is limited to scanned data and available signatures.

The actual --doctor --json command reported Kali as supported, Python 3.14 supported, package inventory and .deb prerequisites available, APT hook prerequisites available, one configured pre-install hook, and zero pre-invoke hooks. The report contained no hook command text. These checks do not verify v3 protocol compatibility, signature freshness, hook order, or cancellation timing.

The README temporary APT configuration procedure was extended with a synthetic postinst marker cancellation test. It requires no dpkg package-processing exec during cancellation, no package status entry, and absent marker files. The procedure was not executed because no disposable Debian VM was available; it is not integration-test evidence.

The procedure also documents a separate approval run from a clean snapshot: exact `INSTALL` confirmation, APT success, marker creation, configured package status, and a trace showing the test postinst execution, followed by immediate snapshot rollback. This approval procedure was not executed.

### Repository command wrapper

A real CLI run scanned a harmless temporary repository. Inventory, ClamAV, and static review all reported complete; ClamAV reported no_detection; static review reported no findings. Without a usable controlling terminal, the command was cancelled with exit code 3 and the command marker was absent. A second real CLI JSON-mode run produced parseable JSON on stdout, sent the human preview to stderr, cancelled with command_status=cancelled, and left its marker absent.

The module-level approval test supplied a fake terminal returning exact RUN, then launched a harmless real Python child process with shell=False; it created the expected marker. The cancellation test supplied CANCEL; its child process did not run and its marker stayed absent.

Two attempts to test actual CLI approval through the available PTY ended with CLI cancellation because /dev/tty was unavailable to the child process. They are failed/inconclusive approval integration attempts, not successful approval validation. Approval through the actual CLI in a controlling-terminal session remains unverified.

### APT integration

- Source review found that the previous implementation returned success when a transaction had no archive actions, including configure/remove records, and ignored those records when archives were also present. This could allow maintainer-script-capable operations without an archive scan. The hook now fails closed for removals and unmatched configure actions. This behavior is covered by unit tests only.
- Debian Bookworm's official [`apt.conf(5)`](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) documents that Pre-Install-Pkgs hooks run before dpkg, hook failures abort APT, and protocol actions include archive unpack, configure, and remove. This corroborates the protocol design from documentation; it does not substitute for observing the target APT binary in a guest.
- Debian's [`dpkg-preconfigure(8)`](https://manpages.debian.org/bookworm/debconf/dpkg-preconfigure.8.en.html) documents that apt-mode preconfiguration runs package `config` scripts before installation. Therefore ordering LinuxSecMonitor before this hook is necessary for the documented test path; a preceding or differently configured hook remains a bypass risk.
- APT cancellation prevention: not verified.
- APT approval/continuation: not verified.
- The README procedure defines evidence for controlled cancellation and approval, but neither transaction was executed.
- Direct hook-process cancellation without a controlling terminal was observed, and the synthetic script marker remained absent. This is not evidence of APT transaction cancellation because APT did not invoke the hook.
- After requiring approval on clean scans, a new script-free synthetic `.deb` was built (exit 0) and scanned by a real `--apt-preinstall-hook` subprocess using v3 input. The real ClamAV/dpkg-deb path returned `no_detection`; with no controlling terminal, the hook exited 1 and reported missing explicit approval. `dpkg-query` confirmed the package was not installed. This validates the hook subprocess behavior only, not APT cancellation or maintainer-script suppression.
- No APT transaction, package installation, or maintainer-script execution was attempted.
- This host is Kali Rolling 2026.3 with APT 3.3.3+kali1, while the existing documented install test targets a disposable Debian 12 environment. Docker is installed but the daemon socket is inaccessible; `/dev/kvm` and a provisioned Debian guest image are unavailable.
- QEMU 11.1 is installed, but `/dev/kvm` and a guest image were unavailable. An approved official cloud-image download attempt yielded an incomplete 196,608-byte QCOW file rejected by `qemu-img check`; fetching Debian's SHA512SUMS failed with DNS resolution error 6. The incomplete image was not booted or used.
- Exact VM provisioning commands attempted:

      curl -fL --connect-timeout 10 --max-time 120 --output /tmp/linuxsecmonitor-debian12-cloud.qcow2 https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2
      qemu-img info /tmp/linuxsecmonitor-debian12-cloud.qcow2
      qemu-img check /tmp/linuxsecmonitor-debian12-cloud.qcow2
      curl -fL --connect-timeout 10 --max-time 30 https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS
      curl -fL --connect-timeout 10 --max-time 30 https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS -o /tmp/linuxsecmonitor-debian12-SHA512SUMS

  The QCOW file was only 196,608 bytes and failed reference checks as truncated; both checksum fetch attempts failed with `curl: (6) Could not resolve host: cloud.debian.org`. The partial image was deleted from `/tmp` after recording the failure.
- Existing unit tests validate APT v3 parser and mocked decision behavior only. They do not prove that a real cancellation stops before dpkg-preconfigure, dpkg, or maintainer scripts.

## Repository protection results

--scan-repo remains advisory and does not prevent later execution. --safe-run now provides one explicit reviewed command path, but callers can bypass it by running commands directly, and it is not a sandbox. A concurrent writer can change repository contents after scanning. No Git, build, package-manager, or normal shell operations are automatically intercepted.

## Setup, uninstall, and persistent protection

The local Python package lifecycle is documented and was tested in a disposable virtualenv: install, command invocation, uninstall, and reinstall succeeded. `--doctor` provides read-only diagnostics. There is still no installer or managed persistent APT-hook setup, enable/disable, status, uninstall, or configuration-restoration implementation. No system configuration was changed. APT-hook lifecycle still needs design and disposable-environment validation.

## Remaining security gaps and limitations

1. Validate APT protocol behavior on a disposable target and prove cancellation with a synthetic maintainer-script marker, no dpkg package-processing exec, nonzero APT status, and package not configured. Test approval separately.
2. The hook now blocks `**REMOVE**` and archive-less `**CONFIGURE**` actions because their scripts cannot be covered by transaction archives. A configure action with matching archive identity is accepted only alongside scanning that archive. Validate this policy in real APT transactions in the disposable VM.
3. Validate APT ordering, dependency archives, upgrades, noninteractive behavior, error paths, and alternate package front ends. The existing hook is experimental and not a universal barrier.
4. Exercise actual CLI approval with a real controlling terminal; current full CLI attempt cancelled safely due unavailable /dev/tty.
5. Add system APT-hook setup/status/disable/uninstall and restoration only after controlled APT validation; keep the tested local virtualenv lifecycle distinct and do not enable persistent hooks automatically.
6. Repository static heuristics and ClamAV/OSV data are incomplete by design. Kali vulnerability assessment remains unsupported.
7. CI configuration was added but not executed remotely, and Python versions other than 3.14.7 were not tested locally.

## Reproduction commands

Offline tests:

    .venv/bin/python -B -m pytest -q -p no:cacheprovider

Focused wrapper tests:

    .venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_execution_guard.py tests/test_main.py

Compile check:

    python -m compileall -q main.py scanner tests

APT validation must be run only in a disposable Debian/Kali VM or snapshot using the documented temporary-config procedure and marker-script evidence. The procedure includes requiring no dpkg package-processing invocation during cancellation. Do not treat unit tests or the written procedure as APT integration proof.

The unprivileged direct-hook runtime harness can be repeated by creating a synthetic `.deb` with `dpkg-deb --build`, forming a v3 stream with `APT::Architecture=amd64` and an archive action line, and running `python3 -B main.py --apt-preinstall-hook` with the stream on stdin. Use a postinst that only writes a marker if executed; verify a review lead, blocked/no-terminal result, and absent marker. This is a hook-process check only.

## Release assessment

The deterministic suite passes and the new user-mediated wrapper has both unit-level decision evidence and a real clean-scan/cancellation run. Local Python virtualenv installation and uninstall/reinstall were also exercised. LinuxSecMonitor is not production-ready as automatic APT or general repository pre-execution protection. Real APT cancellation and approval remain unverified, repository commands can bypass the wrapper, and system APT-hook lifecycle commands are absent. No GitHub push was made; explicit approval is still required before any push.

## APT validation follow-up (2026-10-28)

This follow-up records a focused review of the current APT hook and an attempted preparation for its disposable-VM validation. It does not change the earlier integration status: no real APT transaction was run, so cancellation and approval remain unverified.

- The focused command `.venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_apt_hook.py tests/test_apt_hook_cli.py` completed with **78 passed in 0.86s**. These tests do not invoke APT or dpkg.
- Source review of Debian APT 3.3.3's `pkgDPkgPM::Go()` confirms upstream ordering: `DPkg::Pre-Invoke` runs first, then `DPkg::Pre-Install-Pkgs`; the latter's failure aborts before the following dpkg invocation. The official [`apt.conf(5)` hook documentation](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) describes Pre-Install-Pkgs as running before dpkg, supports protocol v3 action records, and specifies that a failed hook aborts APT. The corresponding [`APT 3.3.3 source`](https://sources.debian.org/src/apt/3.3.3/apt-pkg/deb/dpkgpm.cc) corroborates the order. This is source/documentation evidence, not a runtime observation of a Debian guest.
- APT hook-list ordering remains security-critical. Debian's [`dpkg-preconfigure(8)` documentation](https://manpages.debian.org/bookworm/debconf/dpkg-preconfigure.8.en.html) says apt-mode runs package `config` scripts. The documented temporary config clears and rebuilds only the temporary `DPkg::Pre-Install-Pkgs` list with LinuxSecMonitor before `apt-listchanges` and `dpkg-preconfigure`; other earlier hooks or a different effective order are outside that procedure's evidence.
- The hook covers APT transactions that invoke this configured hook and provide supported protocol-v3 input. It does not intercept direct `dpkg` or other non-APT installation entry points. Hook configuration alone is not proof that every package-management path is covered.
- Environment checks found `/usr/bin/qemu-system-x86_64`, `/usr/bin/qemu-img`, `/usr/bin/guestfish`, and `/usr/bin/virt-customize`, but no `/dev/kvm`, no Debian guest image, no `cloud-localds` or ISO-building utility, no `strace`, and no `virt-install`. `docker info` exited 1. `getent hosts cloud.debian.org` failed, so a guest image could not be acquired in this run. The installed APT identifies itself as `apt 3.3.3 (amd64)`.
- No installation was attempted on this Kali host. The host's persistent APT configuration was not modified, no package scripts were run, and no project report or source file was changed during the validation run itself.
- Required next evidence remains the README's controlled VM procedure: one harmless allowed install; a synthetic marker package cancellation with nonzero APT exit, absent marker, no dpkg package-processing execution, and no configured package state; then a separate approved run with marker present, package configured, and trace evidence of its `postinst`. The test also needs to record effective hook ordering and assess multi-package/dependency and upgrade transactions. Until those checks run in an isolated guest, do not claim APT cancellation prevents maintainer-script execution.

## Development continuation: package vulnerability reports

The project checklist is now maintained in `PROJECT_COMPLETION_CHECKLIST.md`.
Current status remains **PARTIALLY READY**: offline implementation work can
continue, but APT cancellation/approval and supported Debian/Ubuntu runtime
behavior remain unverified, so the project is not ready for broader deployment.

This continuation connected the existing distribution-aware OSV assessor to
manual `.deb` workflows:

- `dpkg-deb --field` now reads the package `Source` identity. If `Source` is
  omitted, Debian policy permits using the binary name/version as source
  identity; an invalid explicit field remains missing and produces
  `requires_review` instead of substituting an ambiguous binary version.
- `--scan-deb` and `--preinstall-deb` reports now include a separate
  `vulnerability_assessment` based on the current host distribution and
  release. Kali remains explicitly unsupported. OSV failures are represented
  as errors; raw unexpected exception messages are not exposed.
- `--scan-deb` returns zero only for complete malware coverage with no
  detection and a conclusive vulnerability status (`no_known_match`, `fixed`,
  `not_affected`, or `mixed`). Unsupported, review-required, error, and
  vulnerable results return nonzero. The manual pre-install workflow shows
  OSV results before exact `INSTALL` approval; its existing malware coverage
  gate remains unchanged.
- The APT hook now aggregates package source identities and runs one
  transaction-level OSV assessment. Errors and `requires_review` fail closed;
  unsupported distributions are reported and still require the exact user
  approval token. A vulnerability result is presented for decision and does
  not independently prohibit approval. Unit coverage was added, but this code
  change does not establish real APT transaction timing or cancellation.

Files changed in this continuation: `main.py`, `scanner/malware_scanner.py`,
`tests/test_main.py`, `tests/test_malware_scanner.py`, `README.md`,
`PROJECT_AUDIT.md`, `PROJECT_COMPLETION_CHECKLIST.md`, and this report.

Validation for this continuation:

- Focused `.deb` and CLI suite: **123 passed**. A later `tests/test_main.py`
  run after an additional report assertion: **91 passed**. The first focused
  run had two test failures due to missing required `scanner` values in new
  test fixtures; the fixtures were corrected, then the focused run passed.
- Full offline command `.venv/bin/python -B -m pytest -q -p no:cacheprovider`:
  **431 passed, 2 skipped in 21.08s**. The skipped tests are the opt-in live
  Debian/Ubuntu OSV cases.
- Full live-enabled command
  `LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider`:
  **433 passed in 18.83s**, including both live OSV tests.
- `PYTHONPYCACHEPREFIX=/tmp/linuxsecmonitor-completion-pycache python -m compileall -q main.py scanner tests` exited 0. Both `git diff --check` and `git diff --cached --check` exited 0.
- A real harmless synthetic `.deb` was built with `dpkg-deb` (exit 0) and
  scanned through the CLI with actual `dpkg-deb` and ClamAV. On Kali, the
  malware result was `no_detection` with complete coverage, vulnerability
  result `unsupported`, and CLI exit 1. A second synthetic archive containing
  a harmless marker-writing `postinst` also returned `no_detection` and
  `unsupported`; its marker was absent after scanning. Neither package was
  installed.
- A further real synthetic `.deb` explicitly declared
  `Source: linuxsecmonitor-source-fixture-src (0.0.1-2)`. `dpkg-deb --build`
  exited 0; the CLI reported `source_name=linuxsecmonitor-source-fixture-src`,
  `source_version=0.0.1-2`, malware `no_detection`, OSV `unsupported` on Kali,
  and exit 1. The package was not installed.
- Debian source identity to OSV behavior is covered by unit tests using a
  mocked assessment provider. No Debian/Ubuntu guest was available, so the
  combined `.deb` CLI behavior on those distributions remains unverified.

The earlier malware-only `--scan-deb` runtime entries in this report describe
the implementation before this continuation. Their historical exit code 0
does not describe the current combined exit policy.

## APT transaction vulnerability assessment follow-up (2026-10-29)

The APT hook now gathers inspected archive package/source identities and calls
the existing distribution-aware OSV assessor once for the transaction. It
displays bounded status, package, and advisory details before requesting the
exact `INSTALL` token. Assessment `error` and `requires_review` states block
without prompting. Unsupported distributions are reported and can continue
only with exact interactive approval. Vulnerability findings are shown to the
user; exact approval currently permits continuation. This is an implementation
and unit-test result, not proof of behavior in an APT-managed transaction.

Validation run on 2026-10-29:

- `.venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_apt_hook.py tests/test_apt_hook_cli.py` — **81 passed** after correcting an assertion for the additional transaction status output.
- `.venv/bin/python -B -m pytest -q -p no:cacheprovider` — **434 passed, 2 skipped in 20.78s**. The skips are opt-in live OSV tests.
- `LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider` — **436 passed in 27.15s** with network access.
- `PYTHONPYCACHEPREFIX=/tmp/linuxsecmonitor-completion-pycache python -m compileall -q main.py scanner tests` — exit 0.
- `git diff --check` and `git diff --cached --check` — exit 0.

The APT assessment tests mock the advisory provider and do not call APT/dpkg.
No disposable Debian environment is available in this run; no real APT
cancellation or approval transaction was executed. Therefore there is no
marker, package-status, or execution-trace evidence that cancellation
prevents maintainer scripts, nor approval evidence. Overall status remains
**PARTIALLY READY** for controlled integration work and **NOT READY** for
general deployment. No commit, push, or persistent host APT configuration
change was made. The working tree still contains existing staged and
unstaged project work and the untracked user report `kali-host-report.json`;
that report was not read or modified.

## Fresh-session continuation report (2026-10-29)

### Verdict

**Not ready for controlled real-world APT testing.** The unit and live OSV
checks pass, but this session could not find or boot an isolated Debian guest.
The actual cancellation and approval transactions remain unverified. The APT
integration is experimental and must not be described as a guaranteed security
boundary.

### Validation performed

- Offline suite: `.venv/bin/python -B -m pytest -q -p no:cacheprovider` —
  **434 passed, 2 skipped in 39.65s**. The two skips are opt-in live OSV tests.
- Live-enabled suite:
  `LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider` —
  **436 passed in 42.22s**, including both live OSV integration tests.
- Focused APT hook/CLI, diagnostics, malware, execution-guard, Debian
  assessment, vulnerability assessment, and main CLI suites — **335 passed in
  22.40s**.
- CLI `--help`, read-only `--doctor --json`, `pip check`, Python compilation,
  `git diff --check`, and `git diff --cached --check` exited 0. The current
  venv does not have LinuxSecMonitor installed; pip emitted a cache ownership
  warning. The repository defines no lint or formatter configuration.
- Doctor reports Kali 2026.3, Python 3.14, APT 3.3.3, ClamAV 1.4.6/database
  28165, one Pre-Install-Pkgs entry, and zero Pre-Invoke entries. Those host
  counts do not establish hook order or actual dpkg timing.

### APT integration transaction status

No guest, overlay, Debian image, seed image, SSH key, QEMU process, or
transaction log was present under the project, `/tmp`, or `/var/tmp`. There is
no `/dev/kvm`; DNS lookup for `cloud.debian.org` failed. The prior harmless
EICAR `.deb` in `/home/kali/linuxsecmonitor-test.npOPWP` was preserved and not
installed. No new VM was created or booted. Consequently:

- **Cancellation:** not run. No APT exit status, scan prompt, marker state,
  package database state, or dpkg/preconfiguration execution trace exists.
- **Approval:** not run. No successful transaction, exact approval prompt,
  installed-package status, or maintainer-script trace exists.
- **Effective order:** the host doctor sees one Pre-Install-Pkgs and zero
  Pre-Invoke hooks, but this is Kali host information, not Debian guest order.
  The temporary Debian configuration procedure remains unexecuted.

The README's current package-status query single-quotes `${db:Status-Abbrev}`.
No saved evidence was found for the earlier `db: unbound variable`, SCP
destination error, SSH startup delay, or slow `.deb` scan, so their original
causes cannot be determined. These historical problems are not claimed fixed.

### Preservation and system changes

All existing staged and unstaged changes were preserved. `kali-host-report.json`
was not opened or modified. This session made no code changes, installed or
removed no packages, changed no host APT configuration, and made no persistent
system change. It appended this verification evidence to the audit, checklist,
and report. No commit, push, or release was made.

The next blocking step is to provide or restore a disposable Debian VM/snapshot
with a known baseline, isolated temporary APT configuration, and sufficient
trace tooling. Run the marker cancellation test on one fresh overlay and the
approval test on a separate fresh overlay, and record both package state and
maintainer-script execution evidence before changing the readiness verdict.

## Debian VM preparation continuation (2026-10-29)

This continuation supersedes the preceding statement that no VM image was
available, but it does **not** change the APT integration verdict.

### Exact verification rerun

- `.venv/bin/python -B -m pytest -q -p no:cacheprovider` — **434 passed, 2
  skipped in 23.68s**.
- `LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider` — **436 passed in 30.32s**.
- `.venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_apt_hook.py tests/test_apt_hook_cli.py tests/test_diagnostics.py tests/test_malware_scanner.py tests/test_execution_guard.py tests/test_debian_assessment.py tests/test_vulnerability_assessment.py tests/test_main.py` — **335 passed in 23.50s**.
- `PYTHONPYCACHEPREFIX=/tmp/linuxsecmonitor-revalidation-pycache .venv/bin/python -m compileall -q main.py scanner tests`, `git diff --check`, `git diff --cached --check`, `.venv/bin/python -m pip check`, `main.py --help`, and read-only `main.py --doctor --json` all exited 0. Pip printed a cache-directory ownership warning. No lint/formatter configuration exists.
- A package build with `.venv/bin/python -m pip wheel --no-deps --no-build-isolation ...` failed because that venv lacks setuptools (`BackendUnavailable: Cannot import 'setuptools.build_meta'`). Rebuilding the clean source copy with system Python 3.14.7 and setuptools 78.1.1 succeeded. Wheel metadata reported `Requires-Python: >=3.11` and console entry point `linuxsecmonitor = main:main`; installing into a temporary venv and running `linuxsecmonitor --help` succeeded. Ruby parsed `.github/workflows/tests.yml`. GitHub Actions itself was not run.

### Debian environment and real scan result

The official Debian 12 generic cloud image was downloaded into `/tmp`. Its
SHA-512 matched Debian's published manifest and `qemu-img check` found no
errors. The first download timed out after 120 seconds at 73%; resuming it
completed successfully. A temporary NoCloud seed and SSH key were created
under `/tmp/linuxsecmonitor-debian-validation`. QEMU user networking forwarded
SSH only to `127.0.0.1:22222`. The booted guest identified as Debian 12
Bookworm with Python 3.11.2. APT updated its indexes and installed ClamAV,
freshclam, strace, and apt-listchanges inside the disposable setup overlay
only. The ClamAV service populated `daily.cvd`; version output was
`ClamAV 1.4.6/28168/Thu Oct 29 06:24:16 2026`.

The guest's existing Pre-Install-Pkgs list was apt-listchanges followed by
dpkg-preconfigure, and no pre-invoke hook was listed. The effective test-only
configuration showed the LinuxSecMonitor command before both. This is
configuration evidence only; no APT transaction was executed.

A newly built 1 KiB synthetic marker package had harmless `preinst` and
`postinst` scripts that write marker files; the postinst also writes a hidden
cron file containing only `true` to trigger the static review heuristic. The
prior EICAR test package was not used. The package was not installed and its
scripts were never executed.

The real command
`python3 -B /opt/linuxsecmonitor-apt-validation/main.py --scan-deb /opt/linuxsecmonitor-apt-validation/linuxsecmonitor-apt-hook-marker_0.0.1_all.deb --json --output /home/debian/marker-scan.json`
returned `scan_exit=1`. Its report showed malware status `error`, error
`ClamAV timed out while scanning package contents.`, `coverage_complete=false`,
the expected `startup-persistence-write` review finding, and OSV
`no_known_match`. Guest process inspection showed ClamAV using approximately
99.5% of one emulated CPU at 42 seconds; the configured 120-second scanner
timeout then stopped the scan. This is an incomplete real scan, not a clean
result. Because the hook uses the same scanner path, it is expected to hit the
timeout before prompting; no APT transaction was run to confirm that.

A separate scan-probe overlay using `-accel tcg,thread=multi -smp 2` panicked
with Debian's `IO-APIC + timer doesn't work` kernel error. That QEMU process
was stopped. Both overlays passed `qemu-img check`; no QEMU process remains.
No fresh cancellation or approval overlay was created. No APT transaction
ran, so cancellation and approval exit codes, user prompts, package state,
unrelated package state, maintainer-script trace, and hook execution order
remain unverified. Do not substitute a fake scanner or reduced database to
force a prompt.

The SSH client initially rejected the host's
`/etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf` permissions; using `ssh -F
/dev/null` avoided that host-side client configuration. The guest took about
a minute to reach sshd, reproducing startup delay. SCP with the explicit
destination `debian@127.0.0.1:/home/debian/linuxsecmonitor-source/` worked; the
earlier destination error has no saved log and was not reproduced. The current
README's dpkg status format uses single quotes around `${db:Status-Abbrev}`;
the earlier unbound-variable error has no saved command and was not reproduced.
The slow `.deb` scan was reproduced as the TCG ClamAV timeout and remains an
environment blocker, not a fixed product defect.

### Status and next step

**Not ready for controlled real-world APT testing.** The live OSV and unit
tests pass, but neither real APT transaction ran. No host APT configuration,
host package state, or persistent host setting was changed. Guest-only
preparation packages and test configuration are in the disposable setup
overlay. The next concrete step is to run the same prepared baseline under
working hardware acceleration or equivalent ClamAV performance, then create
separate clean cancellation and approval overlays. Capture the real prompts,
APT statuses, full package-state diffs, dpkg-preconfigure/dpkg `strace`, marker
files, and rollback evidence before claiming APT validation.

## Final implementation continuation (2026-10-29)

### A. Final verdict

**IMPLEMENTED — INTEGRATION TESTS STILL BLOCKED.** Automated behavior,
packaging, and a local real `.deb` scan are verified. The required real Debian
APT cancellation and approval transactions remain unverified because the
available QEMU TCG guest timed out in ClamAV and no `/dev/kvm` is available.

### B. Task status

| Task | Status | Evidence and limitation |
| --- | --- | --- |
| 1. ClamAV timeout | PARTIAL | ClamAV timeout now reports `incomplete` with incomplete coverage; deadline remains 120 seconds. A real host scan of a harmless marker `.deb` completed fully. Debian 12 TCG still timed out; no performance workaround was applied. |
| 2. APT cancellation | BLOCKED | No APT transaction reached a prompt. No cancellation, package-state diff, or maintainer-script trace exists. |
| 3. APT approval | BLOCKED | No separate clean approval overlay or APT approval transaction was run. No install marker evidence exists. |
| 4. Security/fail-closed review | PARTIAL | Existing protocol, archive identity, timeout, scanner-status and exact approval checks retained; lifecycle and timeout regressions added. Real APT ordering/race behavior remains unknown. |
| 5. Lifecycle | PARTIAL | Status/install/enable/disable/uninstall CLI and ownership-aware temp-root implementation added; APT parser validation and runtime trust checks included. Unit tests pass; actual persistent installation and process-kill recovery were not exercised. |
| 6. Tests/CI/docs/package | PARTIAL | 444 offline passes/2 skips; 446 live OSV passes; final wheel built/installed in temporary venv; dependency, compile, diff, YAML checks pass; README, audit and checklist updated. GitHub CI itself was not run. |

### C. Test evidence

- **Unit and mocked/process-level:** Focused command covering lifecycle, APT
  hook/CLI, malware/package scanning, and main CLI:
  `.venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_apt_lifecycle.py tests/test_apt_hook.py tests/test_apt_hook_cli.py tests/test_malware_scanner.py tests/test_package_scanner.py tests/test_main.py` — **229 passed in 24.01s**.
- **Full offline:** `.venv/bin/python -B -m pytest -q -p no:cacheprovider` —
  **444 passed, 2 skipped in 17.58s**.
- **Live OSV:** `LINUXSECMONITOR_LIVE_OSV=1 LINUXSECMONITOR_LIVE_DEBIAN_OSV=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider` — **446 passed in 22.89s**.
- **Real local `.deb` scan (not APT):** built a fresh Debian package with a
  harmless `postinst` marker script using `dpkg-deb --build`, then called
  `scanner.malware_scanner.scan_deb`. Build exited 0; scan returned
  `no_detection`, `coverage_complete=true`; marker was absent; `dpkg-query`
  showed the package absent before and after. Fixture lived in a temporary
  directory and was removed. This confirms no package installation or script
  execution during the scan on the host, not on Debian guest APT.
- **Real VM APT:** Not run. Existing Debian 12 TCG scan evidence is summarized
  above and in `PROJECT_AUDIT.md`; there is no retained raw transaction log or
  `strace` trace because no APT transaction ran.
- **Packaging/static:** final wheel SHA-256
  `5d4bafd1019c86a610debcdc781be5e99b6c1e8d1a34017dc5cb49119793db67`, built
  from a clean copy under `/tmp/linuxsecmonitor-final-wheel.E8kYkW`, installed
  in its temporary venv, and its installed CLI help ran. `pip check` passed
  both project and isolated environments. `compileall`, staged/unstaged
  `git diff --check`, and Ruby YAML parsing exited 0. GitHub Actions not run.

Raw guest output/logs were not present in the checkout. The saved evidence is
the narrative record in `PROJECT_AUDIT.md` and `PROJECT_COMPLETION_CHECKLIST.md`.

### D. Security limitations

- APT integration only applies when its v3 hook is enabled and invoked in the
  expected order. Direct `dpkg`, other managers, hook overrides/removal,
  earlier hooks, and commands outside APT remain bypasses.
- Real APT ordering, cancellation/approval behavior, and package-script timing
  remain unverified. A privileged user can replace or disable the program or
  APT configuration.
- Repository scanning is advisory; `--safe-run` is a user-mediated wrapper,
  not interception or a sandbox.
- OSV and ClamAV have data, mapping, signature, and coverage limits. Neither
  no-match nor no-detection proves safety.

### E. Repository state

- Branch: `codex/linuxsecmonitor-completion`; HEAD was
  `2c1f341b75d2a3c4e61b699c1974c3ea9157f24f` at inspection.
- Existing staged and unstaged work was preserved. The pre-existing untracked
  `kali-host-report.json` was not opened, modified, or staged. This continuation
  adds lifecycle source/tests and updates project documentation; no files were
  staged by these commands.
- No persistent host APT configuration changed and no package was installed on
  the main host. The synthetic `.deb` was only scanned.
- No commit, push, or release occurred.

### F. Remaining work

1. Obtain a disposable Debian guest with hardware acceleration or equivalent
   ClamAV throughput, then execute cancellation and approval in separate fresh
   overlays and record prompts, status diffs, markers, and `strace` evidence.
2. Exercise actual lifecycle install/disable/enable/uninstall and interrupted
   recovery inside that guest; inspect ownership, permissions, and hook order.
3. Run GitHub Actions and validate supported Debian/Ubuntu runtime behavior.

### Latest verification addendum (2026-10-29)

Lifecycle follow-up uses the `00linuxsecmonitor` drop-in, selects APT protocol
v3 with the command-specific `DPkg::Tools::Options::<command>::Version`
setting, and checks effective merged hook order before install/enable returns
success. Unsafe effective order triggers rollback. Temporary-config tests
confirm order ahead of ordinary hooks and detection of a later `#clear`. This
is not proof against explicit caller overrides.

The opt-in real guest harness now has separate safe-approval,
finding-cancellation, and finding-approval scenarios. It refuses non-Debian/
Ubuntu or unmarked/non-root environments and records APT output, a JSON
summary, package-database differences, maintainer-script markers, and an
`strace` exec trace. All three are **unverified**: this session ran on Kali and
left them skipped. No disposable guest transaction or privileged lifecycle
operation ran. The prior Debian 12 TCG ClamAV timeout remains the outstanding
performance blocker; this environment has no `/dev/kvm`, and its Docker socket
is inaccessible.

Latest actual test results:

- Offline suite: **453 passed, 5 skipped in 22.32s**.
- Live OSV-enabled suite: **455 passed, 3 skipped in 24.98s**. The three
  skipped cases are the real guest APT scenarios.
- Compileall, `pip check`, Ruby parse of the Actions YAML, and staged/unstaged
  `git diff --check`: exit 0.
- `.venv/bin/python -m build --wheel` could not run because the `build`
  package is absent. System Python successfully built the wheel with
  `pip wheel --no-deps --no-build-isolation`; its SHA-256 is
  `f8224bf2789e95b12e087b8e1186e83e8261c3ec1d465e75628b572829d645f0`.
  The 18-file wheel installed into a fresh temporary venv, included lifecycle,
  APT hook and malware modules, passed isolated `pip check`, and its installed
  CLI `--help` exited 0.
- GitHub Actions was not triggered. Only the YAML parser check ran locally.

No host APT configuration or package state changed; no package was installed
on the main host. No commit, push, or release occurred. The verdict remains
**IMPLEMENTED — INTEGRATION TESTS STILL BLOCKED**.

### Follow-up review (2026-10-29)

The real-guest harness was expanded to five opt-in scenarios: safe approval,
finding cancellation, finding approval, incomplete-coverage denial, and
lifecycle install/disable/enable/uninstall/recovery with unrelated-config
preservation. The incomplete scenario builds a valid package with an in-package
symlink, which the scanner must report as incomplete before dpkg. The
lifecycle scenario tests conflict refusal, root ownership/modes, repeated
operations, and the recoverable receipt-without-hook state. It does not inject
a process kill between lifecycle writes. None of the guest cases ran here.

The new incomplete fixture was built and scanned on Kali with actual `dpkg-deb`
and ClamAV: **incomplete**, `coverage_complete=false`, explicit symlink
limitation. It was not installed. This does not verify APT behavior.

ClamAV path inspection found one `clamscan` invocation per package scan; no
duplicate ClamAV pass or repeated daemon startup occurs for a single package.
The previous Debian guest's approximately 99.5% CPU use through its 120-second
timeout indicates CPU-bound scanning under TCG. A fresh local small-package
scan took about 10 seconds, but the available evidence cannot precisely divide
cost between ClamAV database/scan work and emulation. The timeout remains
bounded and unchanged. QEMU is installed, but `/dev/kvm` and guest images are
absent; Docker daemon access and host `strace` are unavailable.

Updated test results: offline **453 passed, 7 skipped in 22.09s**; live
OSV-enabled **455 passed, 5 skipped in 26.97s**; focused APT/lifecycle
**98 passed, 5 skipped in 0.94s**. The current wheel built, installed in a
fresh venv, passed `pip check`, and ran the installed CLI help; SHA-256
`29ef62ff0dc95d8a1c404dd051166b87835c7219966cc801e6007077e92d03a6`.
GitHub Actions and all real Debian/Ubuntu transactions remain unverified.

Final rerun after these changes: offline **453 passed, 7 skipped in 17.87s**;
live OSV-enabled **455 passed, 5 skipped in 20.97s**. The five skips in the
live run are all opt-in guest APT/lifecycle scenarios; the offline run also
skips the two opt-in OSV tests. `compileall`, `pip check`, Ruby workflow YAML
parsing, staged/unstaged `git diff --check`, and read-only
`--apt-integration status --json` passed. Host status was `not_installed`.
No host APT configuration or package state changed.

Immediately before preparing this commit, the offline suite again passed
**453 passed, 7 skipped in 17.15s**, and the live OSV-enabled suite passed
**455 passed, 5 skipped in 19.76s**. A new wheel built, installed in a fresh
temporary venv, passed wheel-content inspection and `pip check`, and its
installed CLI help exited successfully. GitHub Actions and real Debian/Ubuntu
APT/lifecycle transactions remain unverified.
