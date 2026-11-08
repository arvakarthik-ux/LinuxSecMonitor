# LinuxSecMonitor — Project AGENTS.md

## Project Architecture

LinuxSecMonitor is a unified Linux security tool for Debian-family distributions (primary: Kali Linux; secondary: Debian, Ubuntu). It operates in multiple modes:

**Host Assessment (read-only):**
- `main.py` → `scanner/system_info.py` → `scanner/package_scanner.py` → `scanner/vulnerability_assessment.py`
- Collects OS/distribution/kernel/CPU/Python/hostname
- Inventories installed packages via `dpkg-query`
- Queries Ubuntu/Debian OSV records for vulnerability assessment (Kali explicitly unsupported)
- Caches validated full Debian OSV advisories on disk (24h default)
- Outputs human-readable text or structured JSON

**Downloaded Package Scanning (opt-in, pre-install):**
- `--scan-deb`: Scans a local `.deb` without installing (malware + vulnerability)
- `--preinstall-deb`: Scans `.deb`, requires exact `INSTALL` confirmation, then runs `apt-get install --no-remove` on private snapshot
- Creates size-limited private snapshot; scans snapshot; passes same snapshot to APT
- Static review of maintainer scripts (preinst/postinst/prerm/postrm/config) for heuristic patterns
- Requires Linux, `dpkg-deb`, `clamscan`, ClamAV signatures, `apt-get`, privileges for installation

**Repository Scanning (opt-in, manual):**
- `--scan-repo`: Inventory + ClamAV malware scan + bounded static security review
- `--review-repository`: Same scans, reports findings without gating execution
- `--safe-run`: Scans repository, requires exact `RUN` confirmation before one explicit command
- ClamAV scans eligible files copied to private temp storage
- Static checks use no-follow POSIX directory descriptors
- Neither stage executes scripts, hooks, builds, package managers, Git commands
- Heuristic findings are review leads, not verdicts
- Exit code 0 requires complete inventory, ClamAV `no_detection`, static review `completed` with no findings

**APT Integration (opt-in, experimental):**
- `--apt-preinstall-hook`: Implements APT Pre-Install-Pkgs protocol v3
- Runs as root via APT hook, drops to `_apt` user before scanning archives
- Validates every archive path (absolute, no traversal, `.deb` suffix, no symlinks, root-owned, not user-writable)
- Scans every archive with ClamAV + static maintainer-script review
- Aggregates vulnerability assessment across all transaction packages
- Requires exact `INSTALL` approval on controlling terminal (opened after privilege drop)
- Fail-closed: blocks on incomplete coverage, error, unavailable, detection, mismatch, missing terminal
- `--apt-integration {status,install,enable,disable,uninstall}`: Lifecycle management with atomic writes, trusted runtime validation, hook order verification

**Wrapper Framework (automatic repository protection):**
- `src/wrapper/core.py`: `CommandWrapper` — classifies commands, detects repository context, coordinates scanning/approval/execution
- `src/wrapper/commands.py`: `CommandClassifier` — tier patterns (TIER_1_DANGEROUS, TIER_2_WARN, TIER_3_PASSTHROUGH, BYPASS)
- `src/wrapper/detection.py`: `RepositoryDetector` — finds Git repository root from CWD
- `src/wrapper/scanners.py`: `ScannerOrchestrator` — parallel bounded scans with snapshot isolation
- `src/wrapper/approval.py`: `ApprovalManager` — content-and-command-bound explicit approval with TTL
- `src/wrapper/cache.py`: `ScanCache` — content-hash-keyed cache for complete assessments
- `src/wrapper/path.py`: `PathManager` — trusted executable resolution without trusting PATH
- `src/wrapper/report.py`: `build_unified_report` — unified report from scan results
- `src/wrapper/install.py`: Shell integration helpers for wrapper deployment

## Core Objectives

1. **Host security assessment** — read-only package inventory and conservative vulnerability matching
2. **Downloaded Debian package scanning** — scan `.deb` before installation with explicit approval
3. **Repository scanning** — inventory, malware scan, static review before scripts/builds/dependency installation
4. **APT integration** — examine transaction packages/dependencies before installation scripts execute
5. **Detailed terminal security reports** — human-readable and JSON output with advisory context
6. **Explicit user approval** — exact token confirmation (`INSTALL`/`RUN`) with timeout, EOF, interrupt handling
7. **Safe cancellation** — blocks package installation scripts from executing on cancel
8. **Conservative vulnerability detection** — no false safety claims; `no_known_match` ≠ safe

## Non-Goals

- Complete vulnerability coverage or package safety guarantees
- Sandbox or enforcement boundary (wrappers are user-mediated, not automatic interception)
- Real-time kernel-level execution monitoring
- Windows package inventory (Windows only for development/mocked tests)
- Automatic ClamAV signature updates
- Resolution of all Git hook configurations (custom `core.hooksPath`, includes, global config not followed)

## Security Invariants

**Fail-Closed Behavior:**
- All parsers reject malformed/oversized input with errors (never treat as empty/clean)
- Incomplete scanner coverage blocks approval prompts
- Missing terminal, timeout, EOF, interrupt → cancellation (never approval)
- Archive identity mismatch with APT transaction → blocks clean result
- Changed archive during/after scan → blocks transaction
- Unavailable scanners, errors, incomplete results → block (no bypass)

**Privilege Boundaries:**
- APT hook runs as root from APT, drops to `_apt` user via `setuid`/`setgid` before scanning
- Terminal opened *after* privilege drop (never held with root privileges)
- Private snapshots: `0o700` temp dir, `0o600` package file, only `_apt` group traverse/read
- `sudo` used only *after* user confirmation for installation
- Trusted PATH (`/usr/sbin:/usr/bin:/sbin:/bin`) used for scanner subprocesses; caller PATH restored

**TOCTOU Protections:**
- Archive validation: `O_NOFOLLOW` open → `fstat` → identity capture → re-verify identity after scan
- Snapshot creation: bounded copy with size limit, identity verification before/after
- Repository snapshot: private copy, content hash before/after, detects concurrent modification
- Hard-link atomic writes for lifecycle configs (never replace racing file)

**Approval & Cancellation Correctness:**
- Exact token match (`INSTALL`/`RUN`); lowercase, spaces, empty, EOF → cancel
- Approval bound to repository content hash, argv, working directory, config hash, scanner versions, malware DB version
- TTL enforcement (default 300s); consumed approvals cannot be reused
- JSON mode: human preview to stderr, command args omitted from JSON report

**APT Transaction Safety:**
- Hook validates it is first effective `DPkg::Pre-Install-Pkgs` command
- All archives in transaction must be scannable; archive-less maintainer-script actions (`**CONFIGURE**`, `**REMOVE**`) block unless matching archive exists
- Vulnerability assessment aggregated before approval prompt
- `apt-get --no-remove` used; APT's own confirmation remains enabled

## Development Commands

```bash
# Install in virtual environment
python3 -m venv .venv
.venv/bin/python -m pip install .

# Install with test dependencies
.venv/bin/python -m pip install '.[test]'

# Run scanner
python main.py                    # Human-readable report
python main.py --json             # JSON to stdout
python main.py --json -o scan.json
python main.py --diagnostics --json -o scan.json

# Repository scanning
python main.py --scan-repo /path/to/repo
python main.py --scan-repo /path/to/repo --json -o repo-report.json
python main.py --scan-repo /path/to/repo --include-generated

# Safe run (review + explicit approval)
python main.py --safe-run /path/to/repo -- python -m pip install .
python main.py --safe-run /path/to/repo --json -o review.json -- make build

# Package scanning
python main.py --scan-deb ./package.deb
python main.py --preinstall-deb ./package.deb
python main.py --preinstall-deb ./package.deb --json -o preinstall-report.json

# APT integration (requires root, disposable guest recommended)
python main.py --apt-integration status
sudo python main.py --apt-integration install
sudo python main.py --apt-integration enable
sudo python main.py --apt-integration disable
sudo python main.py --apt-integration uninstall

# Diagnostics (read-only)
python main.py --doctor
python main.py --doctor --json

# Run tests
python -m pytest tests/ -v
python -m pytest tests/test_apt_hook.py tests/test_apt_lifecycle.py tests/test_apt_hook_cli.py tests/test_main.py -k "apt" -q
python -m pytest tests/test_execution_guard.py -v
python -m pytest tests/test_wrapper_core.py tests/test_wrapper_commands.py -v
python -m pytest tests/integration/ -v -k "not live_osv and not live_debian_osv and not real_apt"
```

## Testing Strategy

**Unit Tests (mocked, deterministic):**
- `tests/test_apt_hook.py` — protocol parsing, validation, scanning, approval, privilege dropping
- `tests/test_apt_lifecycle.py` — install/enable/disable/uninstall, trusted runtime, hook order, atomic writes
- `tests/test_apt_hook_cli.py` — CLI dispatch for APT hook and integration commands
- `tests/test_execution_guard.py` — repository review, approval, fail-closed behavior
- `tests/test_main.py` — CLI formatting, JSON output, mode conflicts, approval/cancellation
- `tests/test_malware_scanner.py` — ClamAV integration, static maintainer-script review
- `tests/test_package_scanner.py` — dpkg-query parsing, distribution support
- `tests/test_repository_*.py` — inventory, malware scan, static security review
- `tests/test_vulnerability_assessment.py` — OSV querying, Debian/Ubuntu matching, Kali unsupported
- `tests/test_wrapper_*.py` — classifier, detector, cache, approval, scanners, path, core, install

**Integration Tests (require specific environments):**
- `tests/integration/test_repo_preexec.py` — end-to-end repository review and command execution
- `tests/integration/test_apt_preinstall_guest.py` — disposable guest APT hook verification (manual)
- `tests/integration/test_debian_osv_live.py` — live Debian OSV API (marked `live_debian_osv`)
- `tests/integration/test_ubuntu_osv_live.py` — live Ubuntu OSV API (marked `live_osv`)

**Test Markers (pytest.ini):**
- `live_osv` — optional integration tests contacting real OSV API
- `live_debian_osv` — optional integration tests contacting Debian OSV data
- `real_apt` — opt-in privileged APT tests; only run in disposable Debian/Ubuntu guest

**Run Focused Tests Before Regression:**
```bash
# APT hook/lifecycle focused
python -m pytest tests/test_apt_hook.py tests/test_apt_lifecycle.py tests/test_apt_hook_cli.py -v

# Repository execution guard focused
python -m pytest tests/test_execution_guard.py tests/integration/test_repo_preexec.py -v

# Wrapper framework focused
python -m pytest tests/test_wrapper_*.py -v

# Full regression (excluding live/privileged)
python -m pytest tests/ -v -k "not live_osv and not live_debian_osv and not real_apt"
```

## Unlazy Execution Rules

This project uses the global Unlazy skill for task execution discipline. Key rules:

1. **Plan before implementing** — write acceptance gates before execution
2. **Dependency-aware execution** — respect `Needs` in PLAN.md dispatch tables
3. **Verify before completing** — run focused tests, then relevant regression tests
4. **Evidence-based completion** — never fabricate test results; provide exact file paths and evidence
5. **Incremental implementation** — minimal changes, reuse existing architecture
6. **Preserve existing Unlazy skill** — do not replace, delete, or relocate `.unlazy/` or global skill

**Current Unlazy Scopes (in `.unlazy/`):**
- `apt-hook-complete/` — APT hook/lifecycle implementation (mostly VERIFIED, guest verification ABANDONED)
- `repo-preexec/` — Repository pre-execution inspection (WAITING/READY)
- `auto-repo-protect/` — Automatic repository protection architecture design (READY/WAITING)
- `policy-engine/` — Policy engine design (no PLAN.md yet)
- `priority-3/` — Priority 3 implementation plan (gates only)

**Plan Amendment Protocol:**
- Update `PLAN.md` dispatch table `State` as work progresses
- Record contract amendments before dispatch
- Append events to scope's `status.log`
- Release leaf lease only after parent re-verification and manual gate review
- Root completion requires every leaf settled, final scope verification, no handoffs

## Acceptance and Completion Requirements

**For any code change:**
1. All existing tests pass (focused → regression)
2. New functionality has corresponding tests
3. Security invariants maintained (fail-closed, privilege boundaries, TOCTOU, approval correctness)
4. No credentials, tokens, or private information exposed
5. Minimal, maintainable changes; reuse existing patterns

**For Unlazy scope completion:**
1. Every leaf in dispatch table `VERIFIED` (or honestly `ABANDONED`/`DEFERRED`)
2. Parent node gates pass (`--reverify` from exact ledger)
3. Cross-branch behavior verified (tests pass)
4. Sibling regression checked (no regressions in related tests)
5. Ownership leases released after parent verification
6. Manual outcomes reviewed at branch level
7. Current request reread, every contract row reconciled

**For project configuration changes:**
1. Global skills remain available and unmodified
2. Project instructions discoverable at standard paths
3. No conflicting instructions between global and project config
4. Existing Git changes preserved

---

**Global skills (do not duplicate):** coding-workflow, debugging, security-testing, linux-security, python-development, code-review, security-reviewer, code-reviewer, debugger, find-skills, customize-opencode, unlazy