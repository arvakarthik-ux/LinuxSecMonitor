# LinuxSecMonitor Workflow Skill

This skill provides project-specific workflow guidance for LinuxSecMonitor development.

## Active Unlazy Priority Tracking

Use the Unlazy framework to track and execute work according to the current priorities:

```bash
# Check current status of all scopes
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope apt-hook-complete --reverify
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope repo-preexec --reverify
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope auto-repo-protect --reverify
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope policy-engine --reverify
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope priority-3 --reverify
```

**Current Scope States:**
- `apt-hook-complete` — VERIFIED (guest verification ABANDONED, all unit tests pass)
- `repo-preexec` — WAITING/READY (leaves 1.1.1-1.1.3 READY, 1.2.1-1.2.2 WAITING on 1.1.x)
- `auto-repo-protect` — READY/WAITING (design phase; leaves 1.1.x, 1.3.x READY)
- `policy-engine` — No PLAN.md yet
- `priority-3` — Gates only

## Dependency-Aware Execution

When implementing work, respect the dependency graph in each scope's PLAN.md:

1. **repo-preexec**: Leaves 1.1.1, 1.1.2, 1.1.3 must complete before 1.2.1, 1.2.2
2. **auto-repo-protect**: 1.2.2 needs 1.2.1; 1.4.1 needs all 1.1.x + 1.2.2 + 1.3.x; 1.5.1 needs 1.4.1
3. Never launch a leaf whose `Needs` are not VERIFIED

## Existing Functionality Reuse

Before adding new code, check if it exists in:

**Scanner modules** (`scanner/`):
- `system_info.py` — OS/distribution/kernel/CPU collection
- `package_scanner.py` — dpkg-query inventory with source metadata
- `vulnerability_assessment.py` — OSV querying for Debian/Ubuntu (Kali unsupported)
- `malware_scanner.py` — ClamAV + static maintainer-script review for .deb
- `repository_scanner.py` — file inventory with manifest detection
- `repository_malware_scanner.py` — ClamAV scan on private snapshot
- `repository_security_scanner.py` — bounded static heuristics
- `execution_guard.py` — review + approval + run (used by --safe-run)
- `apt_hook.py` — APT Pre-Install-Pkgs v3 protocol, scanning, approval
- `apt_lifecycle.py` — hook install/enable/disable/uninstall with atomic writes

**Wrapper modules** (`src/wrapper/`):
- `core.py` — CommandWrapper: classification, detection, coordination
- `commands.py` — CommandClassifier with tier patterns
- `detection.py` — RepositoryDetector (Git root from CWD)
- `scanners.py` — ScannerOrchestrator (parallel bounded scans)
- `approval.py` — ApprovalManager (content+command-bound, TTL)
- `cache.py` — ScanCache (content-hash-keyed)
- `path.py` — PathManager (trusted executable resolution)
- `report.py` — build_unified_report
- `install.py` — shell integration helpers

**CLI** (`main.py`):
- All modes (--scan-deb, --preinstall-deb, --scan-repo, --review-repository, --safe-run, --apt-preinstall-hook, --apt-integration, --doctor)
- JSON/text rendering, diagnostics, approval prompts

## Sprint Continuation

When continuing work on an Unlazy scope:

1. Read the scope's PLAN.md and GATES.md
2. Check the dispatch table for READY leaves (dependencies VERIFIED)
3. Read the leaf's gate file for acceptance criteria
4. Implement only what the leaf owns
5. Run the leaf's gate checks
6. Run focused tests for the affected area
7. Run regression tests (exclude live/privileged markers)
8. Update PLAN.md State to VERIFIED after parent re-verification

## Progress Verification

After any change, verify:

```bash
# Focused tests for area changed
python -m pytest tests/test_apt_hook.py tests/test_apt_lifecycle.py tests/test_apt_hook_cli.py -v  # APT
python -m pytest tests/test_execution_guard.py tests/integration/test_repo_preexec.py -v  # Repo exec
python -m pytest tests/test_wrapper_*.py -v  # Wrapper

# Full regression
python -m pytest tests/ -v -k "not live_osv and not live_debian_osv and not real_apt"
```

Never claim completion without test evidence.