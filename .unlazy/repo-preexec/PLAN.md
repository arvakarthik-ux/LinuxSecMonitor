# Plan: Repository Pre-Execution Security Inspection

Scope: repo-preexec
Depth: tree 3
Mode: orchestrated

## Contract

Decide before fan-out:

- Interfaces: `execution_guard.review_repository_for_execution`, `execution_guard.run_reviewed_command`, repository scanners (`scan_repository`, `scan_repository_malware`, `scan_repository_security`), CLI `--review-repository` and `--safe-run`
- Ownership: `scanner/execution_guard.py`, `scanner/repository_malware_scanner.py`, `scanner/repository_security_scanner.py`, `scanner/repository_scanner.py`, `main.py` (CLI integration), `tests/test_execution_guard.py`, new integration tests
- Dependencies: scanner/malware_scanner.py, scanner/package_scanner.py, scanner/vulnerability_assessment.py, scanner/system_info.py, scanner/apt_hook.py (for CLI integration patterns)
- Host launch mode: sequential fallback (single context sufficient for verification)
- Wave policy: single wave for all leaves (independent verification)
- Toolchain: Python 3.11+, pytest, clamscan (for integration)
- Conventions: fail-closed parsing, no-follow directory descriptors, trusted PATH, atomic writes, terminal escape sequences
- Manual review: disposable guest integration verification (requires physical Kali/Debian/Ubuntu guest)

## Current contract inventory

Contract revision: 1. Before fan-out, reread the original request and current amendments. Record every independently omittable required outcome and every constraint that changes acceptance; do not copy credentials, private text, or unrelated context.

| ID | Required outcome or constraint | Owner | Observing gate or manual review | Disposition | Revision |
|---|---|---|---|---|---|
| C1 | Repository identification resolves paths safely, handles nested repos, avoids trusting repo metadata | leaf-1.1 | G1.1.1, G1.1.2 | ACTIVE | 1 |
| C2 | Repository inspection runs before execution: malware scan, security scan, inventory | leaf-1.2 | G1.2.1, G1.2.2, G1.2.3 | ACTIVE | 1 |
| C3 | Security findings distinguish confirmed detections, high-confidence, heuristic, informational, incomplete | leaf-1.2 | G1.2.4 | ACTIVE | 1 |
| C4 | Approval requires explicit RUN; blocks on timeout, EOF, interrupt, incomplete scans, detections | leaf-1.3 | G1.3.1, G1.3.2, G1.3.3 | ACTIVE | 1 |
| C5 | Fail-closed: blocks when inspection fails, scanners unavailable, incomplete, approval unavailable | leaf-1.3 | G1.3.4 | ACTIVE | 1 |
| C6 | Execution interception: Git clone, shell scripts, build commands, dependency installs | leaf-2.1 | G2.1.1, G2.1.2 | ACTIVE | 1 |
| C7 | Bypass prevention: alternate shells, direct interpreter, PATH manipulation, symlinks, subprocesses | leaf-2.2 | G2.2.1, G2.2.2 | ACTIVE | 1 |
| C8 | CLI --review-repository and --safe-run integrate with existing APT CLI | leaf-3.1 | G3.1.1, G3.1.2 | ACTIVE | 1 |
| C9 | End-to-end: normal repo runs, suspicious repo flagged, approval/cancel works, incomplete blocks | leaf-3.2 | G3.2.1 | ACTIVE | 1 |
| C10 | APT regression: all 5 acceptance scenarios still pass | leaf-3.3 | G3.3.1 (manual) | ACTIVE | 1 |

Use stable ids. On an amendment, increment the revision and reconcile every affected row before dispatch or completion credit. `ACTIVE` is complete only with a current owner and observation. `ABANDONED`, `DEFERRED`, and `OWNER_DECISION` are honest non-completion; only explicit user authority may use `REMOVED_BY_USER`.

## State vocabulary

Leaf state is exactly one of:

- WAITING: at least one id in Needs is not VERIFIED
- READY: dependencies are VERIFIED and ownership can be claimed
- IN-FLIGHT: dispatched, not yet parent-verified
- VERIFIED: parent --reverify passed and manual gates were reviewed
- ABANDONED: a required gate has a visible handoff

Branch state is exactly one of OPEN, VERIFIED, or ABANDONED. Derive root and branch state from their ledgers; do not copy it into the topology tree.

## Tree

Use this tree only for parent-child topology and ledger paths. Use `leaf-` paths for work leaves and `node-` paths for branch integration. Keep leaf operational fields only in the dispatch table below; do not repeat `Owns`, `Needs`, `Tier`, `Planned wave`, or `State` here and do not create a separate schedule.

- 1 Repository Pre-Execution Security Inspection .............. GATES.md
  - 1.1 Repository identification and inspection ........ gates/node-1.1.md
    - 1.1.1 Repository identification and path resolution ...... gates/leaf-1.1.1.md
    - 1.1.2 Repository malware and inventory scanning ...... gates/leaf-1.1.2.md
    - 1.1.3 Repository security static review ...... gates/leaf-1.1.3.md
  - 1.2 Approval workflow and fail-closed behavior ........ gates/node-1.2.md
    - 1.2.1 Explicit approval and cancellation handling ...... gates/leaf-1.2.1.md
    - 1.2.2 Fail-closed on incomplete/unavailable/error ...... gates/leaf-1.2.2.md
  - 1.3 Execution interception and CLI integration ........ gates/node-1.3.md
    - 1.3.1 CLI --review-repository and --safe-run commands ...... gates/leaf-1.3.1.md
    - 1.3.2 End-to-end integration tests ...... gates/leaf-1.3.2.md
    - 1.3.3 APT regression preservation ...... gates/leaf-1.3.3.md

## Leaf dispatch table

This is the single authoritative PLAN table for leaf operation. It is authoritative for `Needs`, `Tier`, `Planned wave`, and `State`; `Owns` remains visible here as the derived planning mirror described below. Keep exactly one row per tree leaf and do not duplicate these fields in the tree or a schedule.

| Leaf | Owns | Needs | Tier | Planned wave | State |
|---|---|---|---|---|---|
| 1.1.1 | scanner/execution_guard.py (review_repository_for_execution), scanner/repository_scanner.py, tests/test_execution_guard.py (identification tests) | - | mechanical | 1 | WAITING |
| 1.1.2 | scanner/repository_malware_scanner.py, tests/test_repository_malware_scanner.py | - | mechanical | 1 | WAITING |
| 1.1.3 | scanner/repository_security_scanner.py, tests/test_repository_security_scanner.py | - | mechanical | 1 | WAITING |
| 1.2.1 | scanner/execution_guard.py (confirm_execution, run_reviewed_command), tests/test_execution_guard.py (approval tests) | 1.1.1, 1.1.2, 1.1.3 | mechanical | 2 | WAITING |
| 1.2.2 | scanner/execution_guard.py (run_reviewed_command fail-closed), tests/test_execution_guard.py (fail-closed tests) | 1.1.1, 1.1.2, 1.1.3 | mechanical | 2 | WAITING |
| 1.3.1 | main.py (CLI --review-repository, --safe-run), tests/test_main.py (CLI tests) | 1.2.1, 1.2.2 | mechanical | 3 | WAITING |
| 1.3.2 | tests/integration/test_repo_preexec.py, tests/test_execution_guard.py (integration tests) | 1.3.1 | judgment | 3 | WAITING |
| 1.3.3 | tests/integration/test_apt_preinstall_guest.py, README.md | - | judgment | 3 | WAITING |

`Owns` is a derived planning mirror of the complete glob set in the leaf ledger. The ledger's `OWNS:` header is the command-time authority read by `--claim`. Normalize both into sets and require equality before marking the row `READY` and again before each claim. On disagreement, fail closed, correct and log the plan or ledger, and recheck; never guess ownership. A successful claim does not prove the mirror agreed with the ledger.

`Tier` is planner metadata for execution leaves. Use `judgment` when a leaf's own artifact needs design or review, and `mechanical` only when its pattern and gates are fixed. Map a tier through documented host-specific model or reasoning controls only when the host exposes them. Otherwise retain the tier as a briefing and review requirement without claiming a model choice. Driver and branch duties, including planning, dispatch, parent verification, integration, and final audit, remain judgment responsibilities outside this leaf field. Tier never weakens a leaf's gates, parent re-verification, or integration standard.

`Planned wave` is the earliest intended launch group under the current contract. Use a positive integer, put every dependency in an earlier planned wave, and let the wave policy cap concurrency. It is a plan, not a barrier: rolling dispatch may start a later planned wave as soon as that row's dependencies are verified, without waiting for unrelated work. Actual starts belong in `dispatch.json` and `status.log`; do not add a second schedule to this file.

Change `Needs`, `Owns`, `Tier`, or `Planned wave` only through a recorded plan amendment before that row launches; do not erase a dependency when it becomes satisfied. Update `State` in this table as work progresses. After parent re-verification and manual review, mark a leaf `VERIFIED`, release that exact leaf lease, and record the release. Do not promote a dependent until that exact release is recorded. For an abandoned leaf, record the handoff and confirm its worker has settled before releasing only that leaf; never call it parent-verified. Release the whole scope only after every leaf is settled and final scope verification has run. If final verification reports a handoff, record it before release and never describe the scope as complete.

## Status log

Append events to `.unlazy/repo-preexec/status.log`; do not copy the event history into this file:

```text
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope repo-preexec --log "leaf-1.1.1 dispatched"
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope repo-preexec --log "leaf-1.1.1 verified"
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope repo-preexec --log "leaf-1.1.1 lease released"
```

Record contract amendments, plan changes, dispatch, parent verification, abandonment, branch integration, and lease release. Apply logged plan amendments and live State updates only in the dispatch table; keep the log append-only. Before root completion, reread the current request and review every current inventory row against its owner and observing gate or manual review.