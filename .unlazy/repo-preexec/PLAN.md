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
- Manual review: disposable Kali Linux 2026.3 guest integration verification

## Current contract inventory

Contract revision: 10. Before fan-out, reread the original request and current amendments. Record every independently omittable required outcome and every constraint that changes acceptance; do not copy credentials, private text, or unrelated context.

| ID | Required outcome or constraint | Owner | Observing gate or manual review | Disposition | Revision |
|---|---|---|---|---|---|
| C1 | Repository identification resolves paths safely, handles nested repos, avoids trusting repo metadata | leaf-1.1 | G1.1.1, G1.1.2 | ACTIVE | 1 |
| C2 | Repository inspection runs before execution: malware scan, security scan, inventory | leaf-1.2 | G1.2.1, G1.2.2, G1.2.3 | ACTIVE | 1 |
| C3 | Security findings distinguish confirmed detections, high-confidence, heuristic, informational, incomplete | leaf-1.2 | G1.2.4 | ACTIVE | 1 |
| C4 | Approval requires explicit RUN; blocks on timeout, EOF, interrupt, incomplete scans, detections | leaf-1.3 | G1.3.1, G1.3.2, G1.3.3 | ACTIVE | 1 |
| C5 | Fail-closed: blocks when inspection fails, scanners unavailable, incomplete, approval unavailable | leaf-1.3 | G1.3.4 | ACTIVE | 1 |
| C6 | Execution interception: Git clone, shell scripts, build commands, dependency installs | leaf-2.1 | G2.1.1, G2.1.2 | ACTIVE | 1 |
| C7 | Bypass resistance for commands mediated by installed wrapper shims: alternate shells and interpreters, managed PATH resolution, managed-shim aliases, and subprocess PATH mediation | leaf-2.2 | G2.2.1, G2.2.2 | ACTIVE | 6 |
| C7S | Supporting remediation: wrapper-launched child PATH prepends the managed-wrapper directory without caller-controlled PATH | leaf-2.3 | G2.3.1 (supports C7 G2.2.2) | ACTIVE (supporting C7) | 7 |
| C8 | CLI --review-repository and --safe-run integrate with existing APT CLI | leaf-3.1 | G3.1.1, G3.1.2 | ACTIVE | 1 |
| C9 | End-to-end: normal repo runs, suspicious repo flagged, approval/cancel works, incomplete blocks | leaf-3.2 | G3.2.1 | ACTIVE | 1 |
| C10 | APT regression: all 5 acceptance scenarios still pass | leaf-3.3 | G3.3.1-G3.3.5; G3.3.6 (manual review) | ACTIVE | 3 |

Use stable ids. On an amendment, increment the revision and reconcile every affected row before dispatch or completion credit. `ACTIVE` is complete only with a current owner and observation. `ABANDONED`, `DEFERRED`, and `OWNER_DECISION` are honest non-completion; only explicit user authority may use `REMOVED_BY_USER`.

**Revision 2 amendment (2026-11-13):** The user explicitly authorized reopening the existing `repo-preexec` P2 scope for fresh verification using an accelerated disposable Debian guest, under the existing acceptance criteria. The scope is REOPENED FOR FRESH VERIFICATION and remains incomplete. The original abandonment/handoff statements are preserved verbatim as labeled `HISTORY` in the affected ledgers and are non-operative only for this authorized verification cycle. Prior failed, timed-out, and abandoned evidence remains historical and does not count as a pass. Recovery requires an accelerated disposable Debian guest. No gate ID, acceptance criterion, command, expected result, or dependency changes; this amendment supplies no gate evidence and claims no gate met.

**Revision 3 amendment (2026-11-13):** The user explicitly authorized Kali Linux as the sole required guest OS for the five existing APT scenarios because Kali is the product's primary target. Use the documented Kali Rolling 2026.3 target; record the actual guest `/etc/os-release` in fresh evidence. Debian validation is not required by this scope, and this amendment makes no claim of Debian support. Keep G1 finding-cancel, G2 incomplete-block, G3 finding-approve, G4 safe-approve, and G5 lifecycle and all their security assertions, prompts, transaction/package-state/marker/`strace` evidence, isolation, reset, and dependency requirements unchanged. On Kali, vulnerability assessment must remain explicitly `unsupported`, never treated as clean or simulated. The original ABANDON/handoff statements remain verbatim history and are non-operative for this authorized revision 3 Kali verification cycle; prior failed, timed-out, and abandoned evidence remains historical and does not count as a pass. The scope is reopened but incomplete; all five gates remain unmet. No gate evidence is supplied and no gate is marked met.

HISTORY: Verbatim Debian emulation blocker from PROJECT_COMPLETION_CHECKLIST.md:
> QEMU software emulation
> without KVM booted the setup guest but was too slow for ClamAV. A separate
> probe using `-accel tcg,thread=multi -smp 2` panicked in the Debian kernel
> with `IO-APIC + timer doesn't work`. That probe process was stopped. Both
> guest overlays passed `qemu-img check` afterward and no QEMU process remains.
> The probe does not establish product behavior.

HISTORY: Verbatim Debian real-scan result from PROJECT_FINAL_REPORT.md:
> The real command
> `python3 -B /opt/linuxsecmonitor-apt-validation/main.py --scan-deb /opt/linuxsecmonitor-apt-validation/linuxsecmonitor-apt-hook-marker_0.0.1_all.deb --json --output /home/debian/marker-scan.json`
> returned `scan_exit=1`. Its report showed malware status `error`, error
> `ClamAV timed out while scanning package contents.`, `coverage_complete=false`,
> the expected `startup-persistence-write` review finding, and OSV
> `no_known_match`. Guest process inspection showed ClamAV using approximately
> 99.5% of one emulated CPU at 42 seconds; the configured 120-second scanner
> timeout then stopped the scan. This is an incomplete real scan, not a clean
> result. Because the hook uses the same scanner path, it is expected to hit the
> timeout before prompting; no APT transaction was run to confirm that.

HISTORY: Verbatim Debian TCG scan-probe result from PROJECT_FINAL_REPORT.md:
> A separate scan-probe overlay using `-accel tcg,thread=multi -smp 2` panicked
> with Debian's `IO-APIC + timer doesn't work` kernel error. That QEMU process
> was stopped. Both overlays passed `qemu-img check`; no QEMU process remains.
> No fresh cancellation or approval overlay was created. No APT transaction
> ran, so cancellation and approval exit codes, user prompts, package state,
> unrelated package state, maintainer-script trace, and hook execution order
> remain unverified. Do not substitute a fake scanner or reduced database to
> force a prompt.

**Revision 4 amendment (2026-11-14):** Preserve the original C6-C10 owner IDs (`leaf-2.1`, `leaf-2.2`, `leaf-3.1`, `leaf-3.2`, `leaf-3.3`). C6/leaf-2.1 and C7/leaf-2.2 are distinct pending work and are not covered by the similarly worded 1.3.x ledgers. Cross-reference C8/leaf-3.1 to the existing 1.3.1 implementation/evidence, C9/leaf-3.2 to 1.3.2, and C10/leaf-3.3 to 1.3.3; reuse evidence only for exactly matching outcomes. Keep existing 1.1.x-1.3.x entries and evidence intact. Carry forward dependencies only where the mapped dispatch row explicitly records them. C6/C7 dependency readiness is unresolved and those owners are not dispatchable. All C6-C10 work remains pending, no gate criteria or results change, and no completion is claimed. No owner-specific C6-C10 gate ledgers are created by this amendment.

**Revision 5 amendment (2026-11-14):** The user authorized C7/leaf-2.2 as independent (`Needs: -`) with exact ownership of the new `tests/test_repo_preexec_bypass.py` file. Keep C7's original bypass-prevention outcomes for alternate shells, direct interpreters, PATH manipulation, symlinks, and subprocesses. No application source or existing P3/P4 file is in scope. This amendment changes C7 readiness and ownership only; it supplies no evidence, changes no acceptance criteria, and claims no completion.

**Revision 6 amendment (2026-11-14):** Preserve the original C7 contract wording verbatim as history: “Bypass prevention: alternate shells, direct interpreter, PATH manipulation, symlinks, subprocesses.” C7 now verifies bypass resistance only for commands mediated by installed wrapper shims. Child processes must receive a controlled PATH including the trusted managed-wrapper directory; do not forward arbitrary caller-controlled PATH. Absolute executable paths (for example `/usr/bin/python3`) and deliberate caller reordering of PATH are outside what this user-mediated PATH-wrapper architecture can enforce. Preserve those limitations; do not claim system-wide or unbypassable protection. Symlink coverage distinguishes aliases to managed shims from arbitrary symlinks to system executables; the latter are outside the mediated-shim guarantee. This amendment changes only C7's boundary and observing gate descriptions; it supplies no implementation or test evidence, changes no other owner, and claims no gate met.

**Revision 7 amendment (2026-11-14):** Add `leaf-2.3` as a separate supporting C7 child-PATH remediation under `node-2`, with exact ownership of `src/wrapper/core.py` and observing gate `leaf-2.3:G2.3.1`. It supports, but does not replace, C7/`leaf-2.2` and its `G2.2.2`. Do not change `leaf-2.2`'s owner ID, `Needs`, `Owns`, `IN-FLIGHT` state, acceptance criteria, history, or active lease; no retroactive dependency is added. Run the new source leaf check first, then rerun the previously failing C7 `G2.2.2` under its existing lease, then freshly reverify the source, C6, and C7 ledgers through `node-2:N1`. `node-2:N4` covers release of all three child leases only after parent verification and manual review. `src/wrapper/core.py` is also owned by completed P3 leaves 3A.3, 3A.4, and 3A.5, so their relevant focused checks must be rerun after the source change; preserve their ledgers and criteria. P4.1 explicitly excludes this file, and the current P4 status has no met gate evidence. No test file or existing C6/C7 criterion is changed, and no completion is claimed.

**Revision 8 dispatch-only amendment (2026-11-14):** Resolve the leaf-1.3.1/leaf-1.3.2/node-1.3 dispatch cycle without changing acceptance criteria. As the sole row-specific exception to dispatch requiring every `Needs` entry to be `VERIFIED`, leaf-1.3.2 may proceed after the exact leaf-1.3.1 ledger's G1-G11 have all freshly passed `--reverify`, as recorded in its automatic evidence and the append-only status log; it need not wait for leaf-1.3.1 to become `VERIFIED`. Keep leaf-1.3.1 `IN-FLIGHT` and its lease unchanged. Node-1.3 N1 continues to freshly reverify all three named children, including both leaves 1.3.1 and 1.3.2; neither the node requirement nor any gate definition is weakened. This dispatch prerequisite is satisfied by the already-recorded fresh 11/11 leaf-1.3.1 re-verification. No source, tests, ownership, or gate criteria change, and no leaf is started or claimed by this amendment.

**Revision 9 records-only amendment (2026-11-14):** Add the missing owner ledgers for C8/`leaf-3.1` and C9/`leaf-3.2`, plus the `node-3` parent ledger, using the existing owner IDs, gate IDs, contract outcomes, and dispatch ownership mirrors. C8's prerequisites `1.2.1, 1.2.2` are verified, so its row is `READY` now that its exact `OWNS:` authority is recorded. C9 keeps its dependency on C8/`leaf-3.1` and also records the mapped `leaf-1.3.1` G1-G11 fresh self-verification prerequisite required by Revisions 4 and 8; it remains `WAITING`. The existing tree establishes node-3 as the parent of leaves 3.1, 3.2, and 3.3. Node-3 must freshly reverify all three children, complete its manual review, and only then allow the individually leased child work to be released; its post-release receipt is recorded afterward. New child and parent gates remain pending with no evidence credit, including exact-match crosswalk candidates. C10's ledger, evidence, and active lease are unchanged. The retained C9 `Needs: 3.1` also exposes a dispatch cycle under the existing rule that `Needs` entries must be `VERIFIED`: node-3 requires C9 in its parent verification, so C8 cannot become `VERIFIED` before C9 dispatches. No self-verification exception is inferred; resolving whether C9 may dispatch after fresh C8 self-verification requires a user decision. No source or test files or gate criteria changed, no application checks or tests were run, and no C8/C9/C10 item is claimed complete.

**Revision 10 dispatch-only amendment (2026-11-14):** Per the user's decision, C9/`leaf-3.2` may proceed after `leaf-3.1` G3.1.1 and G3.1.2 both freshly pass `--reverify`, as recorded in their automatic evidence and the append-only status log; it need not wait for `leaf-3.1` to become `VERIFIED`. Keep C8's own dependencies, C9's dependency on C8 and fresh `leaf-1.3.1` G1-G11 evidence, all owner IDs, ownership, and gate criteria unchanged. Node-3 N1 still freshly re-verifies all three named children before parent verification; this exception only resolves dispatch order. C9 remains `WAITING` until the specified fresh C8 evidence is recorded. No source, tests, leases, or completion states change.

## Revision 4 implementation/evidence crosswalk

These are references, not aliases or completion credit for the preserved owner IDs. The new owner-specific ledgers must define their exact `OWNS:` sets and verification oracles before any claim. Existing 1.3.x ledgers remain intact.

| Contract owner | Existing implementation/evidence reference | Outcomes eligible for exact-match evidence reuse |
|---|---|---|
| C6 / leaf-2.1 | Dedicated test artifact: `tests/test_repo_preexec_interception.py`; wrapper source is inspected as behavior under test but is not owned by C6 | No 1.3.x evidence credit; new tests must cover all four C6 outcomes |
| C7 / leaf-2.2 | No 1.3.x cross-reference; candidate implementation paths: `src/wrapper/path.py`, `src/wrapper/core.py`, `src/wrapper/commands.py` | None established by this amendment |
| C8 / leaf-3.1 | `leaf-1.3.1.md` G1, G6, G11; `node-1.3.md` N2-N3 | Repository-review scanners, safe-run approval path, and preservation of existing APT CLI |
| C9 / leaf-3.2 | `leaf-1.3.2.md` G1-G6; `node-1.3.md` N4 | Normal/suspicious repository outcomes, malware/incomplete blocking, approval, and cancellation |
| C10 / leaf-3.3 | `leaf-1.3.3.md` G1-G5; `node-1.3.md` N5; root `GATES.md` N6 | The five Kali 2026.3 APT scenarios and their reviewed guest outcomes |

Dependency mapping: C6/leaf-2.1 has no prerequisites by the user's explicit 2026-11-14 decision recorded in the scope status log; this is not inferred from code. C7/leaf-2.2 remains dependency-unresolved. C8/leaf-3.1 carries the mapped 1.3.1 row's explicit `1.2.1, 1.2.2` prerequisites. C9/leaf-3.2 carries the mapped 1.3.2 row's dependency on fresh leaf-1.3.1 G1-G11 self-verification, as amended by Revision 8; this does not change node-1.3 parent verification. The mapped 1.3.3 row explicitly has no dependency, so C10/leaf-3.3 has none. All five owner-specific gate ledgers must define their exact `OWNS:` authorities before claim; C6's ledger now does so.

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
  - 2 Execution interception and bypass prevention ........ gates/node-2.md
    - 2.1 Execution interception: Git clone, shell scripts, build commands, dependency installs ...... gates/leaf-2.1.md
    - 2.2 Bypass prevention: alternate shells, direct interpreter, PATH manipulation, symlinks, subprocesses ...... gates/leaf-2.2.md
    - 2.3 Supporting C7 child-PATH source remediation ...... gates/leaf-2.3.md
  - 3 CLI and integration outcomes ........ gates/node-3.md
    - 3.1 CLI --review-repository and --safe-run integrate with existing APT CLI ...... gates/leaf-3.1.md
    - 3.2 End-to-end: normal repo runs, suspicious repo flagged, approval/cancel works, incomplete blocks ...... gates/leaf-3.2.md
    - 3.3 APT regression: all 5 acceptance scenarios still pass ...... gates/leaf-3.3.md

## Leaf dispatch table

This is the single authoritative PLAN table for leaf operation. It is authoritative for `Needs`, `Tier`, `Planned wave`, and `State`; `Owns` remains visible here as the derived planning mirror described below. Keep exactly one row per tree leaf and do not duplicate these fields in the tree or a schedule.

| Leaf | Owns | Needs | Tier | Planned wave | State |
|---|---|---|---|---|---|
| 1.1.1 | scanner/execution_guard.py (review_repository_for_execution), scanner/repository_scanner.py, tests/test_execution_guard.py (identification tests) | - | mechanical | 1 | VERIFIED |
| 1.1.2 | scanner/repository_malware_scanner.py, tests/test_repository_malware_scanner.py | - | mechanical | 1 | VERIFIED |
| 1.1.3 | scanner/repository_security_scanner.py, tests/test_repository_security_scanner.py | - | mechanical | 1 | VERIFIED |
| 1.2.1 | scanner/execution_guard.py (confirm_execution, run_reviewed_command), tests/test_execution_guard.py (approval tests) | 1.1.1, 1.1.2, 1.1.3 | mechanical | 2 | VERIFIED |
| 1.2.2 | scanner/execution_guard.py (run_reviewed_command fail-closed), tests/test_execution_guard.py (fail-closed tests) | 1.1.1, 1.1.2, 1.1.3 | mechanical | 2 | VERIFIED |
| 1.3.1 | main.py (CLI --review-repository, --safe-run), tests/test_main.py (CLI tests) | 1.2.1, 1.2.2 | mechanical | 3 | VERIFIED |
| 1.3.2 | tests/integration/test_repo_preexec.py, tests/test_execution_guard.py (integration tests) | 1.3.1 G1-G11 fresh self-verification | judgment | 3 | VERIFIED |
| 1.3.3 | tests/integration/test_apt_preinstall_guest.py, README.md | - | judgment | 3 | VERIFIED |
| 2.1 | tests/test_repo_preexec_interception.py | - | judgment | 1 | VERIFIED |
| 2.2 | tests/test_repo_preexec_bypass.py | - | judgment | 1 | VERIFIED |
| 2.3 | src/wrapper/core.py (managed-wrapper child PATH construction) | - | judgment | 2 | VERIFIED |
| 3.1 | main.py (CLI --review-repository, --safe-run), tests/test_main.py (CLI tests); cross-reference leaf-1.3.1 | 1.2.1, 1.2.2 | mechanical | 3 | VERIFIED |
| 3.2 | tests/integration/test_repo_preexec.py, tests/test_execution_guard.py (integration tests); cross-reference leaf-1.3.2 | 3.1 G3.1.1-G3.1.2 fresh self-verification (Revision 10 exception), leaf-1.3.1 G1-G11 fresh self-verification | judgment | 4 | VERIFIED |
| 3.3 | tests/integration/test_apt_preinstall_guest.py, README.md | - | judgment | 3 | VERIFIED |

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