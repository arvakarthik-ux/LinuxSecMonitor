# Plan: Complete APT hook/lifecycle implementation

Scope: apt-hook-complete
Depth: tree 3
Mode: orchestrated

## Contract

Decide before fan-out:

- Interfaces: APT Pre-Install-Pkgs protocol v3 (stdin/stdout), apt_lifecycle.py public API (install_apt_hook, enable_apt_hook, disable_apt_hook, uninstall_apt_hook, integration_status, validate_trusted_runtime, validate_effective_hook_order), CLI --apt-preinstall-hook and --apt-integration
- Ownership: scanner/apt_hook.py, scanner/apt_lifecycle.py, tests/test_apt_hook.py, tests/test_apt_lifecycle.py, tests/test_apt_hook_cli.py, main.py (CLI integration)
- Dependencies: scanner/malware_scanner.py, scanner/package_scanner.py, scanner/vulnerability_assessment.py, scanner/system_info.py
- Host launch mode: sequential fallback (single context sufficient for verification)
- Wave policy: single wave for all leaves (independent verification)
- Toolchain: Python 3.11+, pytest, clamscan (for integration), apt-config (for lifecycle validation)
- Conventions: fail-closed parsing, root-owned paths, _apt sandbox user, atomic writes, terminal escape sequences
- Manual review: disposable guest integration verification (requires a physical/virtual Kali/Debian/Ubuntu guest, or — when VM/KVM is unavailable — a fresh isolated local Docker/Podman container from a local Kali/Debian/Ubuntu image with no host mounts, no privileged mode, one container per scenario, rollback by removal, an unchanged base image, and evidence recorded in status.log)

## Current contract inventory

Contract revision: 4. Before fan-out, reread the original request and current amendments. Record every independently omittable required outcome and every constraint that changes acceptance; do not copy credentials, private text, or unrelated context.

| ID | Required outcome or constraint | Owner | Observing gate or manual review | Disposition | Revision |
|---|---|---|---|---|---|
| C1 | APT Pre-Install-Pkgs v3 protocol parser accepts valid transactions and rejects malformed input | leaf-1.1 | G1.1.1, G1.1.2 | ACTIVE | 1 |
| C2 | Archive path validation rejects traversal, symlinks, non-.deb, oversized, missing files | leaf-1.2 | G1.2.1, G1.2.2 | ACTIVE | 1 |
| C3 | Malware assessment runs on every archive with ClamAV and static heuristics | leaf-1.2 | G1.2.3 | ACTIVE | 1 |
| C4 | Vulnerability assessment aggregates all transaction packages before approval | leaf-1.2 | G1.2.4 | ACTIVE | 1 |
| C5 | Terminal approval requires exact "INSTALL" string; blocks on timeout, EOF, interrupt | leaf-1.3 | G1.3.1, G1.3.2 | ACTIVE | 1 |
| C6 | Privileges irreversibly drop to _apt user before scanning archives | leaf-1.3 | G1.3.3 | ACTIVE | 1 |
| C7 | Scanner uses trusted PATH (/usr/sbin:/usr/bin:/sbin:/bin) and restores caller environment | leaf-1.3 | G1.3.4 | ACTIVE | 1 |
| C8 | install_apt_hook creates hook atomically with apt-config validation and rollback | leaf-2.1 | G2.1.1, G2.1.2 | ACTIVE | 1 |
| C9 | enable_apt_hook restores hook from state; disable/uninstall remove only owned artifacts | leaf-2.1 | G2.1.3, G2.1.4 | ACTIVE | 1 |
| C10 | validate_trusted_runtime rejects non-root-owned or user-writable interpreter/module paths | leaf-2.2 | G2.2.1 | ACTIVE | 1 |
| C11 | validate_effective_hook_order ensures LinuxSecMonitor hook is first effective Pre-Install-Pkgs | leaf-2.2 | G2.2.2 | ACTIVE | 1 |
| C12 | _atomic_write publishes via hard-link with fsync; never replaces racing existing file | leaf-2.3 | G2.3.1, G2.3.2 | ACTIVE | 1 |
| C13 | Lifecycle state tracks hook SHA-256, python path, format version; survives disable/enable | leaf-2.3 | G2.3.3 | ACTIVE | 1 |
| C14 | CLI --apt-preinstall-hook dispatches to run_apt_preinstall_hook with stdin/stdout | leaf-3.1 | G3.1.1 | ACTIVE | 1 |
| C15 | CLI --apt-integration {status,install,enable,disable,uninstall} works with JSON/text output | leaf-3.1 | G3.1.2 | ACTIVE | 1 |
| C16 | End-to-end transaction blocks on incomplete coverage, error, unavailable, detection, mismatch | leaf-3.2 | G3.2.1 | ACTIVE | 1 |
| C17 | Real disposable guest verification (Kali/Debian/Ubuntu) confirms hook executes in APT | leaf-3.3 | G3.3.1 (manual) | ACTIVE | 2 |

**Revision 2 amendment (2026-11-09):** The user explicitly reopened leaf 1.3.3 / manual gate G3.3.1 after its prior ABANDONED state. No documented Unlazy reopen procedure exists, so this amendment records the reopening without creating a new leaf or scope identifier. The original ABANDON reason is preserved verbatim in `status.log`. The leaf state moves from ABANDONED to IN-FLIGHT pending parent reverify; REOPENED is an event, not a state. Guest verification used a fresh isolated Docker Kali guest basis, and an independent `lsm-security-auditor` audit returned APPROVE WITH CONDITIONS (documentation/gate amendments only, no product security defect). No scope expansion. After parent node-1.3 reverify returned `ALL MET` and the lease was released on 2026-11-09, leaf 1.3.3 is VERIFIED; root GATES N1/N5/N6 remain pending only for pre-existing node-1.1/1.2 manual lease/outcome gates, not this leaf.

**Revision 3 amendment (2026-11-09):** Historical lease-release evidence for leaf-1.1.1, leaf-1.1.2, leaf-1.1.3, leaf-1.2.1, leaf-1.2.2, and leaf-1.2.3 is unavailable. The recorded search found no authentic lease files or release events; absence is not proof of release. No release is inferred, reconstructed, or fabricated. The release-recording rule above leaves node-1.1:N1.5, node-1.2:N1.5, and root N5 unmet, and prevents root N1 from reaching ALL MET. Node-1.1:N1.6, node-1.2:N1.6, and root N6 remain unmet and unrecorded. The honest branch disposition is ABANDONED with a visible handoff, not VERIFIED and not complete. This disposition changes no contract row C1-C17, leaf state, gate checkbox, gate evidence, or historical ABANDON record. ABANDONED does not mean the APT hook/lifecycle scope or product is complete.

**Revision 4 amendment (2026-11-12):** The user explicitly authorized this scope-level exception to P1's recorded terminal abandonment, reopening P1 solely for fresh verification under the existing acceptance criteria. The prior root `ABANDON:` record and full handoff wording are preserved verbatim as `HISTORY` in `GATES.md` and `status.log`; that historical record is no longer operative for this authorized verification cycle. P1 is REOPENED FOR FRESH VERIFICATION and remains incomplete. No C1-C17 acceptance criterion, gate ID, or dependency is changed; this amendment itself provides no gate evidence and claims no gate met.

The exact outstanding gates are `node-1.1:N1.5`, `node-1.1:N1.6`, `node-1.2:N1.5`, `node-1.2:N1.6`, root `GATES.md:N1`, `GATES.md:N5`, and `GATES.md:N6`. In addition, `leaf-1.3.3:G3.3.1` is reopened and unmet pending resolution of the guest cleanup/rollback condition: the leaf records that its seven scenario containers and base container were still running. No container was removed by this amendment. The prior guest results remain historical and are not counted as complete evidence until the cleanup condition is resolved under separate authorization or fresh guest evidence satisfies the existing procedure.

Recovery order, with no scope expansion and only in a separately authorized verification task: (1) in sequential order, freshly claim and reverify leaves 1.1.1–1.1.3 and 1.2.1–1.2.3; their declared ownership overlaps, so do not run them concurrently. (2) At each parent, reverify its child ledgers and integration outcomes and complete the branch-level manual review for N1.6. Only after that parent verification and review, release each exact newly claimed leaf lease and append its release event; these prospective events can satisfy the prospective release requirement in N1.5, but are not and must never be represented as the missing historical releases. Record N1.5 from those new events, then reverify the node. (3) Resolve the leaf-1.3.3 cleanup condition without changing its acceptance criteria, then reverify node-1.3 and complete the root-level manual review. (4) Only after all three nodes and their manual outcomes are ready, reverify root N1/N5/N6 and the remaining root gates. A gate that cannot be satisfied by fresh evidence under its unchanged criterion must remain unmet and be returned for a separate user decision; do not reinterpret historical evidence or release records.

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

- 1 Complete APT hook/lifecycle implementation .............. GATES.md
  - 1.1 Core hook protocol and scanning ........ gates/node-1.1.md
    - 1.1.1 Protocol parsing and validation ...... gates/leaf-1.1.1.md
    - 1.1.2 Archive validation and malware assessment ...... gates/leaf-1.1.2.md
    - 1.1.3 Terminal approval and privilege dropping ...... gates/leaf-1.1.3.md
  - 1.2 Lifecycle management ........ gates/node-1.2.md
    - 1.2.1 Install/enable/disable/uninstall operations ...... gates/leaf-1.2.1.md
    - 1.2.2 Trusted runtime and hook order validation ...... gates/leaf-1.2.2.md
    - 1.2.3 Atomic writes and state persistence ...... gates/leaf-1.2.3.md
  - 1.3 CLI integration and end-to-end verification ........ gates/node-1.3.md
    - 1.3.1 CLI dispatch and apt-integration commands ...... gates/leaf-1.3.1.md
    - 1.3.2 End-to-end transaction behavior ...... gates/leaf-1.3.2.md
    - 1.3.3 Disposable guest verification ...... gates/leaf-1.3.3.md

## Leaf dispatch table

This is the single authoritative PLAN table for leaf operation. It is authoritative for `Needs`, `Tier`, `Planned wave`, and `State`; `Owns` remains visible here as the derived planning mirror described below. Keep exactly one row per tree leaf and do not duplicate these fields in the tree or a schedule.

| Leaf | Owns | Needs | Tier | Planned wave | State |
|---|---|---|---|---|---|
| 1.1.1 | scanner/apt_hook.py (parse_pre_install_v3, _validate_package_action, _safe_archive_path), tests/test_apt_hook.py (parse tests) | - | mechanical | 1 | VERIFIED |
| 1.1.2 | scanner/apt_hook.py (run_apt_preinstall_hook scanning logic), tests/test_apt_hook.py (scan tests) | - | mechanical | 1 | VERIFIED |
| 1.1.3 | scanner/apt_hook.py (_prompt_for_detection, _drop_to_apt_sandbox_user, _scan_with_trusted_path), tests/test_apt_hook.py (prompt/privilege tests) | - | mechanical | 1 | VERIFIED |
| 1.2.1 | scanner/apt_lifecycle.py (install_apt_hook, enable_apt_hook, disable_apt_hook, uninstall_apt_hook), tests/test_apt_lifecycle.py (lifecycle tests) | - | mechanical | 1 | VERIFIED |
| 1.2.2 | scanner/apt_lifecycle.py (validate_trusted_runtime, validate_effective_hook_order), tests/test_apt_lifecycle.py (runtime/order tests) | - | mechanical | 1 | VERIFIED |
| 1.2.3 | scanner/apt_lifecycle.py (_atomic_write, _read_state, integration_status), tests/test_apt_lifecycle.py (atomic/state tests) | - | mechanical | 1 | VERIFIED |
| 1.3.1 | main.py (CLI --apt-preinstall-hook, --apt-integration), tests/test_apt_hook_cli.py, tests/test_main.py (apt CLI tests) | - | mechanical | 1 | VERIFIED |
| 1.3.2 | scanner/apt_hook.py (run_apt_preinstall_hook full flow), tests/test_apt_hook.py (full transaction tests) | - | mechanical | 1 | VERIFIED |
| 1.3.3 | tests/integration/test_apt_preinstall_guest.py, README.md (guest verification notes) | - | judgment | 1 | VERIFIED |

`Owns` is a derived planning mirror of the complete glob set in the leaf ledger. The ledger's `OWNS:` header is the command-time authority read by `--claim`. Normalize both into sets and require equality before marking the row `READY` and again before each claim. On disagreement, fail closed, correct and log the plan or ledger, and recheck; never guess ownership. A successful claim does not prove the mirror agreed with the ledger.

`Tier` is planner metadata for execution leaves. Use `judgment` when a leaf's own artifact needs design or review, and `mechanical` only when its pattern and gates are fixed. Map a tier through documented host-specific model or reasoning controls only when the host exposes them. Otherwise retain the tier as a briefing and review requirement without claiming a model choice. Driver and branch duties, including planning, dispatch, parent verification, integration, and final audit, remain judgment responsibilities outside this leaf field. Tier never weakens a leaf's gates, parent re-verification, or integration standard.

`Planned wave` is the earliest intended launch group under the current contract. Use a positive integer, put every dependency in an earlier planned wave, and let the wave policy cap concurrency. It is a plan, not a barrier: rolling dispatch may start a later planned wave as soon as that row's dependencies are verified, without waiting for unrelated work. Actual starts belong in `dispatch.json` and `status.log`; do not add a second schedule to this file.

Change `Needs`, `Owns`, `Tier`, or `Planned wave` only through a recorded plan amendment before that row launches; do not erase a dependency when it becomes satisfied. Update `State` in this table as work progresses. After parent re-verification and manual review, mark a leaf `VERIFIED`, release that exact leaf lease, and record the release. Do not promote a dependent until that exact release is recorded. For an abandoned leaf, record the handoff and confirm its worker has settled before releasing only that leaf; never call it parent-verified. Release the whole scope only after every leaf is settled and final scope verification has run. If final verification reports a handoff, record it before release and never describe the scope as complete.

## Status log

Append events to `.unlazy/apt-hook-complete/status.log`; do not copy the event history into this file:

```text
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope apt-hook-complete --log "leaf-1.1.1 dispatched"
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope apt-hook-complete --log "leaf-1.1.1 verified"
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope apt-hook-complete --log "leaf-1.1.1 lease released"
```

Record contract amendments, plan changes, dispatch, parent verification, abandonment, branch integration, and lease release. Apply logged plan amendments and live State updates only in the dispatch table; keep the log append-only. Before root completion, reread the current request and review every current inventory row against its owner and observing gate or manual review.