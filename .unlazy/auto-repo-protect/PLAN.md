# Plan: Automatic Repository Protection Architecture Design

Scope: auto-repo-protect
Depth: tree 3
Mode: orchestrated

## Contract

Decide before fan-out:

- Interfaces: Architecture decision document, execution coverage matrix, threat model, Priority 3 implementation plan
- Ownership: Design documents and Unlazy gates under .unlazy/auto-repo-protect/
- Dependencies: None (design task only)
- Host launch mode: sequential fallback (single context sufficient for design)
- Wave policy: single wave for all leaves (independent design work)
- Toolchain: Node.js for gate-check, Markdown for documentation
- Conventions: Follow existing Priority 1 Unlazy structure
- Manual review: Architecture decisions reviewed by human before Priority 3 implementation

## Current contract inventory

Contract revision: 1. Before fan-out, reread the original request and current amendments. Record every independently omittable required outcome and every constraint that changes acceptance; do not copy credentials, private text, or unrelated context.

| ID | Required outcome or constraint | Owner | Observing gate or manual review | Disposition | Revision |
|---|---|---|---|---|---|
| C1 | Execution path coverage matrix for all operation categories | leaf-1.1 | G1.1.1 | ACTIVE | 1 |
| C2 | Enforcement architecture comparison and recommendation | leaf-1.2 | G1.2.1 | ACTIVE | 1 |
| C3 | Security workflow design with approval and fail-closed | leaf-1.3 | G1.3.1 | ACTIVE | 1 |
| C4 | Threat model with explicit protections and limitations | leaf-1.4 | G1.4.1 | ACTIVE | 1 |
| C5 | Complete architecture design document | leaf-1.5 | G1.5.1 | ACTIVE | 1 |
| C6 | Priority 3 implementation plan with testable units | leaf-1.6 | G1.6.1 | ACTIVE | 1 |
| C7 | All design components integrate into coherent architecture | node-1.1 | N2 | ACTIVE | 1 |
| C8 | Design ready for Priority 3 implementation | node-1.2 | N3 | ACTIVE | 1 |

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

- 1 Automatic Repository Protection Architecture Design .............. GATES.md
  - 1.1 Execution Path Coverage ........ gates/node-1.1.md
    - 1.1.1 Git operations coverage ...... gates/leaf-1.1.1.md
    - 1.1.2 Shell execution coverage ...... gates/leaf-1.1.2.md
    - 1.1.3 Interpreter execution coverage ...... gates/leaf-1.1.3.md
    - 1.1.4 Build system coverage ...... gates/leaf-1.1.4.md
    - 1.1.5 Dependency installation coverage ...... gates/leaf-1.1.5.md
  - 1.2 Enforcement Architecture Evaluation ........ gates/node-1.2.md
    - 1.2.1 Mechanism comparison ...... gates/leaf-1.2.1.md
    - 1.2.2 Recommended architecture ...... gates/leaf-1.2.2.md
  - 1.3 Security Workflow and Threat Model ........ gates/node-1.3.md
    - 1.3.1 Security workflow design ...... gates/leaf-1.3.1.md
    - 1.3.2 Threat model ...... gates/leaf-1.3.2.md
  - 1.4 Architecture Design Document ........ gates/node-1.4.md
    - 1.4.1 Complete architecture document ...... gates/leaf-1.4.1.md
  - 1.5 Priority 3 Implementation Plan ........ gates/node-1.5.md
    - 1.5.1 Implementation plan ...... gates/leaf-1.5.1.md

## Leaf dispatch table

This is the single authoritative PLAN table for leaf operation. It is authoritative for `Needs`, `Tier`, `Planned wave`, and `State`; `Owns` remains visible here as the derived planning mirror described below. Keep exactly one row per tree leaf and do not duplicate these fields in the tree or a schedule.

| Leaf | Owns | Needs | Tier | Planned wave | State |
|---|---|---|---|---|---|
| 1.1.1 | .unlazy/auto-repo-protect/gates/leaf-1.1.1.md, .unlazy/auto-repo-protect/coverage/git.md | - | judgment | 1 | READY |
| 1.1.2 | .unlazy/auto-repo-protect/gates/leaf-1.1.2.md, .unlazy/auto-repo-protect/coverage/shell.md | - | judgment | 1 | READY |
| 1.1.3 | .unlazy/auto-repo-protect/gates/leaf-1.1.3.md, .unlazy/auto-repo-protect/coverage/interpreter.md | - | judgment | 1 | READY |
| 1.1.4 | .unlazy/auto-repo-protect/gates/leaf-1.1.4.md, .unlazy/auto-repo-protect/coverage/build.md | - | judgment | 1 | READY |
| 1.1.5 | .unlazy/auto-repo-protect/gates/leaf-1.1.5.md, .unlazy/auto-repo-protect/coverage/dependency.md | - | judgment | 1 | READY |
| 1.2.1 | .unlazy/auto-repo-protect/gates/leaf-1.2.1.md, .unlazy/auto-repo-protect/architecture/comparison.md | - | judgment | 1 | READY |
| 1.2.2 | .unlazy/auto-repo-protect/gates/leaf-1.2.2.md, .unlazy/auto-repo-protect/architecture/recommendation.md | 1.2.1 | judgment | 2 | WAITING |
| 1.3.1 | .unlazy/auto-repo-protect/gates/leaf-1.3.1.md, .unlazy/auto-repo-protect/workflow/workflow.md | - | judgment | 1 | READY |
| 1.3.2 | .unlazy/auto-repo-protect/gates/leaf-1.3.2.md, .unlazy/auto-repo-protect/workflow/threat-model.md | - | judgment | 1 | READY |
| 1.4.1 | .unlazy/auto-repo-protect/gates/leaf-1.4.1.md, .unlazy/auto-repo-protect/architecture/architecture.md | 1.1.1,1.1.2,1.1.3,1.1.4,1.1.5,1.2.2,1.3.1,1.3.2 | judgment | 3 | WAITING |
| 1.5.1 | .unlazy/auto-repo-protect/gates/leaf-1.5.1.md, .unlazy/auto-repo-protect/plan/implementation-plan.md | 1.4.1 | judgment | 4 | WAITING |

`Owns` is a derived planning mirror of the complete glob set in the leaf ledger. The ledger's `OWNS:` header is the command-time authority read by `--claim`. Normalize both into sets and require equality before marking the row `READY` and again before each claim. On disagreement, fail closed, correct and log the plan or ledger, and recheck; never guess ownership. A successful claim does not prove the mirror agreed with the ledger.

`Tier` is planner metadata for execution leaves. Use `judgment` when a leaf's own artifact needs design or review, and `mechanical` only when its pattern and gates are fixed. Map a tier through documented host-specific model or reasoning controls only when the host exposes them. Otherwise retain the tier as a briefing and review requirement without claiming a model choice. Driver and branch duties, including planning, dispatch, parent verification, integration, and final audit, remain judgment responsibilities outside this leaf field. Tier never weakens a leaf's gates, parent re-verification, or integration standard.

`Planned wave` is the earliest intended launch group under the current contract. Use a positive integer, put every dependency in an earlier planned wave, and let the wave policy cap concurrency. It is a plan, not a barrier: rolling dispatch may start a later planned wave as soon as that row's dependencies are verified, without waiting for unrelated work. Actual starts belong in `dispatch.json` and `status.log`; do not add a second schedule to this file.

Change `Needs`, `Owns`, `Tier`, or `Planned wave` only through a recorded plan amendment before that row launches; do not erase a dependency when it becomes satisfied. Update `State` in this table as work progresses. After parent re-verification and manual review, mark a leaf `VERIFIED`, release that exact leaf lease, and record the release. Do not promote a dependent until that exact release is recorded. For an abandoned leaf, record the handoff and confirm its worker has settled before releasing only that leaf; never call it parent-verified. Release the whole scope only after every leaf is settled and final scope verification has run. If final verification reports a handoff, record it before release and never describe the scope as complete.

## Status log

Append events to `.unlazy/auto-repo-protect/status.log`; do not copy the event history into this file:

```text
node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --scope auto-repo-protect --log "PLAN.md created"
```

Record contract amendments, plan changes, dispatch, parent verification, abandonment, branch integration, and lease release. Apply logged plan amendments and live State updates only in the dispatch table; keep the log append-only. Before root completion, reread the current request and review every current inventory row against its owner and observing gate or manual review.