# Priority 4 Plan (P4.1-P4.6 complete)

## Scope statement

- **P4.1 (Installable Wrapper Lifecycle) is complete.**
- **P4.2 (Installed-Wrapper Post-Clone Review Integration) is complete** within the bounded scope defined in `gates/leaf-4.2.md`.
- **P4.3 (Installed Non-Git Wrapper Execution Paths) is complete** within the bounded scope defined in `gates/leaf-4.3.md`.
- **P4.4 (Installed Shell-Script Tier 2 Routes) is complete** within the user-authorized bounded scope defined in `gates/leaf-4.4.md`. P4.4 was a placeholder, not a defined item in an approved original roadmap.
- **P4.5 (Installed Zsh and Fish Script Tier 2 Routes) is complete** within the user-authorized bounded scope defined in `gates/leaf-4.5.md`.
- **P4.6 (Installed Zsh/Fish Fresh-Shell Activation) is complete** within the bounded scope defined in `gates/leaf-4.6.md`, authorized by the user for this task only. It remains a proposed unit, not an item in the approved original roadmap.
- Original Priority 4 numbering and dependencies are preserved.

## Dependency

- P4.1 depends on the existing **P3 wrapper implementation** (`src/wrapper/**`, including files
  that were uncommitted when this plan was created: `src/wrapper/core.py`,
  `src/wrapper/git_clone.py`, `scanner/execution_guard.py`, and guard/Git tests; these are now
  included in the P1-P3 release base).
- P4.1 must not change P3 source behavior except for a directly required, minimal integration fix
  (must be identified and justified before any such change).
- P1/P2/P3 Unlazy history (`.unlazy/apt-hook-complete/`, `.unlazy/priority-3/`) is unchanged by this scope.

## Dispatch table

| ID | Required outcome or constraint | Owner | Observing gate or manual review | Disposition | Revision |
|----|-------------------------------|-------|---------------------------------|-------------|----------|
| P4.1 | Wheel/sdist ships `src.wrapper`; generated shim imports installed package (no source-checkout path); opt-in `--wrapper-integration {status,install,uninstall}`; user-scoped idempotent conflict-aware install/status/uninstall for bash/zsh/fish; fail-closed broken/missing package; focused tests + installed-wheel integration test; bounded security review | lsm-developer (impl), lsm-test-engineer (tests), lsm-security-auditor (review) | leaf-4.1.md G1-G6 | COMPLETE | 1 |
| P4.2 | Installed P4.1 Git shim reaches existing P3A.5 post-clone review for successful worktree clones; preserve parser, scanner/cache, integrity, fail-closed, and exact RUN semantics; offline installed-wheel tests | focused installed-wrapper and P3A.5 regression tests | leaf-4.2.md G1-G5 | COMPLETE | 1 |
| P4.3 | Installed P4.1 shims for existing non-Git Tier 1 `make install` and Tier 2 `python3 <script.py>` reach P3 scan/approval/execution behavior unchanged; temporary/offline integration coverage for scan-before-execution, existing acceptance/refusal outcomes, and Tier 2 findings policy | focused installed-wrapper tests and selected P3 regressions | leaf-4.3.md G1-G4 | COMPLETE | 1 |
| P4.4 | User-authorized proposed unit: installed `bash <script>` and `sh <script>` routes preserve existing P3 Tier 2 scan/warn/execute behavior; offline installed-wheel tests cover scan-before-action and existing blocking outcomes without production changes | focused installed-wrapper and P3 Tier 2 regression tests | leaf-4.4.md G1-G3 | COMPLETE | 1 |
| P4.5 | User-authorized proposed unit: installed `zsh <script>` and `fish <script>` routes preserve existing P3 Tier 2 behavior; offline installed-wheel tests cover scan-before-action and existing blocking outcomes without production changes | focused installed-wrapper and P3 Tier 2 regression tests | leaf-4.5.md G1-G3 | COMPLETE | 1 |
| P4.6 | User-authorized proposed unit: fresh interactive Zsh/Fish sessions load the installed temporary-HOME PATH integration, resolve `python3` through its installed shim, and execute a harmless Tier 2 script only after the existing scan completes | installed-wheel fresh-shell tests and focused P3 Tier 2 regression | leaf-4.6.md G1-G3 | COMPLETE | 1 |

## Acceptance gates

Measurable gates are defined in `GATES.md` and the P4.1-P4.6 leaf records.
P4.1-P4.6 gates have fresh recorded evidence under their respective authorized scopes.
