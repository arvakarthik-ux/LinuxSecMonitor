# Priority 4 Gates (P4.1-P4.6 complete)

Scope: `.unlazy/priority-4/` — P4.1 Installable Wrapper Lifecycle, P4.2
Installed-Wrapper Post-Clone Review Integration, and P4.3 Installed Non-Git Wrapper
Execution Paths. P4.1-P4.3 are complete with their recorded gate evidence.
P4.4 is complete under the user-authorized bounded scope in `gates/leaf-4.4.md`;
it was previously a placeholder, not a defined item in an approved original roadmap.
P4.5 is complete under the bounded scope in `gates/leaf-4.5.md`.
P4.6 is complete under the bounded user-authorized proposed scope in
`gates/leaf-4.6.md`; it is not part of the approved original roadmap.

See `gates/leaf-4.1.md` and `gates/leaf-4.2.md` for CHECK/EXPECT/EVIDENCE of each gate.

- [x] G1: Wheel and sdist built from current project include `src.wrapper` and required modules
- [x] G2: Clean temporary venv installs the wheel offline; `src.wrapper` imports resolve to the venv site-packages, not the source checkout
- [x] G3: Focused existing tests pass (wrapper install/path/config + main CLI)
- [x] G4: New installed-wheel integration test passes all P4.1 scenarios (fresh-shell git via shim, git --version, clone enters installed wrapper then real git, idempotent reinstall, uninstall restore, ownership limits, conflict/backup/broken-shim, primary HOME untouched)
- [x] G5: Generated shim contains no source-checkout dependency (no absolute checkout path, no sys.path insertion)
- [x] G6: Bounded security review (shell RC ownership, PATH behavior, uninstall safety, broken-shim handling) completed with no unresolved blocking findings

State: P4.1 COMPLETE; all G1-G6 gates are satisfied. P4.2 COMPLETE with G1-G5 evidence in
`gates/leaf-4.2.md`. P4.3 COMPLETE with G1-G4 evidence in `gates/leaf-4.3.md`.
P4.4 COMPLETE with G1-G3 fresh evidence in `gates/leaf-4.4.md`.
P4.5 COMPLETE with G1-G3 fresh evidence in `gates/leaf-4.5.md`.
P4.6 COMPLETE with G1-G3 fresh evidence in `gates/leaf-4.6.md`.
Priority 4 as a whole is not complete.

## P4.2 Gates

See `gates/leaf-4.2.md`; all G1-G5 gates have fresh focused passing evidence. P4.5
and P4.6 are complete; Priority 4 as a whole is not complete.

## P4.3 Gates

See `gates/leaf-4.3.md`; all G1-G4 gates have fresh focused passing evidence.
P4.5 and P4.6 are complete.

## P4.4 Gates

See `gates/leaf-4.4.md`; all G1-G3 gates have fresh focused passing evidence.
P4.5 and P4.6 are complete.

## P4.5 Gates

See `gates/leaf-4.5.md`; all G1-G3 gates have fresh focused passing evidence.
P4.6 is complete under user authorization.

## P4.6 Gates

See `gates/leaf-4.6.md`; all G1-G3 gates have fresh focused passing evidence.

## Status amendment (2026-11-15)

The statements above that P4.2-P4.6 remained proposed or that Priority 4 was not complete
are historical snapshots from before their later user-authorized bounded scopes were verified.
The current records support P4.1-P4.6 as complete within the exact scopes in their leaf gates.
P4.4-P4.6 remain supplemental proposed roadmap items, not part of the original approved
roadmap; this status makes no claim about work outside P4.1-P4.6.
