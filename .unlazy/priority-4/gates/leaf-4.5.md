# Gates: Installed Zsh and Fish Script Tier 2 Routes - 4.5

Status: COMPLETE. This bounded unit is user-authorized; it was not an
originally approved Priority 4 roadmap item.

Depends on completed P4.1-P4.4 and existing P3 Tier 2 classification and
scan/warn/execute behavior.

Scope: Verify installed `zsh <script>` and `fish <script>` routes preserve
existing P3 Tier 2 behavior using offline fixtures and temporary HOME, venv,
and repository paths. Do not add production hooks or change classification,
scanning, warning, or execution semantics. Do not install packages or modify
the user's shell configuration.

- [x] G1: Complete scans finish before either installed shell script runs, without approval
  CHECK: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledZshFishScriptTier2 tests/test_wrapper_commands.py::TestTier2Commands::test_bash_tier2 tests/test_wrapper_core.py::TestScannerIntegration::test_tier2_runs_scans`
  EXPECT: `PASSED`
  EVIDENCE: The CHECK command passed 10 tests in 117.05s. Both Zsh and Fish
  recorded `scan`, `scan_complete`, `marker_action`; preserved the Tier 2
  warning; executed the fixture marker; and requested no approval.

- [x] G2: Existing Tier 2 blocking scan outcomes prevent either installed script from running
  CHECK: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledZshFishScriptTier2 tests/test_wrapper_commands.py::TestTier2Commands::test_bash_tier2 tests/test_wrapper_core.py::TestScannerIntegration::test_tier2_runs_scans`
  EXPECT: `PASSED`
  EVIDENCE: The CHECK command passed 10 tests in 117.05s. Both shell routes
  retained the existing nonzero result and left the marker absent for incomplete
  coverage, malware, and CRITICAL findings; no approval was requested.

- [x] G3: Focused existing P3 Tier 2 regressions remain passing
  CHECK: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledShellScriptTier2 tests/test_wrapper_installed_wheel.py::TestInstalledZshFishScriptTier2 tests/test_wrapper_commands.py::TestTier2Commands::test_bash_tier2 tests/test_wrapper_core.py::TestScannerIntegration::test_tier2_runs_scans`
  EXPECT: `PASSED`
  EVIDENCE: 18 tests passed in 85.33s, covering the P4.4 Bash/sh routes, P4.5
  Zsh/Fish routes, and existing Tier 2 classification/scanner integration.
  No P3 source or P3 gate files were changed.

Non-goals: new command categories or tiers; inline `-c`, absolute paths, shell
builtins, other interpreters, or bypass-prevention claims; P3 semantic changes;
Git clone, APT, Policy Engine, P4.6, or system-wide enforcement.
