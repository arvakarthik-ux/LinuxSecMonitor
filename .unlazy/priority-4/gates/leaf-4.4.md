# Gates: Installed Shell-Script Tier 2 Routes - 4.4

Status: COMPLETE. This bounded unit was authorized by the user; it was not an
originally approved Priority 4 roadmap item.

Depends on completed P4.1 (installed wrapper lifecycle), completed P4.2 (installed
Git-wrapper route), completed P4.3 (installed non-Git routes), and existing P3 Tier 2
classification and scan/warn/execute behavior.

Scope: Verify installed `bash <script>` and `sh <script>` routes preserve existing P3
Tier 2 behavior using offline fixtures and temporary HOME, venv, and repository paths.
Do not add production hooks or change classification, scanning, warning, or execution
semantics.

- [x] G1: Complete scans finish before either installed shell script runs, without approval
  CHECK: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledShellScriptTier2::test_shell_script_runs_after_complete_scan_without_approval`
  EXPECT: `PASSED`
  EVIDENCE: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledShellScriptTier2::test_shell_script_runs_after_complete_scan_without_approval` — 2 passed in 6.85s (bash and sh). Both tests observed scan, scan_complete, marker_action ordering, the existing Tier 2 warning, no approval prompt, and successful script marker execution.

- [x] G2: Existing Tier 2 blocking scan outcomes prevent either installed script from running
  CHECK: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledShellScriptTier2::test_shell_script_blocks_existing_block_conditions`
  EXPECT: `PASSED`
  EVIDENCE: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledShellScriptTier2::test_shell_script_blocks_existing_block_conditions` — 6 passed in 7.55s. Both shell routes returned the existing nonzero result and left the marker absent for incomplete coverage, malware, and CRITICAL findings.

- [x] G3: Focused existing P3 Tier 2 regressions remain passing
  CHECK: `python3 -m pytest -vv tests/test_wrapper_commands.py::TestTier2Commands::test_bash_tier2 tests/test_wrapper_core.py::TestScannerIntegration::test_tier2_runs_scans`
  EXPECT: `PASSED`
  EVIDENCE: `python3 -m pytest -vv tests/test_wrapper_commands.py::TestTier2Commands::test_bash_tier2 tests/test_wrapper_core.py::TestScannerIntegration::test_tier2_runs_scans` — 2 passed in 21.75s.

Non-goals: new command categories or tiers; inline `-c`, absolute paths, shell builtins, other
interpreters, or bypass-prevention claims; P3 semantic changes; Git clone, APT, Policy Engine,
P4.5-P4.6, or system-wide enforcement.
