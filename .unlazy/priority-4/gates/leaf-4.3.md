# Gates: Installed Non-Git Wrapper Execution Paths - 4.3

Status: COMPLETE.

Depends on completed P4.1 (installed wrapper lifecycle), completed P4.2 (installed
Git-wrapper route), and existing P3A.1-A.4 command classification, scanner, approval,
and trusted execution behavior.

Scope: Exercise already-supported non-Git Tier 1 `make install` and Tier 2
`python3 <script.py>` commands through installed shims in temporary repositories. Preserve
P3 behavior; do not add command patterns or change scanner/approval semantics.

- [x] G1: Tier 1 runs only after completed scan and exact approval
  CHECK: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier1_make_install_runs_only_after_scan_and_exact_run`
  EXPECT: `PASSED`
  Evidence required: While the deterministic installed-process scanner seam is held before
  returning, the temporary make marker is absent. After scan completion, an approval request
  occurs; exact `RUN` executes the marker action. Event order is `scan`, `scan_complete`,
  `approval_request`, `marker_action`.
  EVIDENCE: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier1_make_install_runs_only_after_scan_and_exact_run` — 1 passed in 5.94s. The installed route remained blocked at the scanner seam with no marker; the recorded order was scan, scan_complete, approval_request, marker_action after exact RUN.

- [x] G2: Tier 1 refusal and missing repository context fail closed
  CHECK: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier1_make_install_rejection_does_not_run tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier1_make_install_unavailable_tty_does_not_run tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier1_make_install_without_repository_does_not_run tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier1_make_install_blocks_existing_scan_failures`
  EXPECT: `PASSED`
  Evidence required: Rejected input and unavailable controlling TTY preserve nonzero P3 outcomes
  without marker execution; Tier 1 invocation outside repository context returns before scan,
  approval, or command execution.
  EVIDENCE: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier1_make_install_rejection_does_not_run tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier1_make_install_unavailable_tty_does_not_run tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier1_make_install_without_repository_does_not_run tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier1_make_install_blocks_existing_scan_failures` — 7 passed in 8.01s. Rejection, EOF, no-TTY, no-repository, incomplete/error coverage, and malware all left the marker absent; missing context emitted no scanner or approval event.

- [x] G3: Tier 2 matches existing allow/block outcomes
  CHECK: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier2_python_script_runs_after_complete_scan tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier2_python_script_allows_noncritical_finding tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier2_python_script_blocks_existing_block_conditions`
  EXPECT: `PASSED`
  Evidence required: Complete coverage with no malware/CRITICAL finding runs the script after the
  Tier 2 scan warning and without approval; a non-CRITICAL finding follows current P3 behavior.
  Incomplete coverage, scanner error represented as incomplete coverage, malware, and CRITICAL
  findings block without marker execution. No new severity policy is introduced.
  EVIDENCE: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier2_python_script_runs_after_complete_scan tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier2_python_script_allows_noncritical_finding tests/test_wrapper_installed_wheel.py::TestInstalledNonGitWrapperPaths::test_tier2_python_script_blocks_existing_block_conditions` — 6 passed in 7.42s. Complete and HIGH-finding scans ran after the Tier 2 warning without approval; incomplete/error, malware, and CRITICAL findings blocked marker execution.

- [x] G4: Isolation and P3 regression
  CHECK: `python3 -m pytest -vv tests/test_wrapper_commands.py::TestTier1Commands::test_make_install_tier1 tests/test_wrapper_commands.py::TestTier2Commands::test_python_script_tier2 tests/test_wrapper_core.py::TestScannerIntegration::test_tier1_calls_scanners tests/test_wrapper_core.py::TestScannerIntegration::test_tier2_runs_scans tests/test_wrapper_scanner_integration.py::test_scanner_failure_timeout_and_incomplete`
  EXPECT: `PASSED`
  Evidence required: All installed tests use temporary HOME, local repository, and marker paths;
  primary-HOME RC guard is active; no remote access is used. Focused installed tests and selected
  P3 tier/scanner regressions pass. P3 source and P3 gate records remain unchanged.
  EVIDENCE: `python3 -m pytest -vv tests/test_wrapper_commands.py::TestTier1Commands::test_make_install_tier1 tests/test_wrapper_commands.py::TestTier2Commands::test_python_script_tier2 tests/test_wrapper_core.py::TestScannerIntegration::test_tier1_calls_scanners tests/test_wrapper_core.py::TestScannerIntegration::test_tier2_runs_scans tests/test_wrapper_scanner_integration.py::test_scanner_failure_timeout_and_incomplete` — 5 passed in 56.35s. The new installed tests use temporary HOME/repositories/markers, local-only Git initialization, and the active `guard_primary_home_rc` fixture. No P3 source or gate files were edited.

Non-goals: new command categories or tiers; changes to P3 classification, scanner, cache, approval,
prompt, or execution behavior; Git clone behavior; APT; Policy Engine; system-wide enforcement;
P4.4-P4.6.
