# Gates: Execution Safety - 3A.4

OWNS: src/wrapper/path.py, src/wrapper/core.py, src/wrapper/approval.py, tests/test_wrapper_path.py, tests/test_wrapper_core.py, tests/test_execution_safety.py

Scope: Trusted executable resolution, PATH injection protection, environment security, race protection, approval integrity

- [x] G1: Trusted executable resolution uses only approved system paths and rejects untrusted directories
  CHECK: python -m pytest tests/test_execution_safety.py::TestTrustedExecutableResolution::test_trusted_executable_system_paths_only tests/test_execution_safety.py::TestTrustedExecutableResolution::test_trusted_executable_rejects_writable_dirs -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=291ca455ccd37979a494f2679629fbf56f9c66502af226a5fe01e45364c176aa; exit=0; EXPECT=matched; output-sha256=4a21522df5a28f8c8177f5ef0e2f5f03f0548cbbd67a8f0c0c7222ea5e94dba3; output-bytes=644; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G2: PATH injection attacks are prevented (malicious, relative, empty entries)
  CHECK: python -m pytest tests/test_execution_safety.py::TestPathInjectionProtection::test_path_injection_malicious tests/test_execution_safety.py::TestPathInjectionProtection::test_path_injection_relative_empty tests/test_execution_safety.py::TestPathInjectionProtection::test_path_injection_repo_shadowing -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d0e5a84983893845517aa1633b3fe3602cf4e1626e5dadc95d94bf1f2ac788ae; exit=0; EXPECT=matched; output-sha256=dca2a1ffd4230cce3f20324ff66d188a0c0a7aab5d38bd695c7c8b699a6b7ca2; output-bytes=723; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G3: Wrapper recursion is prevented (self-selection, name collisions)
  CHECK: python -m pytest tests/test_execution_safety.py::TestWrapperRecursionPrevention::test_wrapper_recursion_prevention tests/test_execution_safety.py::TestWrapperRecursionPrevention::test_wrapper_name_collision -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9dd15bede5a3c616365034c3dcd65b464ff672d7458c205cf23e69ba204cfe29; exit=0; EXPECT=matched; output-sha256=553e66c7c6e2ca54a93ad9f5136484e7e943b5e17e790bdb4e38236d5dd5afe8; output-bytes=616; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G4: Dangerous environment variables are sanitized at execution time
  CHECK: python -m pytest tests/test_child_environment.py tests/test_execution_safety.py::TestChildEnvironmentPolicy tests/test_execution_guard.py::test_run_reviewed_command_passes_explicit_child_environment tests/test_wrapper_core.py::TestRunCommandChildEnvironment -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=68e30dee4e6e73343e9b93f9e4a49dc01823cf937819015d629348c456e8ab28; exit=0; EXPECT=matched; output-sha256=5e033ae15f6e0eaa04dce3b8670ae547f61f5c71f5cc145338eaa0c6c9476f68; output-bytes=13051; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G5: TOCTOU limitation documented (executable identity verified at decision time only, not re-verified at execution)
  CHECK: python -m pytest tests/test_execution_safety.py::TestExecutableIdentityVerification::test_executable_identity_verification tests/test_execution_safety.py::TestExecutableIdentityVerification::test_symlink_replacement_protection -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=10ae8ce157f2eae84d643e21ce97e7a03801fae799e1881ae7fe2fc864434324; exit=0; EXPECT=matched; output-sha256=a5542a6a13ef28bfbb55d3071524a751b6b242f65a3d384ffcc7b783b0c4936f; output-bytes=636; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries
  NOTE: Tests document that executable identity is verified at decision time but not re-verified at execution time. This is a known TOCTOU window.

- [x] G6: Approval-executable binding limitation documented (approval not bound to executable identity)
  CHECK: python -m pytest tests/test_execution_safety.py::TestApprovalIntegrity::test_approval_bound_to_executable tests/test_execution_safety.py::TestApprovalIntegrity::test_approval_revalidated_before_exec -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=136df010cc2ef825526ad9bd959235ec6458494110a72b00a109f1b6d2d5f2de; exit=0; EXPECT=matched; output-sha256=d036a4aa3598fd1ee908c2c95b5ada44051202a86635ca285cf730e915401b71; output-bytes=608; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries
  NOTE: Tests document that approval validation does not include executable identity. This is a known limitation.

- [x] G7: No shell=True, no unsafe interpolation, argv preserved in protected execution path
  CHECK: python -m pytest tests/test_execution_safety.py::TestNoShellTrue::test_no_shell_true_in_core tests/test_execution_safety.py::TestArgvPreserved::test_argv_preserved_in_execution -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3a2b6442c783e6a6c410746c9fff49b9ecf19f11939878150e058b3c4bbd8873; exit=0; EXPECT=matched; output-sha256=e4b251ad1485df6b96accd57360bc5d3d8b4856d73776a1597afa190163eec84; output-bytes=586; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G8: All 3A.4 focused tests pass
  CHECK: python -m pytest tests/test_execution_safety.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9aba658600cf189d8ec7f6e3455b2380a01c7650e74ac0711b8007fd17450461; exit=0; EXPECT=matched; output-sha256=587428eedbc63e4a4807f3bae40d2769011e857013027d9479e743f2ffeb0196; output-bytes=3154; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G9: Relevant existing regression tests still pass
  CHECK: python -m pytest tests/test_wrapper_path.py tests/test_wrapper_commands.py tests/test_wrapper_core.py tests/test_wrapper_scanner_integration.py tests/test_execution_guard.py tests/test_repository_scanner.py tests/test_repository_malware_scanner.py tests/test_repository_security_scanner.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b9d00d11b66b78b91d3bda88c00cee96e062d137fedc35ef47296a247a925f64; exit=0; EXPECT=matched; output-sha256=3ca46a4c1acbcd34662582b0d9243fc5202a50090c2cf19600dd6018cc37a4c7; output-bytes=22386; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries