# Gates: Scanner Integration - 3A.3

OWNS: src/wrapper/scanners.py, src/wrapper/report.py, src/wrapper/approval.py, src/wrapper/core.py, tests/test_wrapper_scanner_integration.py

Scope: Bounded repository scanning, unified reporting, and content-bound approval

- [x] G1: Inventory, malware, and static security scanners run against one bounded snapshot
  CHECK: python -m pytest tests/test_wrapper_scanner_integration.py::test_scanner_success_and_parallel_limit tests/test_wrapper_scanner_integration.py::test_malware_detection_and_modification_invalidation -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5ba41233805ba6302ccafb7658e00198c1d3b4f4e6ea1f09710308671cf91c00; exit=0; EXPECT=matched; output-sha256=89af43c3b7b5979413f9c74cc162562a910dfbe7621350281e160a294a2402e4; output-bytes=605; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G2: Scanner failure, timeout, and incomplete coverage fail closed
  CHECK: python -m pytest tests/test_wrapper_scanner_integration.py::test_scanner_failure_timeout_and_incomplete -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=43f12319fde2745d8421964e04dc1f845466dbebc4d82514129092df12d50b02; exit=0; EXPECT=matched; output-sha256=2ff9c43c2b27da4769b30728471205c20f7bd7883a25f7142b039b9a27390767; output-bytes=498; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G3: Reports classify findings and redact sensitive evidence
  CHECK: python -m pytest tests/test_wrapper_scanner_integration.py::test_severity_json_and_secret_redaction -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9590a2fd43636db4dffde7cebd91ba60cb7c1a833c208f87bad21da11db82739; exit=0; EXPECT=matched; output-sha256=e063625ba4a2d95139d525b54c1867c45832da2c124c56636fa331b6593eea3f; output-bytes=494; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G4: Approval is exact, fail-closed, single-use, and bound to execution identity
  CHECK: python -m pytest tests/test_wrapper_scanner_integration.py::test_run_approval_single_use_expiry_and_binding tests/test_wrapper_scanner_integration.py::test_approval_cancellation_eof_and_interrupt -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=20ec4e5b62bbae429fd956aba48cf10903f2e62c8a71791e7584b391b1268385; exit=0; EXPECT=matched; output-sha256=fe6b8fa38b84de143ed0d45d36e81327161ccf5527b84a0fa1b0f00605d77979; output-bytes=605; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G5: Wrapper core and existing repository scanner regressions remain valid
  CHECK: python -m pytest tests/test_wrapper_core.py tests/test_wrapper_scanner_integration.py tests/test_execution_guard.py tests/test_repository_scanner.py tests/test_repository_malware_scanner.py tests/test_repository_security_scanner.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5cd2a08fe391c5eab3d673393cc0da4c85ab1a39ce57c09209cf185b347c59a1; exit=0; EXPECT=matched; output-sha256=597b4946fcffb4555fe893ca486d7a3964f6b42541f94032876a7e5b58122a94; output-bytes=15805; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries
