# Gates: Scanner Integration - 3A.3

OWNS: src/wrapper/scanners.py, src/wrapper/report.py, src/wrapper/approval.py, src/wrapper/core.py, tests/test_wrapper_scanner_integration.py

Scope: Bounded repository scanning, unified reporting, and content-bound approval

- [x] G1: Inventory, malware, and static security scanners run against one bounded snapshot
  CHECK: python -m pytest tests/test_wrapper_scanner_integration.py::test_scanner_success_and_parallel_limit tests/test_wrapper_scanner_integration.py::test_malware_detection_and_modification_invalidation -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5ba41233805ba6302ccafb7658e00198c1d3b4f4e6ea1f09710308671cf91c00; exit=0; EXPECT=matched; output-sha256=497966686b65342af6a579512c69f5f24f1ac6b7018d526d677f2d1f5877333b; output-bytes=605; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2: Scanner failure, timeout, and incomplete coverage fail closed
  CHECK: python -m pytest tests/test_wrapper_scanner_integration.py::test_scanner_failure_timeout_and_incomplete -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=43f12319fde2745d8421964e04dc1f845466dbebc4d82514129092df12d50b02; exit=0; EXPECT=matched; output-sha256=fcc87dfbfb129b1bf26dbc1ef70c238019a25fd6116f925f555e3cfd5147f752; output-bytes=498; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G3: Reports classify findings and redact sensitive evidence
  CHECK: python -m pytest tests/test_wrapper_scanner_integration.py::test_severity_json_and_secret_redaction -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9590a2fd43636db4dffde7cebd91ba60cb7c1a833c208f87bad21da11db82739; exit=0; EXPECT=matched; output-sha256=04913386cf6e78be9a3da9e55942fb2cb89f13fc7f0b2a3ffe226f7da7587094; output-bytes=494; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G4: Approval is exact, fail-closed, single-use, and bound to execution identity
  CHECK: python -m pytest tests/test_wrapper_scanner_integration.py::test_run_approval_single_use_expiry_and_binding tests/test_wrapper_scanner_integration.py::test_approval_cancellation_eof_and_interrupt -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=20ec4e5b62bbae429fd956aba48cf10903f2e62c8a71791e7584b391b1268385; exit=0; EXPECT=matched; output-sha256=356c33da2cf9d0d85e6d082ed00f0448da7c6ab7510cb06500c2abe43adffbdc; output-bytes=605; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G5: Wrapper core and existing repository scanner regressions remain valid
  CHECK: python -m pytest tests/test_wrapper_core.py tests/test_wrapper_scanner_integration.py tests/test_execution_guard.py tests/test_repository_scanner.py tests/test_repository_malware_scanner.py tests/test_repository_security_scanner.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5cd2a08fe391c5eab3d673393cc0da4c85ab1a39ce57c09209cf185b347c59a1; exit=0; EXPECT=matched; output-sha256=663fde68b04b3dd8d54f22294b1a76af85a556b3238ef32ddeed0798c543364d; output-bytes=16271; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries
