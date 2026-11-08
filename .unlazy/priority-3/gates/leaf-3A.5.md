# Gates: Git Command Integration - 3A.5

OWNS: src/wrapper/commands.py, src/wrapper/core.py, src/wrapper/detection.py, src/wrapper/scanners.py, tests/test_git_integration.py, tests/test_wrapper_commands.py

Scope: Git command classification, clone/checkout workflows, hook/config analysis, approval integration

- [x] G1: Git commands correctly classified (clone, checkout, pull, fetch, merge, rebase, reset, submodule)
  CHECK: python -m pytest tests/test_git_integration.py::TestGitCommandClassification -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=98cb63e5fa599a0b8d16fbaaadb2541d436bced349870399a9946677b720cc67; exit=0; EXPECT=matched; output-sha256=1c060bde761fdc798fea7e0f38b92b52c30b5fcf04880c4a47d8bdc8aefa8018; output-bytes=2725; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G2: Git clone workflow - repository inspected before dangerous operations
  CHECK: python -m pytest tests/test_git_integration.py::TestGitCloneWorkflow -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b7fe26405621a583056d5705ed193924a200e143afb1e9a6cd633bd40cc2c870; exit=0; EXPECT=matched; output-sha256=dc7ff14d32063e29bff8d470323d4fb3f401636be32cef8bb656a6dbbe6ae6dc; output-bytes=689; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G3: Git checkout/switch/branch operations require scan and approval
  CHECK: python -m pytest tests/test_git_integration.py::TestGitCheckoutWorkflow -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3f007e53f3139b120c978a22e38ce63c7e841c954a5fcf2f636df48ba1f5ea0e; exit=0; EXPECT=matched; output-sha256=dd3da8c238b775ac9eea54c73a79360aad6db8fcbe31b236be2e2821b76f2a49; output-bytes=781; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G4: Git hook and configuration analysis integrated with security scanner
  CHECK: python -m pytest tests/test_git_integration.py::TestGitHookConfigAnalysis -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=26ffe0b6ec6a2fd438c2af173d2f079ff239f8193824a4829691005575b1e435; exit=0; EXPECT=matched; output-sha256=823ff0539c7ac62d4351f0461c5e143182898baf8021a0fc5956dff2d1a2eee5; output-bytes=733; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G5: Approval and cancellation work for Git commands
  CHECK: python -m pytest tests/test_git_integration.py::TestGitApprovalCancellation -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=64de2efc0265443cea906b79ee0d0d0da9d437da05153aa2515216c284dc0d01; exit=0; EXPECT=matched; output-sha256=4878671f8ff2d105e198375f51e6a9dc735f2a321467a8cf329491413b85aa4f; output-bytes=713; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G6: Original argv preserved for Git commands
  CHECK: python -m pytest tests/test_git_integration.py::TestGitArgvPreserved -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b6c3c288f5c8a2032ab36ccdf009d03a4a7f098ec90aab181e5a87a8a0ff0049; exit=0; EXPECT=matched; output-sha256=a76222acb6be5461b1799f7da24b0ec3f921544bbfc3bef76b76d4f736298d45; output-bytes=790; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G7: All 3A.5 focused tests pass
  CHECK: python -m pytest tests/test_git_integration.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=837fd999c3cf075ff8dd7a60f74682a4018ea91970b172c4f4add7a812aad27d; exit=0; EXPECT=matched; output-sha256=6a03e752e5af75dff242deba581e409dc6f043a9b0bf0b673a38f0dc96d7fd47; output-bytes=4825; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G8: Relevant existing regression tests still pass
  CHECK: python -m pytest tests/test_wrapper_commands.py tests/test_wrapper_core.py tests/test_wrapper_scanner_integration.py tests/test_execution_guard.py tests/test_repository_scanner.py tests/test_repository_malware_scanner.py tests/test_repository_security_scanner.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f1601871bcd94a1c1c84e556bb2cde77342a3f46ec365247405a4768cefc5562; exit=0; EXPECT=matched; output-sha256=b3eb50f88b1fc78ea75dd08e14b13ae2b089e0b563cba304c6be55878b0713c5; output-bytes=20147; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries