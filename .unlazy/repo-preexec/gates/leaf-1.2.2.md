# Gates: Fail-closed on incomplete, unavailable, error

OWNS: scanner/execution_guard.py, tests/test_execution_guard.py

Scope: block protected execution when inspection fails, scanners unavailable, incomplete, approval unavailable

- [x] G1: review_repository_for_execution returns blocked_incomplete when inventory scanner fails
  CHECK: python -c "from scanner.execution_guard import review_repository_for_execution; r = review_repository_for_execution('/nonexistent'); print(f'review_status={r.get(\"review_status\")}')"
  EXPECT: review_status=blocked_incomplete
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c17550c55c6321ae991b958e25ac1b4ae0a63f5c62290557462526973c54d63c; exit=0; EXPECT=matched; output-sha256=2948cac2ef827965dea1dcb9c4feb3c4a9d64bc9b72a50df0ec64aaf5578efc4; output-bytes=33; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: review_repository_for_execution returns blocked_incomplete when malware scanner fails
  CHECK: python -c "from scanner.execution_guard import review_repository_for_execution; from types import SimpleNamespace; r = review_repository_for_execution('/tmp', malware_scanner=lambda p: (_ for _ in ()).throw(OSError('fail'))); print(f'review_status={r.get(\"review_status\")}')"
  EXPECT: review_status=blocked_incomplete
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5f6490251c14867889d1bb778a956593f94f4fd10bcdb659729f3366aad187ab; exit=0; EXPECT=matched; output-sha256=2948cac2ef827965dea1dcb9c4feb3c4a9d64bc9b72a50df0ec64aaf5578efc4; output-bytes=33; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: review_repository_for_execution returns blocked_incomplete when security scanner fails
  CHECK: python -c "from scanner.execution_guard import review_repository_for_execution; from types import SimpleNamespace; r = review_repository_for_execution('/tmp', security_scanner=lambda p, **k: (_ for _ in ()).throw(OSError('fail'))); print(f'review_status={r.get(\"review_status\")}')"
  EXPECT: review_status=blocked_incomplete
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=72392588bd4296fbed4d778ad3ba7e70b12ac5910eea7b2611aab96fdd79d7ba; exit=0; EXPECT=matched; output-sha256=2948cac2ef827965dea1dcb9c4feb3c4a9d64bc9b72a50df0ec64aaf5578efc4; output-bytes=33; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: review_repository_for_execution preserves failure category without serializing exception text
  CHECK: python -m pytest tests/test_execution_guard.py -k "exception" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5afbba1f07c95a0f66fb1fff9de9631959ba7884fdbce7cdac537ffb68dbf4e5; exit=0; EXPECT=matched; output-sha256=8ad13a8af2a7247d51f3b1bb36413ff87205ed2182ea4a3e7d17ad5cba35bcca; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: run_reviewed_command blocks on blocked_incomplete even if confirm_execution would succeed
  CHECK: python -m pytest tests/test_execution_guard.py -k "incomplete_scan" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=ff9705757231ec8899a0bc27d5011c4b05a8a628ef4710cde13c925e58729efe; exit=0; EXPECT=matched; output-sha256=8ad13a8af2a7247d51f3b1bb36413ff87205ed2182ea4a3e7d17ad5cba35bcca; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: run_reviewed_command blocks on blocked_detection even if confirm_execution would succeed
  CHECK: python -m pytest tests/test_execution_guard.py -k "malware_detection" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=8f0a5db06a8ef5b9da0c76eadaf4951264ed46ea4f5c7809353006c052320afe; exit=0; EXPECT=matched; output-sha256=8ad13a8af2a7247d51f3b1bb36413ff87205ed2182ea4a3e7d17ad5cba35bcca; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: run_reviewed_command blocks on invalid command (empty or non-string args)
  CHECK: python -m pytest tests/test_execution_guard.py -k "invalid" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4fc0edde353112dfd104794449de5934a8f418d94275508229372211b9ffeadf; exit=0; EXPECT=matched; output-sha256=abeba0375faafe0cf6c8af76be3ddf01f83a017e469112121f1c0aab153dc245; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: run_reviewed_command handles OSError, RuntimeError, ValueError from runner
  CHECK: python -m pytest tests/test_execution_guard.py -k "error_type" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=44eeed55e040a31814175eb2dfb9e5120fdde03f4c6a21779e1d1b1370d37a31; exit=0; EXPECT=matched; output-sha256=abeba0375faafe0cf6c8af76be3ddf01f83a017e469112121f1c0aab153dc245; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G9: report does not include command arguments or secret values
  CHECK: python -m pytest tests/test_execution_guard.py -k "secret" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1b50f3b6e7d49b8f26209cf6dfff914e984c15857a4dc64a735b22a7394a12b5; exit=0; EXPECT=matched; output-sha256=8ad13a8af2a7247d51f3b1bb36413ff87205ed2182ea4a3e7d17ad5cba35bcca; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G10: JSON output mode routes command stdout/stderr to stderr
  CHECK: python -m pytest tests/test_execution_guard.py -k "json" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f6437bb97ab861d4256fad174db09f2d1537b6b166b109b66c5754de3d05aaed; exit=0; EXPECT=matched; output-sha256=8ad13a8af2a7247d51f3b1bb36413ff87205ed2182ea4a3e7d17ad5cba35bcca; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries