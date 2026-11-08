# Gates: End-to-end integration tests

OWNS: tests/integration/test_repo_preexec.py, tests/test_execution_guard.py

Scope: normal repo runs, suspicious repo flagged, approval/cancel works, incomplete blocks

- [x] G1: integration test for normal repository (no findings) completes with review_complete
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -k "normal" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5fe5a6e9bb59f44848d8499afcd70c432e6227d2947f38e8defcd7c2005dd9c5; exit=0; EXPECT=matched; output-sha256=11d2953096311e23bfcfc4c3a5ade9d6ea745d254befce946ea96d5ce54a6789; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: integration test for suspicious repository (risky commands) returns review_required
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -k "suspicious" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f10132428b552cb28bc5757328c3a93f0ff6212c11558c26e888c7f4c5c6fdaf; exit=0; EXPECT=matched; output-sha256=11d2953096311e23bfcfc4c3a5ade9d6ea745d254befce946ea96d5ce54a6789; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: integration test for malware detection returns blocked_detection
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -k "malware" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=56d897de38425e51c63f0fc7d23578e75a595fbfb12641e9657e693f7d59b478; exit=0; EXPECT=matched; output-sha256=b288428c4567099945ee264537f67fb6c066e3ec2fcca73e60224c0f040de0e3; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: integration test for incomplete scan returns blocked_incomplete
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -k "incomplete" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a0c9ede4bcff53d94e64f37e665dd51d69cb8b44a45db3189f5037b53f2e0ea9; exit=0; EXPECT=matched; output-sha256=d9b34b2ecce18c90de172cb38c010cfd7aad1176bdee78fd7bab5c13cfe38f89; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: integration test for approval (RUN) runs command and returns completed
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -k "approval_runs_command" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0f1275ae666beb0b0a834169089affcfe17e5af749eb095dc2fb253ffb44a1ae; exit=0; EXPECT=matched; output-sha256=b6f173232a3b1fcefcc38e140a80dd7d335731c3ba669883fa863abdd812616e; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: integration test for cancellation (CANCEL) returns cancelled, command not run
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -k "cancel" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=237dc64560d1e7156e60c095f1507970ccf40dc41f134c68e1d624a20ce34af0; exit=0; EXPECT=matched; output-sha256=17e91e797564ea090348e641c82fdfc1f0ee2f8b065584d6421381020fec75f7; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: integration test for bypass attempts (alternate shell, direct interpreter) documented
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -k "subprocess_execution_prevention" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6ef7f65cbb9da2ef96442adb3b0c098ba6459f0a93aec01e59970ad4f88eee5a; exit=0; EXPECT=matched; output-sha256=11d2953096311e23bfcfc4c3a5ade9d6ea745d254befce946ea96d5ce54a6789; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: integration test for symlink traversal prevention
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -k "symlink" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0f44aae0da3fc3a11071038b6a1db11f3efffa9d06d445ba677219e159befd52; exit=0; EXPECT=matched; output-sha256=bd00753293631a81f74727ea17f9c7a8bbcf8d3eb1db9c226253ceaf1cb2b656; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G9: integration test for subprocess/nested command execution prevention
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -k "subprocess" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=03f3bf71b9c13e31264a1c463773ad1902e50675b21ebba26ac7cdb3a36bd326; exit=0; EXPECT=matched; output-sha256=11d2953096311e23bfcfc4c3a5ade9d6ea745d254befce946ea96d5ce54a6789; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G10: integration test for resource exhaustion (timeout, large repo) handled
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -k "timeout or resource" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d4f0e7a90d0b0d22a1b24a1fe26c34bc651a80c672117abf76440957a286b4c2; exit=0; EXPECT=matched; output-sha256=1ac1ba28b4e0c1d10dad8cbbc2a24e46d967dcaeae055f5849dce880c4b893c0; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G11: integration test for scanner executable path resolution (trusted path, not PATH)
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -k "trusted" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1a44b7dc8dac3e38ff038e3897cf7e8285c2c4edb544ff3b0b6b5d3b24653a08; exit=0; EXPECT=matched; output-sha256=b288428c4567099945ee264537f67fb6c066e3ec2fcca73e60224c0f040de0e3; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries