# Gates: Explicit approval and cancellation handling

OWNS: scanner/execution_guard.py, tests/test_execution_guard.py

Scope: confirm_execution requires exact RUN; fail-closed on timeout, EOF, interrupt, invalid input

- [x] G1: confirm_execution requires exact "RUN\n" string
  CHECK: python -m pytest tests/test_execution_guard.py -k "exact" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9d96364bcb30a5a14d91ffdc03b5725f347d2d31dc567c2a2215e22323c7728a; exit=0; EXPECT=matched; output-sha256=bba84ba09befb1e7dc6cf7f70450260c63040878cd319b5a69cf4fc09d326011; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: confirm_execution rejects "run\n", "RUN \n", "", "\n"
  CHECK: python -m pytest tests/test_execution_guard.py -k "reject" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7273f6673fc0cd3877772be46b5b54b296dd1eb9de0bbd055e37b5067501e676; exit=0; EXPECT=matched; output-sha256=bfd2a6d893c5d652705ce49efff94a8efe1aecdeb98fa1ade46e22cc57d7887e; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: confirm_execution fails closed on OSError, EOFError, KeyboardInterrupt
  CHECK: python -m pytest tests/test_execution_guard.py -k "interrupt or eof or error" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=574a058f7c2e0d66e6c51c41280672d7b4cfe5e875a8b23729064f862f06534b; exit=0; EXPECT=matched; output-sha256=bd90daaaa8eaa69c6fbc6e4009bf9f066ee4077923a72ccd086d4d0bd46f6a91; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: confirm_execution fails closed when no TTY available
  CHECK: python -m pytest tests/test_execution_guard.py -k "tty" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=214a727d26439e9fa59d7b9f97e0bbc1b2e64c2de84a33ba5a0dcd8ba69692fb; exit=0; EXPECT=matched; output-sha256=8ad13a8af2a7247d51f3b1bb36413ff87205ed2182ea4a3e7d17ad5cba35bcca; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: run_reviewed_command blocks when coverage_complete is False
  CHECK: python -m pytest tests/test_execution_guard.py -k "incomplete" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=2f17f7c8805fc952ab9c37176c62b931c1937dadaa9b3366e5de9c889f7c3bf0; exit=0; EXPECT=matched; output-sha256=bfd2a6d893c5d652705ce49efff94a8efe1aecdeb98fa1ade46e22cc57d7887e; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: run_reviewed_command blocks when review_status is blocked_detection
  CHECK: python -m pytest tests/test_execution_guard.py -k "blocked_detection" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=68e84d0e78f8fcfc458b9e9ab66bdaae2ac95f2130f8cf8e1dcab1ddcb4eb3d6; exit=0; EXPECT=matched; output-sha256=8ad13a8af2a7247d51f3b1bb36413ff87205ed2182ea4a3e7d17ad5cba35bcca; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: run_reviewed_command prompts for RUN when review_complete or review_required
  CHECK: python -m pytest tests/test_execution_guard.py -k "complete or review" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e84f442ac7d337d9c6a8e161e0bda6ebfa88decfcb5f638ab52aaefec425b2c5; exit=0; EXPECT=matched; output-sha256=e8a68de7bbbd7c83680d4e794b8b13e204a0f8df0beafe30269cf1a4780aacb5; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: run_reviewed_command runs argv without shell, in resolved repo directory
  CHECK: python -m pytest tests/test_execution_guard.py -k "argv or shell" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f3e98d0b49c5e68a2e31fd1207211fd237aded422c75a652d47701e19da1f1de; exit=0; EXPECT=matched; output-sha256=bba84ba09befb1e7dc6cf7f70450260c63040878cd319b5a69cf4fc09d326011; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G9: run_reviewed_command returns correct exit code (0=completed, 3=cancelled, 1=error)
  CHECK: python -m pytest tests/test_execution_guard.py -k "exact_approval or cancellation or fails_closed" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=09473e29ffe46e8ebd0bd94ad80bfd2786a7969001774ef13803411c4ef86efb; exit=0; EXPECT=matched; output-sha256=93058c7db127d9b03fc9694027da3e660dded14956be361cff332087d5b3f87f; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G10: run_reviewed_command sets command_status and command_returncode in report
  CHECK: python -m pytest tests/test_execution_guard.py -k "report" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=922bdc0f6b2831a73bcebad36de3e6b1eb226f1e67665cc8eb6cdcc65478da2c; exit=0; EXPECT=matched; output-sha256=bfd2a6d893c5d652705ce49efff94a8efe1aecdeb98fa1ade46e22cc57d7887e; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G11: limitations list documents advisory nature, no sandbox, concurrent writers
  CHECK: python -c "from scanner.execution_guard import review_repository_for_execution; import tempfile; import os; d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, '.git'), exist_ok=True); r = review_repository_for_execution(d); lims = r.get('limitations', []); assert any('advisory' in l.lower() for l in lims); assert any('sandbox' in l.lower() for l in lims); assert any('concurrent' in l.lower() for l in lims); print('Limitations documented')"
  EXPECT: Limitations documented
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1efe76a3a868ef93fd6bba72defaa7a38b9eb302bee1b6e0d36a2932f6c2acd7; exit=0; EXPECT=matched; output-sha256=ffbfe7fc90203148c3aeb5f8b679ed30c7b719f834c0a86486f62f7d72ccac95; output-bytes=23; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries