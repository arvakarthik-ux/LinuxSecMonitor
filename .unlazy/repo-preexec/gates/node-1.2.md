# Gates: Approval workflow and fail-closed behavior

Scope: verify children leaf-1.2.1, leaf-1.2.2 compose to approve or block execution

- [x] N1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.2.1.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.2.2.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=51be2dcf4d003742ff06f53012e53a27db61d07218996b031a4e1ce0383cb9fd; exit=0; EXPECT=matched; output-sha256=b739f72709cc12552cfdd11db721e758778ace1ce8da87db65a8b4258e8cb881; output-bytes=12353; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N2: explicit RUN approval required; rejects lowercase, trailing space, empty, EOF
  CHECK: python -m pytest tests/test_execution_guard.py -k "approval or cancel" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=90a4e293242aca82446eaebee39e4ab4dbcd002754fa8c512ce8e6c4454f1c27; exit=0; EXPECT=matched; output-sha256=36511713f81b97a9bbbbcf839a1bf509a70f2bcc979baeb319e0fca459165972; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N3: fail-closed blocks on incomplete scan, detection, scanner error, no TTY
  CHECK: python -m pytest tests/test_execution_guard.py -k "incomplete or detection or blocked or tty" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=fbf0e965cf81d5c223dbe6b0e7c21d9b3624d9c0d2c9fbe34eb80316c43e6b41; exit=0; EXPECT=matched; output-sha256=efbe5770941527869461771ac2f2bac9aee2d724f9452ad1faef9b81230e0e14; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N4: command runs without shell, in resolved repo directory, with correct exit code
  CHECK: python -m pytest tests/test_execution_guard.py -k "argv or shell or exit" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e84f659d1720d4adf401ff4851fda06aa0ba84adbc09fbfacc58a78c2365d6b8; exit=0; EXPECT=matched; output-sha256=ad3176147a0bbba664d47349d88cd340268dde08d384189b2fd4b24b90352615; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N5: limitations documented (advisory only, not sandbox, concurrent writers not controlled)
  CHECK: python -c "from scanner.execution_guard import review_repository_for_execution; r = review_repository_for_execution('/tmp'); assert 'advisory' in str(r['limitations']).lower(); assert 'sandbox' in str(r['limitations']).lower(); print('Limitations documented')"
  EXPECT: Limitations documented
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=cadf320b7d7f5d6127c5bc9e3b80abe6d06649460b29114174c108f51010b83d; exit=0; EXPECT=matched; output-sha256=ffbfe7fc90203148c3aeb5f8b679ed30c7b719f834c0a86486f62f7d72ccac95; output-bytes=23; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries