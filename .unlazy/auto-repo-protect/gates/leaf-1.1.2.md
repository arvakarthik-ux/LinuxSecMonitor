# Gates: Execution Path Coverage - Shell Execution

OWNS: .unlazy/auto-repo-protect/coverage/shell.md, .unlazy/auto-repo-protect/gates/leaf-1.1.2.md

Scope: Analyze all shell execution patterns for interception feasibility, inspection timing, and bypasses

- [x] G1: Direct script execution (./script.sh, bash script.sh) covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/shell.md && grep -q "\./install\.sh\|bash install\.sh" .unlazy/auto-repo-protect/coverage/shell.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=abf57b0aaaf16acd6894ffccd0abc8008624b74610952d874b8d3495302d1783; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: Inline shell (bash -c, sh -c) covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/shell.md && grep -q "bash -c\|sh -c" .unlazy/auto-repo-protect/coverage/shell.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=52cb30df60ea1f128ae116c86f8455854fcee8746dbc9025bd6c119bb561c8cc; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: Pipeline to shell (curl | bash) covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/shell.md && grep -q "curl.*|.*bash\|wget.*|.*sh" .unlazy/auto-repo-protect/coverage/shell.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a7c8352b3adc9de71f258f2023e822ef8e4a7e9e432e3bb0d18bc8dbf2e113f1; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: Source/eval built-ins covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/shell.md && grep -q "source\|eval\|\. install" .unlazy/auto-repo-protect/coverage/shell.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3b274b6f34967443edc06442c38bec58fc4fc8265ee0c80e64ea98e02ada1dec; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: Alternate shells (zsh, fish, ksh) covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/shell.md && grep -q "zsh\|fish\|ksh" .unlazy/auto-repo-protect/coverage/shell.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=02b2b5743cbc2c7d10b2ebd5f4c503c0014a696659021d6fdae884f6a46fae15; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: Non-interactive shells covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/shell.md && grep -q "non-interactive\|cron\|systemd" .unlazy/auto-repo-protect/coverage/shell.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=abf5dd41f93d99d68444e81a5a5fe8dd227ed81cbd0feeb886583839aa61f170; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: Bypass analysis for shell execution complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/shell.md && grep -q "Bypass" .unlazy/auto-repo-protect/coverage/shell.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=bc9b9872b37d3c54e4cb4c6a49307b9d32d208b41dd439d77bf4e800b2577b53; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: Coverage matrix includes shell operations
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/shell.md && grep -q "Coverage Matrix\|Summary" .unlazy/auto-repo-protect/coverage/shell.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9bef08acedb5a59f04f7a0a993f6edf8db634a3c4af5676898d470c0945b4c2f; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries