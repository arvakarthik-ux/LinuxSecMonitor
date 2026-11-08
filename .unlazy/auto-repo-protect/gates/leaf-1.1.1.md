# Gates: Execution Path Coverage - Git Operations

OWNS: .unlazy/auto-repo-protect/coverage/git.md, .unlazy/auto-repo-protect/gates/leaf-1.1.1.md

Scope: Analyze all Git operations for interception feasibility, inspection timing, and bypasses

- [x] G1: git clone coverage documented with inspection timing and bypasses
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/git.md && grep -q "git clone" .unlazy/auto-repo-protect/coverage/git.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=73fabd4b1c197155ee6b9a106055e3cd713c95fabb2918bf6853e596bf22e71c; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: git pull/fetch/merge coverage documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/git.md && grep -q "git pull\|git fetch\|git merge" .unlazy/auto-repo-protect/coverage/git.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c5281b4b38e4e8415cca5197550d049b0d2774e0b575938da9a60154327e1124; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: git checkout/switch coverage documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/git.md && grep -q "git checkout\|git switch" .unlazy/auto-repo-protect/coverage/git.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=640ea94eca37941ecb4e6601e1fd75973fab449bff6f8b86624607f09ed427cd; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: git submodule coverage documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/git.md && grep -q "git submodule" .unlazy/auto-repo-protect/coverage/git.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=926594abffce9e7139e3fd80ba52e70d7fb9d316326085c963d28b795c925799; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: Bypass analysis for Git operations complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/git.md && grep -q "Bypass" .unlazy/auto-repo-protect/coverage/git.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=31b88947bc1010b8c1af279acf900fa8380c111d695d7805efa67b3d0c7bb631; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: Coverage matrix includes Git operations
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/git.md && grep -q "Coverage Matrix\|Summary" .unlazy/auto-repo-protect/coverage/git.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a552a6f494fd6e39ff3ffa63d9cf708da803dee0b6322864e4689c93ecc44415; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries