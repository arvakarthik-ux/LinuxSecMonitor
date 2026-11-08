# Gates: Enforcement Architecture Comparison

OWNS: .unlazy/auto-repo-protect/architecture/comparison.md, .unlazy/auto-repo-protect/gates/leaf-1.2.1.md

Scope: Compare all enforcement mechanisms with criteria and recommend one

- [x] G1: Shell hooks mechanism evaluated
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "Shell.*Hook\|Shell Hook" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=fe09d7aeaaaa6d0a044abf41b61d9ca6d4e1d77ab1357d881b7d2687169a4979; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: PATH wrappers mechanism evaluated
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "PATH.*Wrapper\|PATH Wrapper" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=ce8955b2a82550b2d441ce9c5a2854ec723da6e7ded3f154ed7fa20349151f72; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: Git hooks mechanism evaluated
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "Git.*Hook\|Git Hook" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=bb6fe81d8db7c35f336ce4f58c6303a5b7ea043fd50e760f9b73723a71af4ff5; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: Package manager wrappers mechanism evaluated
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "Package.*Manager.*Wrapper\|PM.*Wrapper" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=be242357443663fdf0b51675e7f3117476ec299c9dfd607d4f6acec64fb3a460; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: Central daemon mechanism evaluated
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "Central.*Daemon\|Daemon" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c3f2683b7ca406ad869966ac7785a55860992d816f23cb7adfaf1c19f68a076f; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: LSM/eBPF mechanism evaluated
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "LSM\|eBPF" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0c291ec76624490142d2d2d1bdf2afc611b8c62b265cd86eb2a08f1516c9a9f1; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: Systemd/container mechanism evaluated
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "systemd\|container" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=dbbb925b784d0f5a549d4c864cae667a3ad2a4cb81cb71d81e3ebaf9475540bd; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: Comparison matrix with all criteria complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "Comparison Matrix\|Criteria" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=32886cb3f6888d27e67b608b2da75b567dec94f200f527a968e420984d20f3f6; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G9: Recommendation with rationale documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "Recommend\|Recommended" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b7d4f0ac4c7f96b00df97956a2903bf3a595c199523625d17e1258687064a258; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G10: Rejected alternatives documented with reasons
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "Reject\|Alternative" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5ff7f154e588355d5db2a91ef6ac8e9b268d3ba85af8eed15521826bd6e1a077; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries