# Gates: Recommended Architecture

OWNS: .unlazy/auto-repo-protect/architecture/recommendation.md, .unlazy/auto-repo-protect/gates/leaf-1.2.2.md

Scope: Document recommended architecture with implementation details

- [x] G1: Architecture summary with key principles
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Executive Summary\|Architecture Summary\|Key Principle" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=2ea7b12cd1cd00230c85c8679549534e6f8f7596c86b38f935d29b798dbb9323; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: Existing component reuse documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Existing.*Component\|Reused\|Priority 1" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=59a1e565f2d3e654bd4eaff2e205ae22a72d5d4727736af5842831d02d0ad0bd; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: Wrapper framework design complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Wrapper Framework\|wrapper" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=34ffbcd979eb9bdd8728ed012bbaa7a1c5ecdc8cf0427cff6005578acf98aa67; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: Repository detection design complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Repository Detection\|repo.*detect" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6407d562aab9ddfe9257a336f0f8cf18a64978a8a4079f0d5b0fe864f0b90057; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: Dangerous command classification design complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Dangerous.*Command\|Command.*Tier\|Tier 1\|Tier 2\|Tier 3" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c6b4f388d8fef9e0a1d9daa03515e7ed25ca25f73c83b3fc60df355ee8c7dc08; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: Scanner integration design complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Scanner Integration\|Scan Pipeline" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3650de22c35a9beb63797d4fac8f1213a2943448fc414dc2a0ad8717e24a162d; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: Approval flow design complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Approval Flow\|approval" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a5fc0520a2809aa60931be568b0a2d682d949e8abac7dd4840639187271fd81c; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: Execution guard integration documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Execution Guard\|execution_guard" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3531bc02039a33e50e72591271a4dec6edb0de0722a5ddebb5549f7c14942e0c; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G9: Explicit CLI documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Explicit CLI\|--safe-run\|--review-repository" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3b68611629728a80e0fc92b8e2659a46722b980441fcfd437183c7e02bc9b84c; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G10: Configuration design complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Configuration\|config" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b40003a8252d66f9cd61949f24e0f5cb723fc5b813e0612d1b26deeac4d753cd; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G11: Installation design complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Installation\|--install-wrappers" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0a454af0347dc9033543536a260600699eba002d688ccc770bdb23d8c024ab12; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G12: Bypass documentation complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Bypass.*Document\|Documented.*Bypass" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=af79cc6d29db3a7196ab58f29a7a81732a9dd453cfe8432d6fab602e17b2bb4c; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G13: Security considerations documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Security Consider\|What.*Protect\|What.*Not Protect" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d58220482397615d8d1d859bd8cf55df17e235a833c75e9f4027a98a15794e7c; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G14: Future enhancements listed
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Future Enhance\|Post-Priority" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=727a866c95bd166c2a8be7d8bbee22246c8d99d10e63589c1ec1e411e3912e4d; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries