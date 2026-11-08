# Gates: Threat Model

OWNS: .unlazy/auto-repo-protect/workflow/threat-model.md, .unlazy/auto-repo-protect/gates/leaf-1.3.2.md

Scope: Document threat model with assets, actors, bypasses, and residual risks

- [x] G1: Protected assets enumerated
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Protected Asset\|Asset.*Table" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b7c19f9b3f710cb03ddf7d9dcb60bf45140161c273bcb91033fe0e69fc51644e; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: Attacker capabilities defined
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Attacker.*Capab\|Threat Actor" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b9e9c2d52c7da9d15fea8b0b10dcec32cd72de4b75c532ef4237b5c71122c60b; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: Untrusted repository assumptions documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Untrusted.*Repository\|Repository.*Assumption" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7fa56512c3f213ea852419614aa26e08a2581889aa45e1e840f3752d4a789465; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: Privilege boundaries diagrammed
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Privilege.*Boundar\|Boundary.*Diagram" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a8c2da5e2d7a4bb5412abcfa47940101cba12d53eaafe12b9db7a7e8c4522d3e; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: Trusted components listed
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Trusted.*Component\|Component.*Trust" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=645788676abf6ad4e105eb9a4171c3d7fbcf6f7c33673642cb71c28eabb41474; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: Root/admin limitations documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Root.*Limitation\|Admin.*Limitation\|Root.*Cannot" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e7ced320b3d859a2292fe31fae9ee150fc91313534e3d0ec050e7e112a4885ac; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: Concurrent modification risks documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Concurrent.*Modif\|TOCTOU" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=2c12ff8f67c741b93125e78de30e86964f81f1f4df9e9a07773ad4caceb5f8c1; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: Execution bypasses catalogued
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Execution.*Bypass\|Bypass.*Table\|Bypass.*Catalog" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d106704933bf66d0a918cde6730b67a21a92ae076d7862a1af59f20a9002330d; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G9: Scanner compromise risks documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Scanner.*Compromise\|ClamAV\|Scanner.*Risk" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=208a00b0dc5d0c563ef09fbf71c3ec9c0a456947923d7ab7b1824f804acb911e; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G10: Residual risks table complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Residual.*Risk\|Risk.*Table\|Accepted Risk" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f6b7759a01937a63bbef4c2e68fb1920ed7d3474107d131be7ae57fc2aca6397; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G11: Security assumptions listed
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Security.*Assumption\|Assumption" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=337a4252cc7e65b8e7f01af83fec7c959a28abfc667d48496a178e96d5b607b1; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G12: Threat model summary complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Threat Model.*Summary\|Summary.*Table" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d30b7d28ec7117a1e5dc7b0f7b7311dc08c8dbba7bbdf0c1df2576a7806207de; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries