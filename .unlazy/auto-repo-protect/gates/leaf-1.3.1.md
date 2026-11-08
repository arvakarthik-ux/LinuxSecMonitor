# Gates: Security Workflow Design

OWNS: .unlazy/auto-repo-protect/workflow/workflow.md, .unlazy/auto-repo-protect/gates/leaf-1.3.1.md

Scope: Complete security workflow from detection through approval to execution

- [x] G1: Stage 1 - Operation detection documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 1\|Operation Detection" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=da3b430ee03d33d6aca0ccd2904ee95902055907d0c7591cef703ea5d3a57be0; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: Stage 2 - Repository identification documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 2\|Repository.*Identif" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3893a0f3cace312f51271bb9152f57de913d8110b6126ed56d6933cb34cd7657; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: Stage 3 - Path resolution documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 3\|Path.*Resol" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f690f8f845aa229e20b57e18fc5821817d6274bf0f98b57d04202570056f0009; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: Stage 4 - Stable inspection target documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 4\|Stable.*Inspect\|Stable.*Target" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c78229ddf58d1797330d3f9992fad072131880642ccedb76a566c34fa9550b96; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: Stage 5 - Scanner execution documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 5\|Scanner.*Execut" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=95a0503115e99b13b4a4102bbf0a6d9d8e0479d6b971a15c654831e3dab4df07; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: Stage 6 - Dependency/build inspection documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 6\|Dependenc.*Inspect\|Build.*Inspect" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=17a88cb90f07abe952f44058aaa0a5b3c84a4712480ab8dcfbfca70bafb80bf4; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: Stage 7 - Report generation documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 7\|Report.*Generat" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0ff9973f63e9f3d32e838837dc2cafac76a62f3231e1009c1c646cef8294a905; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: Stage 8 - Finding classification documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 8\|Finding.*Classif\|Severity\|Confidence" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=cec2a2e67a7a042b389e8ef5406cd0ef3e3b241938baba30c45706a4efd6514d; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G9: Stage 9 - Explicit approval documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 9\|Explicit.*Approval\|Approval.*Mechanism" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=504d8edae8a0f778e6733ac99dd59c34cab3c68f626e724d901c140be156d8dc; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G10: Stage 10 - Fail-closed blocking documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 10\|Fail-closed\|Blocking" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=41ba4e432d819611d06a7f294088c7b6778700c45b6c4b2a6608e7de17e4f3cb; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G11: Stage 11 - Approved execution documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 11\|Approved.*Execut" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6a0fe637d88aa9ee334b9940e19f9716b9234609a60196d0cc79c9b065e2c8b8; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G12: Stage 12 - Outcome recording documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Stage 12\|Outcome.*Record\|Audit" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=95749875f0eb0a3d9d995b591d1435e7d0255d9486adeeaad52d8eb71015b3c2; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G13: Approval expiration/invalidation documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Approval.*Expir\|Approval.*Invalid\|Invalidation" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=009462d57cc361c8cf5415980663683a81af5fd801130a8068d28f3fad60b40d; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G14: TOCTOU protection summary complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "TOCTOU\|Time-of-Check" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=45fde7d325f012285d65a90876e68de0d52f15494aeec967cf06c077821fb899; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries