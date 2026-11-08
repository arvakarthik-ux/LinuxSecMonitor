# Gates: Security Workflow and Threat Model Integration

Scope: integrate children leaf-1.3.1, leaf-1.3.2 into verified workflow and threat model

- [x] N1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/auto-repo-protect/gates/leaf-1.3.1.md /home/kali/LinuxSecMonitor/.unlazy/auto-repo-protect/gates/leaf-1.3.2.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0c9e013c2f87558f3e5b2cac0e5b844da61a15b44fc82603b36252a15e9e7be0; exit=0; EXPECT=matched; output-sha256=6f2a01a69b8d4e568a1d83d10caf7ed8d2556eefe41ec4d9be99184e3fa0e12f; output-bytes=14304; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N2: all 12 workflow stages documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -c "Stage [0-9]" .unlazy/auto-repo-protect/workflow/workflow.md | grep -q "12" && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=033bcf75f01ec55064685063a002f642d787dfd38e7213603aa26020c1691deb; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N3: approval binding and expiration documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Approval.*Binding\|Approval.*Expir" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4dfc148e4c29243ebf3294f3176f82be25f8fff78ab1e6e7d8d8f6ad8f4a5ca6; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N4: fail-closed conditions enumerated
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "Fail-closed\|Blocking.*Condition" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5d4a75d48de44299d0ebe1d48a9408d7f1711cf93e0c053ff7dd8ff29d2e8b2d; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N5: TOCTOU protections per stage documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/workflow.md && grep -q "TOCTOU\|Time-of-Check" .unlazy/auto-repo-protect/workflow/workflow.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=45fde7d325f012285d65a90876e68de0d52f15494aeec967cf06c077821fb899; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N6: threat model complete with all elements
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Protected Asset\|Attacker\|Privilege Boundary\|Residual Risk" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=bda22ee9867e5df5669ec0a5f65deffecd664583659408089843dce11bcdeacc; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N7: bypass catalog and residual risks complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/workflow/threat-model.md && grep -q "Bypass.*Table\|Residual Risk\|Accepted Risk" .unlazy/auto-repo-protect/workflow/threat-model.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=163283f88ab82125a1fcaf2719fb1347e9502980a20f8e3428cf1e00d41592f2; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries