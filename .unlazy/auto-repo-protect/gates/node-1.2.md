# Gates: Enforcement Architecture Evaluation Integration

Scope: integrate children leaf-1.2.1, leaf-1.2.2 into verified architecture evaluation

- [x] N1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/auto-repo-protect/gates/leaf-1.2.1.md /home/kali/LinuxSecMonitor/.unlazy/auto-repo-protect/gates/leaf-1.2.2.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=289958b6e2e834a1f6d6e27cecd863a6d38b1295e42f578f4df2d64997ee97f3; exit=0; EXPECT=matched; output-sha256=b681521b8148ac9ed4b4af0c0c642e3563eda0c7f7b4b4621ac198bd6e8ff028; output-bytes=13163; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N2: mechanism comparison complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "Comparison Matrix" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1aa18d9e0e031d4c06b45d198521f02a47760650916683dc5cceeb1d19f4bb1c; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: recommended architecture documented with rationale
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/recommendation.md && grep -q "Recommend\|Recommended" .unlazy/auto-repo-protect/architecture/recommendation.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=10bad29ef6fb8f4b1c44450ee508518e39356cc5855dbb7f3a57821afa414bab; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N4: rejected alternatives documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/architecture/comparison.md && grep -q "Reject\|Alternative" .unlazy/auto-repo-protect/architecture/comparison.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5ff7f154e588355d5db2a91ef6ac8e9b268d3ba85af8eed15521826bd6e1a077; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries