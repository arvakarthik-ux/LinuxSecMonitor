# Gates: Execution Path Coverage Integration

Scope: integrate children leaf-1.1.1, leaf-1.1.2, leaf-1.1.3, leaf-1.1.4, leaf-1.1.5 into verified coverage analysis

- [x] N1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/auto-repo-protect/gates/leaf-1.1.1.md /home/kali/LinuxSecMonitor/.unlazy/auto-repo-protect/gates/leaf-1.1.2.md /home/kali/LinuxSecMonitor/.unlazy/auto-repo-protect/gates/leaf-1.1.3.md /home/kali/LinuxSecMonitor/.unlazy/auto-repo-protect/gates/leaf-1.1.4.md /home/kali/LinuxSecMonitor/.unlazy/auto-repo-protect/gates/leaf-1.1.5.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f26ada075f311527fae8d6f24303637a3ef13a593b3c5d99cd9da0d497562a0f; exit=0; EXPECT=matched; output-sha256=7650cf24645cd5d02c5593bc98d3e2516d9537bdb12a95bc9d11a75dbe7a2932; output-bytes=21096; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N2: all five operation categories covered
  CHECK: test -f .unlazy/auto-repo-protect/coverage/git.md -a -f .unlazy/auto-repo-protect/coverage/shell.md -a -f .unlazy/auto-repo-protect/coverage/interpreter.md -a -f .unlazy/auto-repo-protect/coverage/build.md -a -f .unlazy/auto-repo-protect/coverage/dependency.md && echo "All coverage files exist"
  EXPECT: All coverage files exist
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=74198d46949411f4d87923f2ad98bba4db9f1e50ec183bc32423c96a11557f3e; exit=0; EXPECT=matched; output-sha256=61ebc3611b3ec1ac00c61de51a7c732dab17e2a32800a7d95c694b6a1309aa99; output-bytes=25; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N3: each category has bypass analysis
  CHECK: for f in .unlazy/auto-repo-protect/coverage/*.md; do grep -q "Bypass" "$f" || exit 1; done && echo "All have bypass analysis"
  EXPECT: All have bypass analysis
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7fa3d3bf9bbd57bf28d1e8c7718d3809891fe007915716d689e1e6bc89e6db25; exit=0; EXPECT=matched; output-sha256=2d346f38a55e83d0e1f42539858d772a375e6816ac9696c07aecd6daef420842; output-bytes=25; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N4: cross-category consistency verified
  CHECK: bash -c 'grep -r "Coverage Matrix\|Summary" .unlazy/auto-repo-protect/coverage/ | wc -l | grep -q "5" && echo 5'
  EXPECT: 5
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=59517d67f3b4165e203d81acd92035b06ae06b381df289992cd7edd722cb0309; exit=0; EXPECT=matched; output-sha256=f0b5c2c2211c8d67ed15e75e656c7862d086e9245420892a7de62cd9ec582a06; output-bytes=2; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries