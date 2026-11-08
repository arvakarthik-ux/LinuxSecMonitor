# Gates: Execution interception and CLI integration

Scope: verify children leaf-1.3.1, leaf-1.3.2, leaf-1.3.3 compose for CLI and integration

- [ ] N1: every named direct child is reverified from its exact ledger (node-1.3 has handoff for disposable guest verification)
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.3.1.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.3.2.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.3.3.md
  EXPECT: HANDOFF REQUIRED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: pending

ABANDON: N1 Child leaf-1.3.3 has abandoned gate (disposable guest verification requires physical infrastructure). Branch marked as having handoff.

- [x] N2: CLI --review-repository runs all three scanners and outputs JSON/text
  CHECK: python -m pytest tests/test_main.py -k "review_repository" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3bc0f0b367aed59773f52785eb0802988744822026229004f737225a389fecc8; exit=0; EXPECT=matched; output-sha256=48521f1496f14f9b43b149a249f02d632e876ba5a103a90b0d43102ec3a7d0f0; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N3: CLI --safe-run reviews then prompts and runs argv command
  CHECK: python -m pytest tests/test_main.py -k "safe_run" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3433e825888d3db9afd208f00f620dae4800ded453277e6ef338ab312112accc; exit=0; EXPECT=matched; output-sha256=f79a45a916d8937f849713e910a7438720eee96a501fc6824651c405d1ea04ae; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N4: end-to-end normal repo runs, suspicious repo flagged, approval/cancel works
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0760438cbd988c21e8262de2a7f22addf1b1c84ff9076f53637cc0ead5c11524; exit=0; EXPECT=matched; output-sha256=5bb6b7ed11944d24e3dff038cce8268951ead8609270d27dbe9d3728fef23303; output-bytes=110; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N5: APT regression preserved (all 5 acceptance scenarios still pass)
  CHECK: python -m pytest tests/test_apt_hook.py tests/test_apt_lifecycle.py tests/test_apt_hook_cli.py -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6fb570be914e8980727f74b2ddb27ecaebe136afa4939f8d36ab217222df0f2d; exit=0; EXPECT=matched; output-sha256=521a02f2db7cb1bc5e4765c860259adf6c1cd834e86f92770e8bf5021db68bf3; output-bytes=180; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries