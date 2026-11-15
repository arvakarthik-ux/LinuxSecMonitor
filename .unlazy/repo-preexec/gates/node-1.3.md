# Gates: Execution interception and CLI integration

Scope: verify children leaf-1.3.1, leaf-1.3.2, leaf-1.3.3 compose for CLI and integration

- [x] N1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.3.1.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.3.2.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.3.3.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=94878ea98aa39f94bcfddff00e25ab5404262a995dbf90bd06f26bbad5cd86ac; exit=0; EXPECT=matched; output-sha256=3dbd613958a6b2ec35f69ab7244e8f588e96ce3e4cc4a2d8b1bbcd485236beda; output-bytes=17471; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

HISTORY: Previous N1 wording before revision-3 child verification (preserved verbatim): every named direct child is reverified from its exact ledger (Kali 2026.3 guest verification is pending); EXPECT: HANDOFF REQUIRED

HISTORY: Original active node abandonment record (verbatim; non-operative only for the authorized revision 2 fresh-verification cycle): ABANDON: N1 Child leaf-1.3.3 has abandoned gate (disposable guest verification requires physical infrastructure). Branch marked as having handoff.

- [x] N2: CLI --review-repository runs all three scanners and outputs JSON/text
  CHECK: python -m pytest tests/test_main.py -k "review_repository" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3bc0f0b367aed59773f52785eb0802988744822026229004f737225a389fecc8; exit=0; EXPECT=matched; output-sha256=b484923c8d46698aca1ba0f98c7d1cfc709ca7c225d57d9552500221eddf8951; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N3: CLI --safe-run reviews then prompts and runs argv command
  CHECK: python -m pytest tests/test_main.py -k "safe_run" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3433e825888d3db9afd208f00f620dae4800ded453277e6ef338ab312112accc; exit=0; EXPECT=matched; output-sha256=648237dac2d2dae7b1e5718e454862081cf68087f34f225ce08f40773dd893dd; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N4: end-to-end normal repo runs, suspicious repo flagged, approval/cancel works
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0760438cbd988c21e8262de2a7f22addf1b1c84ff9076f53637cc0ead5c11524; exit=0; EXPECT=matched; output-sha256=7e73a5eb452de6d8e49a43e7d4aedd74004969915dfe6dcc8c3109d29c04614d; output-bytes=110; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N5: APT regression preserved (all 5 acceptance scenarios still pass)
  CHECK: python -m pytest tests/test_apt_hook.py tests/test_apt_lifecycle.py tests/test_apt_hook_cli.py -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6fb570be914e8980727f74b2ddb27ecaebe136afa4939f8d36ab217222df0f2d; exit=0; EXPECT=matched; output-sha256=66594d8f725aabafe6e46f0a9f0208d74b5b3f9b06160e1883d0f3c6b3b45386; output-bytes=180; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries