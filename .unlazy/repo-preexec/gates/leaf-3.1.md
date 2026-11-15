# Gates: C8 CLI integration with existing APT CLI

OWNS: main.py, tests/test_main.py

Scope: verify the repository-review and safe-run CLI paths while preserving the existing APT CLI.

- [x] G3.1.1: --review-repository dispatches all three repository scanners
  CHECK: python -m pytest tests/test_main.py -k "review_repository" -q
  EXPECT: /^6 passed, [0-9]+ deselected in [0-9.]+s$/m
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9883f5512af38c47ab886626370b239410465b5d326cd6a7545d641fe95e06ef; exit=0; EXPECT=matched; output-sha256=9ef4c663301d776b3a5db8d9bb0f28b0873efaf8fd26c7ab82989389949ab8e6; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries
HISTORY: G3.1.1 CHECK/EXPECT/CWD exactly match leaf-1.3.1 G1; its evidence is a crosswalk candidate only and is not credited here.

- [x] G3.1.2: --safe-run works and existing APT CLI dispatch remains available
  CHECK: python -m pytest tests/test_main.py -k "safe_run or apt_integration or apt_preinstall_hook_cli" -q
  EXPECT: /^11 passed, [0-9]+ deselected in [0-9.]+s$/m
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b7785ab45e7c2aeb4057af24bcf748f018184c3550ac97d06c1549a2d8832526; exit=0; EXPECT=matched; output-sha256=e92e16ccec63755cf78d69adbbc152ed8a0b047908c884ccbf06d88de2e69da4; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries
