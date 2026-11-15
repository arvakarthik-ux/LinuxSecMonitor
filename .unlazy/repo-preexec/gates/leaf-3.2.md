# Gates: C9 repository pre-execution end-to-end integration

OWNS: tests/integration/test_repo_preexec.py, tests/test_execution_guard.py

Scope: verify normal and suspicious repository outcomes, approval and cancellation, and incomplete-scan blocking.

- [x] G3.2.1: repository pre-execution integration tests pass
  CHECK: python -m pytest tests/integration/test_repo_preexec.py -q
  EXPECT: /^20 passed in [0-9]+(?:\.[0-9]+)?s \([0-9]+:[0-5][0-9]:[0-5][0-9]\)$/m
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=630efd2defa7b88886feff46cfb28632430a01410d21e596f21b6d7f8c7594b2; exit=0; EXPECT=matched; output-sha256=3a9f38c871f027336b333155edd2cfdda89db9440a50fa5a1546ffc4e810a5e1; output-bytes=111; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries
HISTORY: G3.2.1 CHECK/EXPECT/CWD exactly match node-1.3 N4; its evidence is a crosswalk candidate only and is not credited here.
