# Gates: CLI --review-repository and --safe-run commands

OWNS: main.py, tests/test_main.py

Scope: CLI integrates repository review and safe run with existing APT CLI

- [x] G1: main.py --review-repository <path> runs all three scanners
  CHECK: python -m pytest tests/test_main.py -k "review_repository" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3bc0f0b367aed59773f52785eb0802988744822026229004f737225a389fecc8; exit=0; EXPECT=matched; output-sha256=d9dcbf55d688ca5c01c859a0f344bf26e294e1d2017e997f15ac3b8b22b9829c; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2: --review-repository outputs JSON with --json flag
  CHECK: python -m pytest tests/test_main.py -k "review_repository and json" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c975543684d4099acba509b42638deb0c408a67fc3d1e891968d72c34ec0a066; exit=0; EXPECT=matched; output-sha256=8b5bff64df913f651d4eddca763c772345e4a2eb4ae59c6f30f3d9f1819d8600; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G3: --review-repository outputs text by default with assessments
  CHECK: python -m pytest tests/test_main.py -k "review_repository and text" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5ccafc53061e358cb35d31c4c9dacc89e0007859582fbd38f2964b299b502a46; exit=0; EXPECT=matched; output-sha256=8fd7f6db3bca75d01885f62e5abd2678e2e3b8c4aad399432a5535d4175df83e; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G4: --review-repository --output writes JSON to file
  CHECK: python -m pytest tests/test_main.py -k "review_repository and output" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d6d08bd6bd2183d4adb3cefae4c7f808fa5f1af4a336b3feb7a8804269dc5f3f; exit=0; EXPECT=matched; output-sha256=e8403e45d10717bf28fbe92d88f617184253586141fd0de55f39ca7632ebf4ba; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G5: --review-repository validates path (rejects symlinks, non-directories)
  CHECK: python -m pytest tests/test_main.py -k "review_repository and valid" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=2b67b858af504007978e5f43272067896992f0b139eca6265aadb1538213af42; exit=0; EXPECT=matched; output-sha256=8b5bff64df913f651d4eddca763c772345e4a2eb4ae59c6f30f3d9f1819d8600; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G6: main.py --safe-run <path> <command> reviews then prompts and runs
  CHECK: python -m pytest tests/test_main.py -k "safe_run" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3433e825888d3db9afd208f00f620dae4800ded453277e6ef338ab312112accc; exit=0; EXPECT=matched; output-sha256=dab86f723e834944a311d58e636906c776011384ba98695d22489ee065b3f509; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G7: --safe-run blocks on incomplete scan, detection without approval
  CHECK: python -m pytest tests/test_main.py -k "safe_run and block" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d36b8bc236916b7204f21f154810add799298e3f183c5ab3229c274cd07cd31a; exit=0; EXPECT=matched; output-sha256=8b5bff64df913f651d4eddca763c772345e4a2eb4ae59c6f30f3d9f1819d8600; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G8: --safe-run requires exact RUN approval, fails on CANCEL
  CHECK: python -m pytest tests/test_main.py -k "safe_run and cancel" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=eeba34a898a5005d59d5b6ec3569c52334fd59a35eb3729ad67a416b5660b779; exit=0; EXPECT=matched; output-sha256=8fd7f6db3bca75d01885f62e5abd2678e2e3b8c4aad399432a5535d4175df83e; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G9: --safe-run --json outputs full report including command outcome
  CHECK: python -m pytest tests/test_main.py -k "safe_run and json" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e1981dcd1d789d3ec91017a82c1116ba71aa7b2e9c567bab05516131965482b8; exit=0; EXPECT=matched; output-sha256=8fd7f6db3bca75d01885f62e5abd2678e2e3b8c4aad399432a5535d4175df83e; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G10: --safe-run --output writes JSON to file, rejects paths inside repo
  CHECK: python -m pytest tests/test_main.py -k "safe_run and output" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=013dd4a241ec1437fca19ceff45a00f7714836dabf1b69212de578a055dfcc3a; exit=0; EXPECT=matched; output-sha256=a1c2840ec92fa8cad2c194e59486d1fce1c005b1d3377e8850b2b667b04ee51c; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G11: CLI preserves existing --apt-preinstall-hook and --apt-integration
  CHECK: python -m pytest tests/test_apt_hook_cli.py -q
  EXPECT: 4 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6d613bc1064ecb9d3da472789e10ecaefe29410e6dd9df71851d2c5f1a10e962; exit=0; EXPECT=matched; output-sha256=3cf6c49a7e99b6e1aa60b3eb2b295b5fe359d70adfecbee8d9e048ad10945828; output-bytes=98; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries