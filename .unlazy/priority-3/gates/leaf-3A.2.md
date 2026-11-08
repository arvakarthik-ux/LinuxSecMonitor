# Gates: Shell Integration - 3A.2

OWNS: src/wrapper/install.py, src/wrapper/path.py, src/wrapper/config.py, tests/test_wrapper_install.py, tests/test_wrapper_path.py, tests/test_wrapper_config.py

Scope: Implement shell integration for wrapper installation, PATH management, and TOML configuration

- [x] G1: Installs wrappers to ~/.local/bin/ and updates shell RC
  CHECK: python -m tests.test_wrapper_install test_bash_install test_zsh_install test_fish_install
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7dc9de8b9cd0c153377f25f6358c9f86d7366de0fe062dc7e035e6addb523612; exit=0; EXPECT=matched; output-sha256=a1711bb0401395e4493b6a416a6b3550e49cfd7241400c16148936d7129d5f17; output-bytes=3014; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: Works for bash, zsh, fish
  CHECK: python -m tests.test_wrapper_install test_all_shells_supported
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=2bddf5dc99ac8f821a2f4fb35c45fa646ee66fe24dc1e3a74c55abcaf5105c02; exit=0; EXPECT=matched; output-sha256=09a66564eb72a58c1f3652c45e67d0679d6e985410df280a6dcf53a79874a8f6; output-bytes=3014; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: Config file parsed correctly
  CHECK: python -m tests.test_wrapper_config test_valid_toml test_invalid_toml test_defaults
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=548749abaf94a275536fdd4f3d193e94e131fc97ad2ecd21010d1549a4b9e749; exit=0; EXPECT=matched; output-sha256=4d5e63a37e76c2ec5e95bc01927b79da3f948c0323736dd9ef130c34698e734f; output-bytes=2683; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: Uninstall removes all traces
  CHECK: python -m tests.test_wrapper_install test_uninstall_removes_all
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=cf2c8bd46173448461e380c4985b104279396b5b0e69d9efd0339711315428e2; exit=0; EXPECT=matched; output-sha256=4f10bd5ff8194a840f1cbb3c7342d68b1a3d105e41106c78958743f7a21669d0; output-bytes=3014; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: PATH resolution and wrapper recursion prevention
  CHECK: python -m tests.test_wrapper_path test_path_precedence test_recursion_prevention test_trusted_executable
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=26b55b6ffd11b7c6dfae385d9c57d6d1db6557f76316d8b796d18b23f839be56; exit=0; EXPECT=matched; output-sha256=61dfe77c81b191ac09ca77bdef7f08af0e67a443be77046a85ba36259f8f4f97; output-bytes=2638; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: Safe backup and recovery
  CHECK: python -m tests.test_wrapper_install test_backup_and_recovery
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=40fe5db364b6e7f82f7a941530053f5fd249a7b5d1761a47a0535d7991e72254; exit=0; EXPECT=matched; output-sha256=4f10bd5ff8194a840f1cbb3c7342d68b1a3d105e41106c78958743f7a21669d0; output-bytes=3014; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: Dry-run and idempotent installation
  CHECK: python -m tests.test_wrapper_install test_dry_run test_idempotent
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=48e06566064e20c978676e327aee954152661ad5ae6733ffb3389ed8ed35ace4; exit=0; EXPECT=matched; output-sha256=74cb3c7692492174137fa4dd9da87bf5ab741d92146002a62c87187863eb05f1; output-bytes=3014; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: All 3A.2 focused tests pass
  CHECK: python -m pytest tests/test_wrapper_install.py tests/test_wrapper_path.py tests/test_wrapper_config.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b9e98bde0020df3b7ace905488aa6c05a64d33e995a03d19d417a03f001095bb; exit=0; EXPECT=matched; output-sha256=35db028e69f0ca9451b89f5f68516bff9a9f7833e3439b39ac60048e436d7bf1; output-bytes=7537; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G9: Relevant existing regression tests still pass
  CHECK: python -m pytest tests/test_execution_guard.py tests/test_repository_scanner.py tests/test_repository_malware_scanner.py tests/test_repository_security_scanner.py tests/test_wrapper_core.py tests/test_wrapper_commands.py tests/test_wrapper_detection.py tests/test_wrapper_cache.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f8c11e129549eb0d75c9d8d9af28892af8797f9c8614dcbfb51011098cc85095; exit=0; EXPECT=matched; output-sha256=c2743aac553aeabecb7a729bc109639f66a2dfae8a6e10c32b5695d1f13f36a1; output-bytes=23111; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries