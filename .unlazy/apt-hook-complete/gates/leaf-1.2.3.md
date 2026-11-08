# Gates: Atomic writes and state persistence

OWNS: scanner/apt_lifecycle.py, tests/test_apt_lifecycle.py::test_atomic*, tests/test_apt_lifecycle.py::test_enable_rejects*, tests/test_apt_lifecycle.py::test_integration_status*

Scope: Atomic file publication via hard-link, state persistence with SHA-256, format versioning

- [x] G2.3.1: _atomic_write publishes via hard-link with fsync; never replaces racing existing file
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_atomic_publish_never_replaces_a_racing_existing_file -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1309854e334e713bf239c665c4a8578aa5afad40bab3e91610d46039316692be; exit=0; EXPECT=matched; output-sha256=dd9d4e172d7de2b1613ab2deec8842e8aae5486980276335b40ec0ddc3dab2d6; output-bytes=498; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2.3.2: enable_apt_hook rejects occupied path and corrupt state
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_enable_rejects_occupied_path_and_corrupt_state -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=56955737b7ab1b2c51b6155ef4b1612546ea5bf2b260f074b6c21107a70465af; exit=0; EXPECT=matched; output-sha256=fa69c4ecaf32305aab2799c0920af6ec117917c1498b7697eacc9155fe38c57d; output-bytes=492; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2.3.3: integration_status reads state format v1, hook SHA-256, python path; reports status correctly
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_install_enable_disable_uninstall_are_repeatable_and_preserve_other_config -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c9442f1ca06a753fdd2fbcaf73dd17159f3751be203aa379c646aee1c1e06681; exit=0; EXPECT=matched; output-sha256=ce8e38280935504d282f645547ec31eb9cbfa4c590274bfe5cebd006d694d38a; output-bytes=519; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2.3.4: State persists hook SHA-256 and python path across disable/enable cycles
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_install_enable_disable_uninstall_are_repeatable_and_preserve_other_config -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c9442f1ca06a753fdd2fbcaf73dd17159f3751be203aa379c646aee1c1e06681; exit=0; EXPECT=matched; output-sha256=c18d56d84f6b4f3ae3737f30d1efa037c7d1fb347f9507a1be9c6caeb762a338; output-bytes=519; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries