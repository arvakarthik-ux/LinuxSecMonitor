# Gates: Install/enable/disable/uninstall operations

OWNS: scanner/apt_lifecycle.py, tests/test_apt_lifecycle.py::test_install*, tests/test_apt_lifecycle.py::test_enable*, tests/test_apt_lifecycle.py::test_disable*, tests/test_apt_lifecycle.py::test_uninstall*

Scope: Atomic hook installation with validation, enable/disable/uninstall with ownership checks

- [x] G2.1.1: install_apt_hook creates hook atomically, validates with apt-config, rolls back on failure
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_install_enable_disable_uninstall_are_repeatable_and_preserve_other_config tests/test_apt_lifecycle.py::test_install_refuses_preexisting_hook_and_state_without_overwriting tests/test_apt_lifecycle.py::test_install_rolls_back_partial_state_when_hook_write_fails tests/test_apt_lifecycle.py::test_install_rolls_back_when_effective_hook_order_is_unsafe -v
  EXPECT: 4 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7bd300efaa4c37af086e42e353abcac7fc37505a8487f5a316bc559897cbd996; exit=0; EXPECT=matched; output-sha256=cf5ec511a5f30a60ad580d60035bca4a76712c73a2242d051f095ba637fd8c50; output-bytes=837; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2.1.2: Hook file permissions (0o644) and state file permissions (0o600) are correct
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_install_enable_disable_uninstall_are_repeatable_and_preserve_other_config -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c9442f1ca06a753fdd2fbcaf73dd17159f3751be203aa379c646aee1c1e06681; exit=0; EXPECT=matched; output-sha256=b6b0b07b3faa8eb423c9c0e0abcebcf247a9bca42c19aee1fb8de9d62a5fd580; output-bytes=519; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2.1.3: enable_apt_hook restores hook from state; rolls back on unsafe hook order
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_enable_rolls_back_when_effective_hook_order_is_unsafe -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=57494def51f4a7d6034a05f172758781a2e15d0a1440d173281e944ada71633d; exit=0; EXPECT=matched; output-sha256=318653de8d29862c82a1eff7e700aa26b53a83a98dbc6b151dadd17e834ad03b; output-bytes=499; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2.1.4: disable_apt_hook and uninstall_apt_hook refuse modified/unowned configuration; symlink never removed
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_disable_and_uninstall_refuse_modified_or_unowned_configuration tests/test_apt_lifecycle.py::test_symlink_hook_is_never_removed -v
  EXPECT: 2 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e18e5812aff20e7207d9472b53d8277f7fcf533ba58c7da2d6b00477e11c9827; exit=0; EXPECT=matched; output-sha256=8162791e817892c9ef4559ab05f140506a01137e1c2cdc82b307f0b7b077e6bb; output-bytes=589; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2.1.5: Hook config is valid APT syntax when apt-config available
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_hook_config_is_valid_apt_syntax_when_apt_config_is_available -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0c84983069d3d0f8a0c249c07ceef59514728c66af6f5191319d878e3035e335; exit=0; EXPECT=matched; output-sha256=a5e1a3293e931cfe4cc5eff7cfe99d3dec986844c75d4dcd55ebf8122296404c; output-bytes=506; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2.1.6: Managed drop-in precedes later preconfigure and main config
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_managed_dropin_precedes_later_preconfigure_and_main_config -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1a154b895b7a808a8be11439bf22d000830778aeddc67ba37aa6b41d1407e2dc; exit=0; EXPECT=matched; output-sha256=5bd39798a8dde34a91a56b25e8b97bbca4d2ca8c89b6dd358b671dac7e811e6c; output-bytes=504; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries