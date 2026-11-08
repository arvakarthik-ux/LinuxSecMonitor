# Gates: Protocol parsing and validation

OWNS: scanner/apt_hook.py, tests/test_apt_hook.py::test_parse*

Scope: Parse and validate APT Pre-Install-Pkgs v3 protocol; reject all malformed input

- [x] G1.1.1: parse_pre_install_v3 accepts valid VERSION 3 transactions with configuration and actions
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_v3_transaction_preserves_archive_path_spaces_and_multiarch_fields -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9bf967f9c832464c9859c98068974b0aad51389224e015dbc3ec5283948865f5; exit=0; EXPECT=matched; output-sha256=7fa99a125d01c55473c9ecc91b7ff9d2639bf7f33f222fad8305c35de7e2b3a8; output-bytes=512; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.1.2: parse_pre_install_v3 rejects malformed protocol (wrong version, missing sections, invalid records)
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_rejects_malformed_or_incomplete_protocol -v
  EXPECT: 10 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=33feb7a346e92d59070c1882bf4a9f297b73c72067e9e8848cf3ed64e1844680; exit=0; EXPECT=matched; output-sha256=2af0e32c40fd2ba2c9ce84ab3b4d580527a88c09997553b63820d8318a8082d8; output-bytes=1842; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.1.3: parse_pre_install_v3 rejects duplicate archive paths
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_rejects_duplicate_archive_paths -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1e0c315c1afcb0a5dd1e9f09c22a7012d1514ac4d98ec1480ace8a78ade5fc9b; exit=0; EXPECT=matched; output-sha256=d5cf18f8f25d76f46d5616fef56ac4180e37f8830c6917003bf0dc815c5ad2f7; output-bytes=478; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.1.4: parse_pre_install_v3 rejects traversal and unknown actions
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_rejects_traversal_and_unknown_action -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5130eb775bce8435c3c3a03740a76ef83e5dc82316f338cc3304a9fdb0faaa09; exit=0; EXPECT=matched; output-sha256=6024d2ba0a3bc93e3ea1ee72af4a98322f2ffab266f268b18094b8ed2ff0390e; output-bytes=483; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.1.5: parse_pre_install_v3 accepts configure/remove records without install archives
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_accepts_configuration_and_removal_records_but_no_install_archives -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4ad5d9db9c9209316910080037b1e873aeea31e1c32ec29829053ac0cf4c16cb; exit=0; EXPECT=matched; output-sha256=88132caee4d31dee9e42bd6d199e4f834e2bcd5db106e1a9a5d560ce5eab67af; output-bytes=512; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.1.6: _validate_package_action rejects invalid package action fields
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_rejects_invalid_package_action_fields -v
  EXPECT: 8 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=bd157f2241574df14b120f939ff2179d181f70b9b1c33b1e15f7d55da849aa08; exit=0; EXPECT=matched; output-sha256=8c6a62d2ea6d80dae3bce6824c5358b2db3ebd73ad3fc8f417aae7ce3a68c0c5; output-bytes=1406; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.1.7: parse_pre_install_v3 enforces size limits (MAX_PROTOCOL_BYTES, MAX_PROTOCOL_LINE_BYTES)
  CHECK: python -m pytest tests/test_apt_hook.py::test_unexpected_info_fd_and_oversized_protocol_fail_closed -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=37f07e9c966af5140da8e5139a5058bd8fc5de9cb384f1f98883f83ef571efed; exit=0; EXPECT=matched; output-sha256=a0fe6730fcd3649ea0b2037bf62809bf4637df34c84235e6b9551058e8ad7d17; output-bytes=494; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.1.8: parse_pre_install_v3 rejects malformed transactions before scanning
  CHECK: python -m pytest tests/test_apt_hook.py::test_malformed_transactions_abort_runner_before_scanning -v
  EXPECT: 3 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=358ab99d86d313c5ee96580849e89473d3123379e3ef984f97ed7c996b3653f4; exit=0; EXPECT=matched; output-sha256=6576cf5bd988c7f228f26cd9660bd47b79e6fdd8bb9fcadef33b5df13754e2d9; output-bytes=869; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries