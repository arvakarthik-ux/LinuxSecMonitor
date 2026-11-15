# Gates: Protocol parsing and validation

OWNS: scanner/apt_hook.py, tests/test_apt_hook.py::test_parse*

Scope: Parse and validate APT Pre-Install-Pkgs v3 protocol; reject all malformed input

- [x] G1.1.1: parse_pre_install_v3 accepts valid VERSION 3 transactions with configuration and actions
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_v3_transaction_preserves_archive_path_spaces_and_multiarch_fields -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9bf967f9c832464c9859c98068974b0aad51389224e015dbc3ec5283948865f5; exit=0; EXPECT=matched; output-sha256=c6f194e70d4e70d513e280de304d1da166766c9a9677c9edc87c28d3db160a39; output-bytes=512; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G1.1.2: parse_pre_install_v3 rejects malformed protocol (wrong version, missing sections, invalid records)
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_rejects_malformed_or_incomplete_protocol -v
  EXPECT: 10 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=33feb7a346e92d59070c1882bf4a9f297b73c72067e9e8848cf3ed64e1844680; exit=0; EXPECT=matched; output-sha256=2af0e32c40fd2ba2c9ce84ab3b4d580527a88c09997553b63820d8318a8082d8; output-bytes=1842; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G1.1.3: parse_pre_install_v3 rejects duplicate archive paths
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_rejects_duplicate_archive_paths -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1e0c315c1afcb0a5dd1e9f09c22a7012d1514ac4d98ec1480ace8a78ade5fc9b; exit=0; EXPECT=matched; output-sha256=e544efe2a4a2615a528e15fb48f30e1bdf36a310b71ddcc449e90db2ff005d74; output-bytes=478; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G1.1.4: parse_pre_install_v3 rejects traversal and unknown actions
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_rejects_traversal_and_unknown_action -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5130eb775bce8435c3c3a03740a76ef83e5dc82316f338cc3304a9fdb0faaa09; exit=0; EXPECT=matched; output-sha256=5f0f7f48fd28e2886db801832c780030862dc53027c4b46a002f2543877f2a30; output-bytes=483; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G1.1.5: parse_pre_install_v3 accepts configure/remove records without install archives
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_accepts_configuration_and_removal_records_but_no_install_archives -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4ad5d9db9c9209316910080037b1e873aeea31e1c32ec29829053ac0cf4c16cb; exit=0; EXPECT=matched; output-sha256=bcd95309462bb38e1f9c5fbda8834a8a152240709bb464904b6cf9c803c02c2c; output-bytes=512; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G1.1.6: _validate_package_action rejects invalid package action fields
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_rejects_invalid_package_action_fields -v
  EXPECT: 8 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=bd157f2241574df14b120f939ff2179d181f70b9b1c33b1e15f7d55da849aa08; exit=0; EXPECT=matched; output-sha256=81ff48a84cc1d4e894b69f61995bcc213d22f9b7cbdefa91b26248ee0fb9d352; output-bytes=1406; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G1.1.7: parse_pre_install_v3 enforces size limits (MAX_PROTOCOL_BYTES, MAX_PROTOCOL_LINE_BYTES)
  CHECK: python -m pytest tests/test_apt_hook.py::test_unexpected_info_fd_and_oversized_protocol_fail_closed -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=37f07e9c966af5140da8e5139a5058bd8fc5de9cb384f1f98883f83ef571efed; exit=0; EXPECT=matched; output-sha256=935fc0051908530ecdfe52b9b1b162462a962fa9977172d1b33ba05fe1fa1f92; output-bytes=494; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G1.1.8: parse_pre_install_v3 rejects malformed transactions before scanning
  CHECK: python -m pytest tests/test_apt_hook.py::test_malformed_transactions_abort_runner_before_scanning -v
  EXPECT: 3 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=358ab99d86d313c5ee96580849e89473d3123379e3ef984f97ed7c996b3653f4; exit=0; EXPECT=matched; output-sha256=7e223e7d4f478246b6e54477ae290ff1f4b574b73f81ad4803697574c56d24a4; output-bytes=869; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries