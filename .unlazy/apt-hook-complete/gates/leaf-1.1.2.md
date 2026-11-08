# Gates: Archive validation and malware assessment

OWNS: scanner/apt_hook.py, tests/test_apt_hook.py::test_*archive*, tests/test_apt_hook.py::test_*scan*, tests/test_apt_hook.py::test_*assessment*, tests/test_apt_hook.py::test_*detection*, tests/test_apt_hook.py::test_*coverage*, tests/test_apt_hook.py::test_*identity*, tests/test_apt_hook.py::test_*trusted*

Scope: Validate archive paths, scan with malware scanner, assess vulnerabilities

- [x] G1.2.1: _safe_archive_path rejects missing, oversized, directory, traversal, symlink, non-.deb, relative paths
  CHECK: python -m pytest tests/test_apt_hook.py::test_safe_archive_validation_rejects_missing_oversized_directory_and_traversal tests/test_apt_hook.py::test_safe_archive_validation_rejects_symlinks tests/test_apt_hook.py::test_safe_archive_validation_rejects_inaccessible_file tests/test_apt_hook.py::test_safe_archive_validation_rejects_non_deb_and_relative_paths -v
  EXPECT: 4 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6dc56b88df35568b36a65ca6fe3cd47e966078c60683a3bcf71fed53146f4e51; exit=0; EXPECT=matched; output-sha256=d69ae915f4da5463b8fbbf5cb4dd98e0ee73c39da761ec525958a58ec277e438; output-bytes=794; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.2: run_apt_preinstall_hook scans every archive, blocks without terminal, requires exact approval
  CHECK: python -m pytest tests/test_apt_hook.py::test_clean_transaction_scans_every_archive_but_cancels_without_terminal tests/test_apt_hook.py::test_clean_transaction_requires_exact_terminal_approval -v
  EXPECT: 2 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6dd7175a7f46f9731acee15d76ce1dc56a22a786b4908132b8afdf72a5a36c5b; exit=0; EXPECT=matched; output-sha256=60d04189e1fa38f58c5e225af365c1a2badeea1dbe547d2432acc3c79c699e2c; output-bytes=602; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.3: Vulnerability assessment aggregates all transaction packages before approval
  CHECK: python -m pytest tests/test_apt_hook.py::test_vulnerability_assessment_aggregates_all_archives_before_approval -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c44e09135b5dd9fe696c6da6d24b3a91cfc622b3f50720bbdeb34842a3a336e2; exit=0; EXPECT=matched; output-sha256=1c3049ca2a5354c16a4dfffe98b9b00ce239f67a6a492131f2aee0d569657609; output-bytes=505; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.4: Vulnerability assessment gap (error/requires_review) blocks before prompt
  CHECK: python -m pytest tests/test_apt_hook.py::test_vulnerability_assessment_gap_blocks_before_prompt -v
  EXPECT: 2 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=70602cec3ea2ef5f98d73ee61bbdb250a0f9d27e5c47fb331db12c33260f756c; exit=0; EXPECT=matched; output-sha256=9e26a6f44a65a11095920e0dd252427d36d9c6d9375e66c7bc269b078c962123; output-bytes=608; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.5: Maintainer script review lead requires exact approval
  CHECK: python -m pytest tests/test_apt_hook.py::test_maintainer_script_review_lead_requires_exact_approval -v
  EXPECT: 4 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1492cdb9b75350c949e4fc6bc4f1688df7404a46914d1fd4644310bfb9d0b573; exit=0; EXPECT=matched; output-sha256=1a0f6d28a8eb0ec29cf9a1d69c89ffc6c8bac8be7a47ee6a492a3b020cc3026c; output-bytes=834; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.6: Detection requires exact terminal approval; mixed clean/detected all scanned before approval
  CHECK: python -m pytest tests/test_apt_hook.py::test_detection_requires_exact_terminal_approval tests/test_apt_hook.py::test_mixed_clean_and_detected_archives_are_all_scanned_before_approval tests/test_apt_hook.py::test_detection_cancels_for_any_nonexact_confirmation tests/test_apt_hook.py::test_detection_without_tty_is_blocked -v
  EXPECT: 7 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=463fdb6f2dbd4decf20dda3538b87e89a7e2e042b620fbd13f3a6e0849e4f239; exit=0; EXPECT=matched; output-sha256=2737438c626c34657ed3254a137f5029014cbf9ee6fb42f4af6ee6c672bb433e; output-bytes=1068; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.7: Incomplete/error/unavailable results abort transaction
  CHECK: python -m pytest tests/test_apt_hook.py::test_incomplete_error_and_unavailable_results_abort -v
  EXPECT: 3 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a5010db7b5dcfce53be533798649e7476fccc8900d950df0f1ca2d11ef04fa67; exit=0; EXPECT=matched; output-sha256=ebaf9a61b8d1c58cd58d03f4530517bcdefd035aa584d795ed0594247707783c; output-bytes=700; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.8: Detection with incomplete coverage cannot be approved
  CHECK: python -m pytest tests/test_apt_hook.py::test_detection_with_incomplete_coverage_cannot_be_approved -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b71a3eb771727558392ef3c50aaaa06f05fedd5efb16fb419ebd8cd205f38ae1; exit=0; EXPECT=matched; output-sha256=edf902b899c24cfeed39493c635af2a6312c19a10affb4dec5f52e6611e0af15; output-bytes=494; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.9: Changed archive after scan aborts transaction
  CHECK: python -m pytest tests/test_apt_hook.py::test_changed_archive_after_scan_aborts_transaction -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6f04daee67f2a8db97b3eae14d7a4fd4ad2f63cceb04123db50f9264272dd1ff; exit=0; EXPECT=matched; output-sha256=2b2d3eeb1d581c51a2e3e2843070f4a84fe476af2e2f26b2a0efed886a030da6; output-bytes=486; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.10: Archive identity mismatch with APT transaction blocks clean result and preserves detection
  CHECK: python -m pytest tests/test_apt_hook.py::test_archive_identity_mismatch_with_apt_transaction_blocks_clean_result tests/test_apt_hook.py::test_archive_identity_mismatch_preserves_detection_and_blocks_without_prompt -v
  EXPECT: 5 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=16dac6e18549a1b03e2dd62936fad9e6df99531e4fd26fe306ba275c459f4c83; exit=0; EXPECT=matched; output-sha256=59b7990711003e707592281b05d1a3a7a0fb89686c568af132f406d7eceb41c4; output-bytes=1036; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.11: Scanner uses trusted PATH and restores caller environment
  CHECK: python -m pytest tests/test_apt_hook.py::test_scanner_uses_trusted_system_path_and_restores_caller_environment -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=709fd539a16ce218ac800c99ef699f69560bfb547debcafc77666b88f566ce68; exit=0; EXPECT=matched; output-sha256=4e7c80faffe0d99d1d59edc7be67420ac09941ad8ff7150d2469cc70572d194c; output-bytes=505; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.12: Archive-less maintainer script actions block transaction
  CHECK: python -m pytest tests/test_apt_hook.py::test_archive_less_maintainer_script_actions_block_transaction -v
  EXPECT: 2 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7b6f7529629d6ad1a55ca1308a33d30713068cba27dc03ca8f1912fa29b2ba6f; exit=0; EXPECT=matched; output-sha256=11cef2d7782b431b4a308276210fa0efca8332cc10c2725cd14b158a32f43588; output-bytes=690; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.13: Missing archive reported with expected package identity; configure without matching archive blocks
  CHECK: python -m pytest tests/test_apt_hook.py::test_missing_archive_report_keeps_expected_package_identity tests/test_apt_hook.py::test_configure_action_without_matching_archive_blocks_scanned_transaction tests/test_apt_hook.py::test_configure_action_with_matching_archive_is_scanned -v
  EXPECT: 3 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d8e6c37b85c1d7451b67488df2317d206679819885ba1364ae53ebac86cf7022; exit=0; EXPECT=matched; output-sha256=4f373e04cb0b670f4e585e06a98f622461116f59c5cc5f197e465bf5b718c5c3; output-bytes=701; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.14: Malformed scanner results reported as errors and block
  CHECK: python -m pytest tests/test_apt_hook.py::test_malformed_scanner_results_are_reported_as_errors_and_block -v
  EXPECT: 9 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0ed1fb3251ff2eb4523d7ed1f20079f79b3fb992166cbe1d806d8674bed956b4; exit=0; EXPECT=matched; output-sha256=a6d19a9c137a28edea85ff80c83452660d14e946a03ff6a83821b621929973f8; output-bytes=1394; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.15: Detection with inconsistent complete metadata preserved but blocked
  CHECK: python -m pytest tests/test_apt_hook.py::test_detection_with_inconsistent_complete_metadata_is_preserved_but_blocked -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=2011345a7e2c11cbd2f6a9995157a349b4c079e43fb3b29c2a9d302107500f8e; exit=0; EXPECT=matched; output-sha256=36414aee314542489acd8758fa05c4a5ec601d40575db9297d61f426cfc62650; output-bytes=511; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.2.16: APT report explicitly shows incomplete coverage
  CHECK: python -m pytest tests/test_apt_hook.py::test_apt_report_explicitly_shows_incomplete_coverage -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d34626f107e7e6d8fe9ecb1417f7993a369d74b26c951791c3ddedaead5bd9e9; exit=0; EXPECT=matched; output-sha256=b1c563b364341a623947854156fc61a764fcb84e4b00530f815cec069b605469; output-bytes=488; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries