# Gates: End-to-end transaction behavior

OWNS: scanner/apt_hook.py, tests/test_apt_hook.py (full transaction tests), tests/test_main.py::test_preinstall*

Scope: Full transaction flow blocks on incomplete coverage, error, unavailable, detection, mismatch

- [x] G3.2.1: Clean transaction with exact approval succeeds; without terminal blocks
  CHECK: python -m pytest tests/test_apt_hook.py::test_clean_transaction_scans_every_archive_but_cancels_without_terminal tests/test_apt_hook.py::test_clean_transaction_requires_exact_terminal_approval -v
  EXPECT: 2 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6dd7175a7f46f9731acee15d76ce1dc56a22a786b4908132b8afdf72a5a36c5b; exit=0; EXPECT=matched; output-sha256=e431e50512d10483d3317bf523668111e610ecc76fd27b02626ae0fa88091f2f; output-bytes=602; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3.2.2: Transaction with detection requires exact approval; nonexact cancels
  CHECK: python -m pytest tests/test_apt_hook.py::test_detection_requires_exact_terminal_approval tests/test_apt_hook.py::test_detection_cancels_for_any_nonexact_confirmation -v
  EXPECT: 5 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7ecb0920a397476442d3cba5c67ab0d68dd688b5d4696c1fd15c37f63112fdba; exit=0; EXPECT=matched; output-sha256=5256eff5950b027b377f8dfa725d9896497ea830353ee646ded3ec235c089121; output-bytes=879; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3.2.3: Transaction with incomplete/error/unavailable scanner result blocks
  CHECK: python -m pytest tests/test_apt_hook.py::test_incomplete_error_and_unavailable_results_abort -v
  EXPECT: 3 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a5010db7b5dcfce53be533798649e7476fccc8900d950df0f1ca2d11ef04fa67; exit=0; EXPECT=matched; output-sha256=632154745e87e3f4d3f8bf2d6bb5878dd957a94e598fa68169f5389243c298f6; output-bytes=700; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3.2.4: Transaction with archive identity mismatch blocks
  CHECK: python -m pytest tests/test_apt_hook.py::test_archive_identity_mismatch_with_apt_transaction_blocks_clean_result tests/test_apt_hook.py::test_archive_identity_mismatch_preserves_detection_and_blocks_without_prompt -v
  EXPECT: 5 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=16dac6e18549a1b03e2dd62936fad9e6df99531e4fd26fe306ba275c459f4c83; exit=0; EXPECT=matched; output-sha256=59b7990711003e707592281b05d1a3a7a0fb89686c568af132f406d7eceb41c4; output-bytes=1036; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3.2.5: Transaction with changed archive during scan blocks
  CHECK: python -m pytest tests/test_apt_hook.py::test_changed_archive_after_scan_aborts_transaction -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6f04daee67f2a8db97b3eae14d7a4fd4ad2f63cceb04123db50f9264272dd1ff; exit=0; EXPECT=matched; output-sha256=2b2d3eeb1d581c51a2e3e2843070f4a84fe476af2e2f26b2a0efed886a030da6; output-bytes=486; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3.2.6: Transaction with maintainer script review leads requires exact approval
  CHECK: python -m pytest tests/test_apt_hook.py::test_maintainer_script_review_lead_requires_exact_approval -v
  EXPECT: 4 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1492cdb9b75350c949e4fc6bc4f1688df7404a46914d1fd4644310bfb9d0b573; exit=0; EXPECT=matched; output-sha256=f42c9abfea93d1e4d854fc7f3a150661503c69dd47b1ce7c59260401cde1d268; output-bytes=834; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3.2.7: Transaction with vulnerability assessment error/requires_review blocks before prompt
  CHECK: python -m pytest tests/test_apt_hook.py::test_vulnerability_assessment_gap_blocks_before_prompt -v
  EXPECT: 2 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=70602cec3ea2ef5f98d73ee61bbdb250a0f9d27e5c47fb331db12c33260f756c; exit=0; EXPECT=matched; output-sha256=2bffe1940dcae61e1a79bda75c212a9537231d4333b0059a87a788fc0958e274; output-bytes=608; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3.2.8: --preinstall-deb requires exact confirmation, reports missing apt/sudo/permission errors
  CHECK: python -m pytest tests/test_main.py::test_preinstall_deb_requires_exact_confirmation_and_does_not_start_apt tests/test_main.py::test_preinstall_deb_missing_sudo_is_reported_after_approval_without_apt tests/test_main.py::test_preinstall_deb_denied_sudo_authorization_does_not_start_apt tests/test_main.py::test_preinstall_deb_blocks_when_apt_sandbox_permissions_cannot_be_set tests/test_main.py::test_preinstall_deb_missing_apt_tool_is_reported_without_prompt tests/test_main.py::test_preinstall_deb_apt_failure_is_reported -v
  EXPECT: 8 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7674be585a8ffc342cd9132afcb48dadb7a430d629a2396ed36a016f21ff61a2; exit=0; EXPECT=matched; output-sha256=9b549865346965499773c28aab23e3ef94a0423f1ef39c867cbf7ba97882ccaa; output-bytes=1229; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries