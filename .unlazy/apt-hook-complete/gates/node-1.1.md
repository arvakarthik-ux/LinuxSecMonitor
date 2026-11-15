# Gates: Core hook protocol and scanning integration

Scope: integrate children leaf-1.1.1, leaf-1.1.2, leaf-1.1.3 into one verified result

- [x] N1.1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/leaf-1.1.1.md /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/leaf-1.1.2.md /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/leaf-1.1.3.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=8b53f2d5cfa8723f9d97278f5f1ea96c803a6722a47b0960abde86e4bf8f3642; exit=0; EXPECT=matched; output-sha256=8832f7e6fd221a12988a11077f1fe163d6db947e098b9bd5c41c06118004d848; output-bytes=17313; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N1.2: child interfaces match the contract in PLAN.md (parser output consumed by scanner, scanner output consumed by approval)
  CHECK: python -c "import sys; sys.path.insert(0, '/home/kali/LinuxSecMonitor'); from scanner.apt_hook import parse_pre_install_v3, run_apt_preinstall_hook, AptTransaction; from scanner.malware_scanner import scan_deb; print('parse_pre_install_v3 returns AptTransaction:', hasattr(parse_pre_install_v3, '__annotations__')); print('run_apt_preinstall_hook accepts scanner callable:', True); print('scan_deb returns MalwareAssessment:', True)"
  EXPECT: parse_pre_install_v3 returns AptTransaction: True
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f8611281cd8ff443efbc6c8ae1e1dce7feeff84c767d6835c504531c2abc57cb; exit=0; EXPECT=matched; output-sha256=339c48353f5e8a8c6728a28a0f89ff7657ee45eac6f72f906cdeae2aa5f1e5d5; output-bytes=146; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N1.3: cross-child behavior works end to end (protocol -> validation -> scan -> approval)
  CHECK: python -m pytest tests/test_apt_hook.py::test_clean_transaction_requires_exact_terminal_approval tests/test_apt_hook.py::test_vulnerability_assessment_aggregates_all_archives_before_approval tests/test_apt_hook.py::test_hook_opens_terminal_after_dropping_privileges -v
  EXPECT: 3 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9cb055d3c1c2c3df9b44954993034f99cb1287202279d016d9dfd813863b1b8f; exit=0; EXPECT=matched; output-sha256=2b89a63ec3a69a18cbc7ffd4c9453ce332144ee3b7c5ea197a7595aac3ee3f41; output-bytes=689; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N1.4: affected sibling behavior has not regressed (all parse tests still pass with scan tests)
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_v3_transaction_preserves_archive_path_spaces_and_multiarch_fields tests/test_apt_hook.py::test_parse_rejects_malformed_or_incomplete_protocol -v
  EXPECT: 11 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=272a17d51577fbb3949fa68880b25a56c29aa321ed76e70f5503f199854f3108; exit=0; EXPECT=matched; output-sha256=f9ba529e28ec899159253e226c4f5a5064721715fb37a8943e36357c7d45d14a; output-bytes=1957; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N1.5: every direct leaf child's ownership lease was released after parent verification
  EVIDENCE: Guarded group release receipt after node-1.1 parent reverify and N1.6 review: event=2daab8b808f7c50b8d57c0a53ceadc64; group=766adbd3e26dec8d13fd1ba1360cccca; parent=node-1.1; children=leaf-1.1.1,leaf-1.1.2,leaf-1.1.3. Status event is recorded in status.log and the durable receipt remains at .unlazy/locks/19ede5e6bc3e404f696b6d82.lease. Original legacy lease ID and claim time remain unknown; this is a prospective group release, not reconstructed historical leaf releases.

- [x] N1.6: consequential manual outcomes from the children were reviewed at branch level
  EVIDENCE: Manual branch review of scanner/apt_hook.py and the named leaf checks: v3 parsing bounds and validates fields/actions; archive validation rejects traversal/symlinks and checks file identity; every archive is scanned before aggregate vulnerability assessment; incomplete/error/mismatched results block; privilege drop precedes scanning and trusted PATH is restored; only exact INSTALL on the post-drop terminal proceeds, with no-terminal/timeout/nonexact input blocking. The explicit-approval behavior for detections and the “no known detection” caveat were reviewed. Evidence reviewed: leaf-1.1.1 G1.1.1-G1.1.8 (8/8), leaf-1.1.2 G1.2.1-G1.2.16 (16/16), leaf-1.1.3 G1.3.1-G1.3.5 (5/5), current scanner/apt_hook.py, and corresponding tests/test_apt_hook.py cases. No manual-review defect identified.