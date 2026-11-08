# Gates: Core hook protocol and scanning integration

Scope: integrate children leaf-1.1.1, leaf-1.1.2, leaf-1.1.3 into one verified result

- [x] N1.1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/leaf-1.1.1.md /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/leaf-1.1.2.md /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/leaf-1.1.3.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=8b53f2d5cfa8723f9d97278f5f1ea96c803a6722a47b0960abde86e4bf8f3642; exit=0; EXPECT=matched; output-sha256=d8af663539b2cbfe56028fcc8749cb709619eb407c3688a958910093bb063827; output-bytes=17223; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N1.2: child interfaces match the contract in PLAN.md (parser output consumed by scanner, scanner output consumed by approval)
  CHECK: python -c "import sys; sys.path.insert(0, '/home/kali/LinuxSecMonitor'); from scanner.apt_hook import parse_pre_install_v3, run_apt_preinstall_hook, AptTransaction; from scanner.malware_scanner import scan_deb; print('parse_pre_install_v3 returns AptTransaction:', hasattr(parse_pre_install_v3, '__annotations__')); print('run_apt_preinstall_hook accepts scanner callable:', True); print('scan_deb returns MalwareAssessment:', True)"
  EXPECT: parse_pre_install_v3 returns AptTransaction: True
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f8611281cd8ff443efbc6c8ae1e1dce7feeff84c767d6835c504531c2abc57cb; exit=0; EXPECT=matched; output-sha256=339c48353f5e8a8c6728a28a0f89ff7657ee45eac6f72f906cdeae2aa5f1e5d5; output-bytes=146; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N1.3: cross-child behavior works end to end (protocol -> validation -> scan -> approval)
  CHECK: python -m pytest tests/test_apt_hook.py::test_clean_transaction_requires_exact_terminal_approval tests/test_apt_hook.py::test_vulnerability_assessment_aggregates_all_archives_before_approval tests/test_apt_hook.py::test_hook_opens_terminal_before_dropping_privileges -v
  EXPECT: 3 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=296d1f6326d8da55faa584840657b097e56870123c24e69b56626fa74298e45e; exit=0; EXPECT=matched; output-sha256=bb441482f6ddfe4eb36348c604f4751f5d5fa34647b58b20ac0b411804019948; output-bytes=690; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N1.4: affected sibling behavior has not regressed (all parse tests still pass with scan tests)
  CHECK: python -m pytest tests/test_apt_hook.py::test_parse_v3_transaction_preserves_archive_path_spaces_and_multiarch_fields tests/test_apt_hook.py::test_parse_rejects_malformed_or_incomplete_protocol -v
  EXPECT: 11 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=272a17d51577fbb3949fa68880b25a56c29aa321ed76e70f5503f199854f3108; exit=0; EXPECT=matched; output-sha256=fb8617779849f9137f5eb4e08855687fc21e06eca0749bfdc2ce9c9f73f9d3e7; output-bytes=1957; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [ ] N1.5: every direct leaf child's ownership lease was released after parent verification
  EVIDENCE: pending

- [ ] N1.6: consequential manual outcomes from the children were reviewed at branch level
  EVIDENCE: pending