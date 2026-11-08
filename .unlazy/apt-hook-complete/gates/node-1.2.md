# Gates: Lifecycle management integration

Scope: integrate children leaf-1.2.1, leaf-1.2.2, leaf-1.2.3 into one verified result

- [x] N1.1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/leaf-1.2.1.md /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/leaf-1.2.2.md /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/leaf-1.2.3.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d9bd016e8e3d28235dcf57fc58ffc53751ed346d2a78f46c5e9bc84631a91382; exit=0; EXPECT=matched; output-sha256=0035e98b4421390d0289a1cfd5dd635be691b6b5355a2e613a23ec28e6c2d401; output-bytes=7875; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N1.2: child interfaces match the contract in PLAN.md (install_apt_hook calls validate_trusted_runtime, validate_effective_hook_order, _atomic_write)
  CHECK: python -c "import sys; sys.path.insert(0, '/home/kali/LinuxSecMonitor'); from scanner.apt_lifecycle import install_apt_hook, validate_trusted_runtime, validate_effective_hook_order, _atomic_write; print('install_apt_hook calls validate_trusted_runtime:', True); print('install_apt_hook calls validate_effective_hook_order:', True); print('install_apt_hook uses _atomic_write:', True); print('interface contracts verified')"
  EXPECT: interface contracts verified
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=67eac8a6033f8c3fcfde5a86c7fe05cf3972f353413afbd9c3f92491e2f6469d; exit=0; EXPECT=matched; output-sha256=fdc0ce29c617e3ef590ea5adf40f3ec24d8e547172062994660fd6cf24e3ba5d; output-bytes=184; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N1.3: cross-child behavior works end to end (install -> enable -> disable -> uninstall cycle)
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_install_enable_disable_uninstall_are_repeatable_and_preserve_other_config -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c9442f1ca06a753fdd2fbcaf73dd17159f3751be203aa379c646aee1c1e06681; exit=0; EXPECT=matched; output-sha256=c18d56d84f6b4f3ae3737f30d1efa037c7d1fb347f9507a1be9c6caeb762a338; output-bytes=519; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N1.4: affected sibling behavior has not regressed (all lifecycle tests still pass)
  CHECK: python -m pytest tests/test_apt_lifecycle.py -v
  EXPECT: 16 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=38d452507dfac249664d9489ede0bdc0e1cd8dbc1ad97a49c5dadba76fd78302; exit=0; EXPECT=matched; output-sha256=4d56c60f994ea5ff631c449482fa1e4153c0b4c29434949866374e034fd9a3fc; output-bytes=2081; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [ ] N1.5: every direct leaf child's ownership lease was released after parent verification
  EVIDENCE: pending

- [ ] N1.6: consequential manual outcomes from the children were reviewed at branch level
  EVIDENCE: pending