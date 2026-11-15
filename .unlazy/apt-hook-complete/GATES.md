# Gates: Complete APT hook/lifecycle implementation

Scope: integrate children node-1.1, node-1.2, node-1.3 into one verified result

- [x] N1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/node-1.1.md /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/node-1.2.md /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/node-1.3.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e1623d4288cfce7fca2c3fdcc21eca4b452112e48d3d0c04d87169cd46b7d273; exit=0; EXPECT=matched; output-sha256=ecf6a5c1581415bd55d547a0ae4c8d744868df6a8315ab943caa121da35de9e3; output-bytes=6764; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

HISTORY: N1 previously carried a handoff for disposable guest verification. The original reason is preserved verbatim in status.log; child leaf-1.3.3 was reopened under explicit user authority and its evidence was audited with conditions.

HISTORY: Original malformed lease-history line (verbatim): ABANDON: Historical lease-release evidence for leaf-1.1.1, leaf-1.1.2, leaf-1.1.3, leaf-1.2.1, leaf-1.2.2, and leaf-1.2.3 is unavailable. No release is recorded or inferred. node-1.1:N1.5, node-1.1:N1.6, node-1.2:N1.5, node-1.2:N1.6, root N1, root N5, and root N6 remain unmet. Branch state: ABANDONED with handoff; not VERIFIED; not complete. Resolution requires authentic release records or an explicit authorized amendment; do not fabricate or backdate releases.

HISTORY: Prior active root abandonment record (verbatim): ABANDON: N1 Historical lease-release evidence for leaf-1.1.1, leaf-1.1.2, leaf-1.1.3, leaf-1.2.1, leaf-1.2.2, and leaf-1.2.3 is unavailable. No release is recorded or inferred. node-1.1:N1.5, node-1.1:N1.6, node-1.2:N1.5, node-1.2:N1.6, root N1, root N5, and root N6 remain unmet. Branch state: ABANDONED with handoff; not VERIFIED; not complete. Resolution requires authentic release records or an explicit authorized amendment; do not fabricate or backdate releases.

HISTORY: Amendment 4 (2026-11-12): user-authorized scope-level exception makes the prior root ABANDON record non-operative solely for fresh verification under unchanged P1 criteria. P1 is reopened for fresh verification and remains incomplete; this amendment supplies no gate evidence and claims no gate met. Outstanding: node-1.1:N1.5/N1.6, node-1.2:N1.5/N1.6, root N1/N5/N6, and leaf-1.3.3:G3.3.1 pending guest cleanup/rollback resolution.

- [x] N2: child interfaces match the contract in PLAN.md (full APT hook/lifecycle integration)
  CHECK: python -c "import sys; sys.path.insert(0, '/home/kali/LinuxSecMonitor'); from scanner.apt_hook import parse_pre_install_v3, run_apt_preinstall_hook; from scanner.apt_lifecycle import install_apt_hook, enable_apt_hook, disable_apt_hook, uninstall_apt_hook, integration_status, validate_trusted_runtime, validate_effective_hook_order; from main import main; print('Full APT hook/lifecycle API present'); print('CLI integration present')"
  EXPECT: Full APT hook/lifecycle API present
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=20df36c049f24c98a01749276b83683c35f441f4fa18635f0dcd7cc05ccc2ae3; exit=0; EXPECT=matched; output-sha256=ae73e98e3d042e5f5f2bc0fc47516c6f5e686371f7654a7c1a3fbb1876d0738c; output-bytes=60; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N3: cross-branch behavior works end to end (lifecycle installs hook, CLI invokes hook, hook processes transaction)
  CHECK: python -c "import re, subprocess, sys; files = ['tests/test_apt_hook.py', 'tests/test_apt_lifecycle.py', 'tests/test_apt_hook_cli.py', 'tests/test_main.py']; base = [sys.executable, '-m', 'pytest'] + files + ['-k', 'apt', '-q']; col = subprocess.run(base + ['--collect-only'], capture_output=True, text=True); print(col.stdout); print(col.stderr, file=sys.stderr); m = re.search(r'(\d+)(?:/\d+)? tests collected', col.stdout); selected = int(m.group(1)) if m else 0; run = subprocess.run(base, capture_output=True, text=True); print(run.stdout); print(run.stderr, file=sys.stderr); p = re.search(r'(\d+) passed\b', run.stdout); passed = int(p.group(1)) if p else 0; failed = bool(re.search(r'\b\d+ (?:failed|errors?)\b', run.stdout)) or run.returncode != 0; ok = col.returncode == 0 and run.returncode == 0 and selected > 0 and passed == selected and not failed; print(f'Tests passed: {ok}, Failed: {failed}'); sys.exit(0 if ok else 1)"
  EXPECT: Tests passed: True, Failed: False
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a3e9ed7048fcb1b7f77fdb2710ff2496b9cf1ee70acbf3fda6f9915c369b5daa; exit=0; EXPECT=matched; output-sha256=24a612880c0300fc62ffb90ac1966bfc52c047c236aaa1fd53e448ff6f9d0b14; output-bytes=12287; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N4: affected sibling behavior has not regressed (all APT-related tests pass)
  CHECK: python -c "import re, subprocess, sys; files = ['tests/test_apt_hook.py', 'tests/test_apt_lifecycle.py', 'tests/test_apt_hook_cli.py', 'tests/test_main.py']; base = [sys.executable, '-m', 'pytest'] + files + ['-k', 'apt', '-q']; col = subprocess.run(base + ['--collect-only'], capture_output=True, text=True); print(col.stdout); print(col.stderr, file=sys.stderr); m = re.search(r'(\d+)(?:/\d+)? tests collected', col.stdout); selected = int(m.group(1)) if m else 0; run = subprocess.run(base, capture_output=True, text=True); print(run.stdout); print(run.stderr, file=sys.stderr); p = re.search(r'(\d+) passed\b', run.stdout); passed = int(p.group(1)) if p else 0; failed = bool(re.search(r'\b\d+ (?:failed|errors?)\b', run.stdout)) or run.returncode != 0; ok = col.returncode == 0 and run.returncode == 0 and selected > 0 and passed == selected and not failed; print(f'Tests passed: {ok}, Failed: {failed}'); sys.exit(0 if ok else 1)"
  EXPECT: Tests passed: True, Failed: False
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a3e9ed7048fcb1b7f77fdb2710ff2496b9cf1ee70acbf3fda6f9915c369b5daa; exit=0; EXPECT=matched; output-sha256=efde3c12b6800abf4c63c28b69bc26192f8ef8ae656244628d92ed373c6f0521; output-bytes=12287; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N5: every direct leaf child's ownership lease was released after parent verification
  EVIDENCE: Reviewed release records for every owned child lease. Durable group receipts `.unlazy/locks/19ede5e6bc3e404f696b6d82.lease` and `.unlazy/locks/5e60648478be969ef141fe80.lease` identify scope `apt-hook-complete`, parents `node-1.1`/`node-1.2`, and all six children; each records its parent-verification time before its release event, matching status.log events `2daab8b808f7c50b8d57c0a53ceadc64` and `f927dd40ea6876fbeb284e51731db0a2`. For node-1.3, the explicit 2026-11-09 status.log entry records `leaf-1.3.3` lease release after parent verification/manual review, corroborated by node-1.3 N1.5; no release event is inferred. No other node-1.3 leaf lease was affected, as recorded there.

- [x] N6: consequential manual outcomes from the children were reviewed at branch level (guest verification)
  EVIDENCE: Reviewed node-1.1 N1.6's documented APT protocol, archive-validation, scanning, privilege-drop, and exact-approval outcomes; node-1.2 N1.6's trusted-runtime, hook-order, atomic-write, lifecycle-state, and rollback outcomes; and node-1.3 N1.6's independent audit of six scenarios plus the manual multi-package transaction and Kali `unsupported` result. Reconciled leaf-1.3.3 G3.3.1 evidence and the 2026-11-13 cleanup record: all eight authorized IDs had been verified absent after removal. No consequential defect or unsupported coverage claim was identified; historical test evidence and the original ABANDON wording remain preserved.

- [x] N7: Current request reread, every contract row reconciled, every branch integrated, regressions checked, final claims remeasured
  CHECK: python -c "import subprocess, sys; result = subprocess.run([sys.executable, '-m', 'pytest', 'tests/test_apt_hook.py', 'tests/test_apt_lifecycle.py', 'tests/test_apt_hook_cli.py', 'tests/test_main.py', '-k', 'apt', '-q'], capture_output=True, text=True); print(result.stdout); print(result.stderr); passed = 'passed' in result.stdout; failed = 'failed' in result.stdout; print(f'Tests passed: {passed}, Failed: {failed}'); sys.exit(0 if passed and not failed else 1)"
  EXPECT: Tests passed: True, Failed: False
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e67e7bc369709752fc928afa123f209c077c056b236216ab9fe2c2f3d22ddbcc; exit=0; EXPECT=matched; output-sha256=54067319e29ee6aaf72b17b141bea164f9da32dddbee12bce61a3027f8c04dac; output-bytes=231; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries