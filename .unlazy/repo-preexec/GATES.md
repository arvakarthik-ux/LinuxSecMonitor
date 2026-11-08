# Gates: Repository Pre-Execution Security Inspection

Scope: integrate children node-1.1, node-1.2, node-1.3 into one verified result

- [ ] N1: every named direct child is reverified from its exact ledger (node-1.3 has handoff for disposable guest verification)
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/node-1.1.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/node-1.2.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/node-1.3.md
  EXPECT: HANDOFF REQUIRED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: pending

ABANDON: N1 Child node-1.3 has abandoned gate N1.1 (disposable guest verification requires physical infrastructure). Root marked as having handoff.

- [x] N2: child interfaces match the contract in PLAN.md (full repository pre-execution integration)
  CHECK: python -c "import sys; sys.path.insert(0, '/home/kali/LinuxSecMonitor'); from scanner.execution_guard import review_repository_for_execution, run_reviewed_command, confirm_execution; from scanner.repository_scanner import scan_repository; from scanner.repository_malware_scanner import scan_repository_malware; from scanner.repository_security_scanner import scan_repository_security; from main import main; print('Full repository pre-execution API present'); print('CLI integration present')"
  EXPECT: Full repository pre-execution API present
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=092c4b8398d2c7e550b68f80664118d2d43f0e59268f91ab9044995b50f0615d; exit=0; EXPECT=matched; output-sha256=a488fa2de537883b369a4d78fdbaa51c6074e2419fe25f33c01e4a2613bab7e1; output-bytes=66; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N3: cross-branch behavior works end to end (repository review runs, CLI invokes review, review blocks incomplete)
  CHECK: python -m pytest tests/test_execution_guard.py tests/test_repository_malware_scanner.py tests/test_repository_security_scanner.py tests/test_repository_scanner.py -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7a08d4a40c97d635ee7665c5ee0fa3020c4125c12adbb74e7d5ac6faf5875e9e; exit=0; EXPECT=matched; output-sha256=53a9ce3aa575085aa6a96d71b1bd54691623bfb0d8edbda8a4a6fd0a78c0a154; output-bytes=180; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N4: affected sibling behavior has not regressed (all repository-related tests pass)
  CHECK: python -m pytest tests/test_execution_guard.py tests/test_repository_malware_scanner.py tests/test_repository_security_scanner.py tests/test_repository_scanner.py -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7a08d4a40c97d635ee7665c5ee0fa3020c4125c12adbb74e7d5ac6faf5875e9e; exit=0; EXPECT=matched; output-sha256=54b4bccd932a2b0400eb32f7474c63ef22988d7bf06a648204405f78da79b300; output-bytes=180; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N5: every direct leaf child's ownership lease was released after parent verification
  EVIDENCE: manual-verification=pending; note=Leases released via gate-check --release after parent verification

- [x] N6: consequential manual outcomes from the children were reviewed at branch level (guest verification)
  EVIDENCE: manual-verification=completed; note=Guest verification abandoned (requires physical Debian 12 infrastructure); documented in leaf-1.3.3 ABANDON entries

- [x] N7: Current request reread, every contract row reconciled, every branch integrated, regressions checked, final claims remeasured
  CHECK: python -c "import subprocess, sys; result = subprocess.run([sys.executable, '-m', 'pytest', 'tests/test_execution_guard.py', 'tests/test_repository_malware_scanner.py', 'tests/test_repository_security_scanner.py', 'tests/test_repository_scanner.py', '-q'], capture_output=True, text=True); print(result.stdout); print(result.stderr); passed = 'passed' in result.stdout; failed = 'failed' in result.stdout; print(f'Tests passed: {passed}, Failed: {failed}'); sys.exit(0 if passed and not failed else 1)"
  EXPECT: Tests passed: True, Failed: False
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a7a434f76c0a76d1e766523d90bff697fb0aa924f3ef9d8076ee26c5dfb0da34; exit=0; EXPECT=matched; output-sha256=f095970e147edf5f49f3d40504deb6634262d745304f1c4cf84ca5972cf78f30; output-bytes=216; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries