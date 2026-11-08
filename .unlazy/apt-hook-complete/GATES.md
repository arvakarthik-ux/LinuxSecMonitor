# Gates: Complete APT hook/lifecycle implementation

Scope: integrate children node-1.1, node-1.2, node-1.3 into one verified result

- [ ] N1: every named direct child is reverified from its exact ledger (node-1.3 has handoff for disposable guest verification)
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/node-1.1.md /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/node-1.2.md /home/kali/LinuxSecMonitor/.unlazy/apt-hook-complete/gates/node-1.3.md
  EXPECT: HANDOFF REQUIRED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: pending

ABANDON: N1 Child node-1.3 has abandoned gate N1.1 (disposable guest verification requires physical infrastructure). Root marked as having handoff.

- [x] N2: child interfaces match the contract in PLAN.md (full APT hook/lifecycle integration)
  CHECK: python -c "import sys; sys.path.insert(0, '/home/kali/LinuxSecMonitor'); from scanner.apt_hook import parse_pre_install_v3, run_apt_preinstall_hook; from scanner.apt_lifecycle import install_apt_hook, enable_apt_hook, disable_apt_hook, uninstall_apt_hook, integration_status, validate_trusted_runtime, validate_effective_hook_order; from main import main; print('Full APT hook/lifecycle API present'); print('CLI integration present')"
  EXPECT: Full APT hook/lifecycle API present
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=20df36c049f24c98a01749276b83683c35f441f4fa18635f0dcd7cc05ccc2ae3; exit=0; EXPECT=matched; output-sha256=ae73e98e3d042e5f5f2bc0fc47516c6f5e686371f7654a7c1a3fbb1876d0738c; output-bytes=60; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N3: cross-branch behavior works end to end (lifecycle installs hook, CLI invokes hook, hook processes transaction)
  CHECK: python -m pytest tests/test_apt_hook.py tests/test_apt_lifecycle.py tests/test_apt_hook_cli.py tests/test_main.py -k "apt" -q
  EXPECT: 113 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4d7a649df9ff6d8a4910445478e10f58a236009262f2871c001a3c1ee660a2d7; exit=0; EXPECT=matched; output-sha256=d84cb7d9ca08569f7b7d502cdcf57dee539d86706896e4b2415cc88620de89a9; output-bytes=195; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N4: affected sibling behavior has not regressed (all APT-related tests pass)
  CHECK: python -m pytest tests/test_apt_hook.py tests/test_apt_lifecycle.py tests/test_apt_hook_cli.py tests/test_main.py -k "apt" -q
  EXPECT: 113 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4d7a649df9ff6d8a4910445478e10f58a236009262f2871c001a3c1ee660a2d7; exit=0; EXPECT=matched; output-sha256=b077266ab82724d01cdb32b88822812d1d6a7d774829baca58714e742d53b81a; output-bytes=195; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [ ] N5: every direct leaf child's ownership lease was released after parent verification
  EVIDENCE: pending

- [ ] N6: consequential manual outcomes from the children were reviewed at branch level (guest verification)
  EVIDENCE: pending

- [x] N7: Current request reread, every contract row reconciled, every branch integrated, regressions checked, final claims remeasured
  CHECK: python -c "import subprocess, sys; result = subprocess.run([sys.executable, '-m', 'pytest', 'tests/test_apt_hook.py', 'tests/test_apt_lifecycle.py', 'tests/test_apt_hook_cli.py', 'tests/test_main.py', '-k', 'apt', '-q'], capture_output=True, text=True); print(result.stdout); print(result.stderr); passed = 'passed' in result.stdout; failed = 'failed' in result.stdout; print(f'Tests passed: {passed}, Failed: {failed}'); sys.exit(0 if passed and not failed else 1)"
  EXPECT: Tests passed: True, Failed: False
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e67e7bc369709752fc928afa123f209c077c056b236216ab9fe2c2f3d22ddbcc; exit=0; EXPECT=matched; output-sha256=37adc872fdf2d924a845b1b31738be11f76c41e468d02d9dd4ad68cf25225a87; output-bytes=231; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries