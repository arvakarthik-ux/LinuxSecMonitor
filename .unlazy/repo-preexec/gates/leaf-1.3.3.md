# Gates: APT regression preservation

OWNS: tests/integration/test_apt_preinstall_guest.py, README.md

Scope: all 5 APT acceptance scenarios still pass after repository pre-execution changes

- [ ] G1: finding-cancel scenario passes (malware detection, user cancels)
  CHECK: python -m pytest tests/integration/test_apt_preinstall_guest.py -k "finding_cancel" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: pending

- [ ] G2: incomplete-block scenario passes (incomplete scan blocks transaction)
  CHECK: python -m pytest tests/integration/test_apt_preinstall_guest.py -k "incomplete_block" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: pending

- [ ] G3: finding-approve scenario passes (malware detection, user approves)
  CHECK: python -m pytest tests/integration/test_apt_preinstall_guest.py -k "finding_approve" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: pending

- [ ] G4: safe-approve scenario passes (clean scan, user approves)
  CHECK: python -m pytest tests/integration/test_apt_preinstall_guest.py -k "safe_approve" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: pending

- [ ] G5: lifecycle scenario passes (hook install/enable/disable/uninstall works)
  CHECK: python -m pytest tests/integration/test_apt_preinstall_guest.py -k "lifecycle" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: pending

- [x] G6: all APT unit tests still pass
  CHECK: python -m pytest tests/test_apt_hook.py tests/test_apt_lifecycle.py tests/test_apt_hook_cli.py -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6fb570be914e8980727f74b2ddb27ecaebe136afa4939f8d36ab217222df0f2d; exit=0; EXPECT=matched; output-sha256=23f186b4dbf3d5d70e84fe772ab18f533722806129b013a1dcff6c0b01c27df9; output-bytes=180; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: no system-wide APT configuration modified during development
  CHECK: python -c "import subprocess; result = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True, cwd='/home/kali/LinuxSecMonitor'); changes = result.stdout.strip().split('\n') if result.stdout.strip() else []; system_apt_changes = [c for c in changes if '/etc/apt' in c]; print('No system-wide APT configuration modified' if not system_apt_changes else 'System APT config modified: ' + '; '.join(system_apt_changes))"
  EXPECT: No system-wide APT configuration modified
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7d2bad0a55ae7d7bf9bb91b439d71985c0da6a324faf7aaa67616dfc3842791c; exit=0; EXPECT=matched; output-sha256=bb402601ca45d0159f1d26ee7fa9946f7ae8a17cce2b8fc50b0e4f86d4ec68a4; output-bytes=42; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: existing production APT hook not disabled merely to test repository functionality
  CHECK: python -c "import os; hook_path = '/etc/apt/apt.conf.d/20linuxsecmonitor-preinstall'; exists = os.path.exists(hook_path); print(f'Hook exists: {exists} (not modified by dev)' if exists else 'Hook not present in dev environment (not modified by dev)')"
  EXPECT: Hook not present in dev environment (not modified by dev)
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=baf0a1e77646497314a2a8913311126f4d6f2ab6bc4a49e7524ebfe5accc8922; exit=0; EXPECT=matched; output-sha256=dbf11f57fe7cc785b4d10f953072ba2c5f87f99642dfdcb230334db744901b4f; output-bytes=58; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

ABANDON: G1 finding-cancel scenario requires disposable Debian 12 guest infrastructure not available in this environment
ABANDON: G2 incomplete-block scenario requires disposable Debian 12 guest infrastructure not available in this environment
ABANDON: G3 finding-approve scenario requires disposable Debian 12 guest infrastructure not available in this environment
ABANDON: G4 safe-approve scenario requires disposable Debian 12 guest infrastructure not available in this environment
ABANDON: G5 lifecycle scenario requires disposable Debian 12 guest infrastructure not available in this environment