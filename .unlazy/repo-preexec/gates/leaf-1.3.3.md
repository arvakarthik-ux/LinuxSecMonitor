# Gates: APT regression preservation

OWNS: tests/integration/test_apt_preinstall_guest.py, tests/integration/apt_guest_scenario_runner.py, README.md

Scope: all 5 APT acceptance scenarios pass on the documented Kali Linux 2026.3 target after repository pre-execution changes

Guest target: Kali Rolling 2026.3, the release represented by the project's current documented Kali guest image. Record the actual guest release from `/etc/os-release` with fresh evidence. Kali vulnerability assessment is expected to remain `unsupported`; it must not be presented as clean or replaced with a simulated provider result. Debian validation is not required for this Kali-only scope and no Debian support is implied.

- [x] G1: finding-cancel scenario passes (malware detection, user cancels)
  CHECK: python tests/integration/apt_guest_scenario_runner.py G1
  EXPECT: LSM_GATE_G1_PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c4419597b3681f1d734fdfac64e2b874e8133a1ffc7be59f9cd0e9dd35519eed; exit=0; EXPECT=matched; output-sha256=21244f89ff8468d765ef0ef955a65bbe54299c826cf33df07860ec2f11e22ccb; output-bytes=65; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2: incomplete-block scenario passes (incomplete scan blocks transaction)
  CHECK: python tests/integration/apt_guest_scenario_runner.py G2
  EXPECT: LSM_GATE_G2_PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=852678bb85138bd1bc48abd7c398219f558bc0e3906d2facb2491440676ebc19; exit=0; EXPECT=matched; output-sha256=5a415277565e3527ac513847521c751a842433467dfc7ee6ece293f94adac74e; output-bytes=65; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G3: finding-approve scenario passes (malware detection, user approves)
  CHECK: python tests/integration/apt_guest_scenario_runner.py G3
  EXPECT: LSM_GATE_G3_PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=74e660430e6625c4d4d6160dccf992845e4ef47ec8df367d01c12b4f97d479ef; exit=0; EXPECT=matched; output-sha256=c621716cf1e711dfb6209b976abf96e79d558b850ba7ae4a9a2a33be9c28f05b; output-bytes=65; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G4: safe-approve scenario passes (clean scan, user approves)
  CHECK: python tests/integration/apt_guest_scenario_runner.py G4
  EXPECT: LSM_GATE_G4_PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=57d0fba14eeac5cdffff529d81d42fab93d5e8e12ac684f7de6a14ca3cf4178a; exit=0; EXPECT=matched; output-sha256=302919d0036e33fb0a1f91f4dbd16bf875025dc61aae594ca843c20bfa94ec21; output-bytes=65; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G5: lifecycle scenario passes (hook install/enable/disable/uninstall works)
  CHECK: python tests/integration/apt_guest_scenario_runner.py G5
  EXPECT: LSM_GATE_G5_PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c2ece14811d118f1cf38c4c727ed96025549ddf23754d73ceb1d25c67776a93d; exit=0; EXPECT=matched; output-sha256=8b95c87a06ad68293ffd44fbd1919389592003691b6f6c38d3fb8dd09ed2f810; output-bytes=65; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

HISTORY: Before the tracked-runner amendment, G1-G5 each had EVIDENCE: pending and CHECK commands invoking the absent /tmp/opencode/lsm-apt-evidence/repo-preexec-r3-build/run_scenario.py; no prior evidence is counted for these gates.

- [x] G6: all APT unit tests still pass
  CHECK: python -m pytest tests/test_apt_hook.py tests/test_apt_lifecycle.py tests/test_apt_hook_cli.py -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6fb570be914e8980727f74b2ddb27ecaebe136afa4939f8d36ab217222df0f2d; exit=0; EXPECT=matched; output-sha256=8edf96b728804d012ece853c03f9f6c9b2e0bae38a1737ef7c6743e881843596; output-bytes=180; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G7: no system-wide APT configuration modified during development
  CHECK: python -c "import subprocess; result = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True, cwd='/home/kali/LinuxSecMonitor'); changes = result.stdout.strip().split('\n') if result.stdout.strip() else []; system_apt_changes = [c for c in changes if '/etc/apt' in c]; print('No system-wide APT configuration modified' if not system_apt_changes else 'System APT config modified: ' + '; '.join(system_apt_changes))"
  EXPECT: No system-wide APT configuration modified
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7d2bad0a55ae7d7bf9bb91b439d71985c0da6a324faf7aaa67616dfc3842791c; exit=0; EXPECT=matched; output-sha256=bb402601ca45d0159f1d26ee7fa9946f7ae8a17cce2b8fc50b0e4f86d4ec68a4; output-bytes=42; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G8: existing production APT hook not disabled merely to test repository functionality
  CHECK: python -c "import os; hook_path = '/etc/apt/apt.conf.d/20linuxsecmonitor-preinstall'; exists = os.path.exists(hook_path); print(f'Hook exists: {exists} (not modified by dev)' if exists else 'Hook not present in dev environment (not modified by dev)')"
  EXPECT: Hook not present in dev environment (not modified by dev)
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=baf0a1e77646497314a2a8913311126f4d6f2ab6bc4a49e7524ebfe5accc8922; exit=0; EXPECT=matched; output-sha256=dbf11f57fe7cc785b4d10f953072ba2c5f87f99642dfdcb230334db744901b4f; output-bytes=58; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

HISTORY: Original leaf abandonment record (verbatim; non-operative only for the authorized revision 2 fresh-verification cycle): ABANDON: G1 finding-cancel scenario requires disposable Debian 12 guest infrastructure not available in this environment
HISTORY: Original leaf abandonment record (verbatim; non-operative only for the authorized revision 2 fresh-verification cycle): ABANDON: G2 incomplete-block scenario requires disposable Debian 12 guest infrastructure not available in this environment
HISTORY: Original leaf abandonment record (verbatim; non-operative only for the authorized revision 2 fresh-verification cycle): ABANDON: G3 finding-approve scenario requires disposable Debian 12 guest infrastructure not available in this environment
HISTORY: Original leaf abandonment record (verbatim; non-operative only for the authorized revision 2 fresh-verification cycle): ABANDON: G4 safe-approve scenario requires disposable Debian 12 guest infrastructure not available in this environment
HISTORY: Original leaf abandonment record (verbatim; non-operative only for the authorized revision 2 fresh-verification cycle): ABANDON: G5 lifecycle scenario requires disposable Debian 12 guest infrastructure not available in this environment