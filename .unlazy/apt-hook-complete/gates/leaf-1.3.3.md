# Gates: Disposable guest verification

OWNS: tests/integration/test_apt_preinstall_guest.py, README.md (guest verification notes)

Scope: Real APT transaction verification in disposable Kali/Debian/Ubuntu guest

- [ ] G3.3.1: Real disposable guest verification confirms hook executes in APT transaction (manual)
  EVIDENCE: pending

ABANDON: G3.3.1 Disposable guest verification requires physical/virtual Kali/Debian/Ubuntu guest infrastructure not available in this environment. This is a handoff for future integration testing in a dedicated disposable guest.

  Manual verification required (for future handoff):
  1. Provision fresh Kali/Debian/Ubuntu disposable guest
  2. Create /run/linuxsecmonitor-disposable-apt-test marker file (root-owned, 0o644)
  3. Install LinuxSecMonitor CLI to root-owned path (e.g., /root/linuxsecmonitor/bin/linuxsecmonitor)
  4. Run: LINUXSECMONITOR_RUN_REAL_APT=1 LINUXSECMONITOR_REAL_APT_SCENARIO=safe-approve LINUXSECMONITOR_SYSTEM_CLI=/root/linuxsecmonitor/bin/linuxsecmonitor LINUXSECMONITOR_APT_EVIDENCE_DIR=/root/evidence python -m pytest tests/integration/test_apt_preinstall_guest.py::test_safe_approve_transaction -v
  5. Verify hook intercepts APT transaction, scans archives, prompts for approval, allows on INSTALL
  6. Repeat for scenarios: finding-cancel, finding-approve, incomplete-block, lifecycle
  7. Record evidence in status.log with gate ID G3.3.1

  Note: This gate requires physical/virtual guest infrastructure and cannot be automated in CI.