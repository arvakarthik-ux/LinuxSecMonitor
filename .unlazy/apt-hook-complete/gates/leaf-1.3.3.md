# Gates: Disposable guest verification

OWNS: tests/integration/test_apt_preinstall_guest.py, README.md (guest verification notes)

Scope: Real APT transaction verification in disposable Kali/Debian/Ubuntu guest

- [x] G3.3.1: Real disposable guest verification confirms hook executes in APT transaction (manual)
  EVIDENCE: The historical 2026-11-09 guest results below were reviewed with cleanup resolution on 2026-11-13. Before removal, all eight authorized targets were inspected independently by exact name and full ID; every pair matched, every container was exited, and all had empty mounts and no binds. All eight were removed by full ID and then verified absent by both name and ID. The exact IDs and cleanup event are recorded in status.log. This resolves the pending rollback condition without changing the historical test evidence.
  HISTORY: The prior manual result was recorded on 2026-11-09 in an isolated Docker Kali 2026.3 guest. Its evidence details are retained below. Seven scenario containers and the base container were still running at record time; cleanup was unresolved then. No containers were removed by the 2026-11-12 amendment.
  - Guest image: local `lsm-apt-guest-kali:2026.3-apt-v1`, image ID `sha256:a0b8eb8743012c85709832702eb5ddaea9be4289ecdd185442780e96d4ff11e0`, built from `ghcr.io/usestrix/strix-sandbox:1.3.0`; no host mounts, no privileged mode, one fresh container per scenario. Containers are rolled back by removal; container cleanup was still pending at record time (the seven scenario containers and the base container were still running). Base container `lsm-apt-guest-kali-base`.
  - Guest versions: apt 3.2.0, Python 3.14.8, strace 7.2, ClamAV 1.4.6/28178; corroborated by the read-only environment evidence file `/tmp/opencode/lsm-apt-evidence/guest-environment-2026-11-09.txt` (sha256 `ab3b3a502bf2b2ab630b340bd53d580553657d7b4da345f5fd33d802f9926e48`), which records Kali 2026.3, `Privileged=false`, `Mounts=[]`, and the marker; marker `/run/linuxsecmonitor-disposable-apt-test`; no hook initially installed.
  - Six automated scenarios passed, including post-cleanup assertions that their fixture packages were purged: safe-approve, clean-cancel, finding-cancel, finding-approve, incomplete-block, and lifecycle. The single-scenario JSONs do not contain a post-cleanup package-state field; those results are harness assertions. Container cleanup was still pending at record time; rollback is by container removal.
  - Manual multi-package transaction passed: both archives and packages were announced, one transaction-level `INSTALL` approval covered both, both were unpacked/configured, and both were purged (the multi-package JSON records the purge).
  - APT 3.2 did not prompt for local no-dependency fixtures; repository package `sl` did prompt and aborted on `n`. No `-y` was used.
  - Evidence: host `/tmp/opencode/lsm-apt-evidence/{safe-approve,clean-cancel,finding-cancel,finding-approve,incomplete-block,lifecycle,multi-package}`; guest originals `/var/tmp/linuxsecmonitor-evidence`; multi-package JSON sha256 `f29abffdf1480ad05b68196e78ddceeefcc2485bf4d48414d0a4c160a22d1c47`.
  - Independent `lsm-security-auditor` audit: APPROVE WITH CONDITIONS. Container guest basis acceptable; six scenarios plus manual multi-package evidence sufficient; no product security defect; conditions are documentation/gate amendments only.
  - Kali vulnerability assessment remained visibly `unsupported`. No product source changes.
  - This is a manual gate, not automated CI. Local no-dependency APT transactions may not prompt; plan simulation is additional evidence, not a substitute for the actual hook prompt.

HISTORY: G3.3.1 was previously abandoned because physical/virtual guest infrastructure was unavailable in this environment. The original reason is preserved verbatim in status.log. The user explicitly authorized reopening this same gate; no new leaf or scope identifier was created.

  Manual verification (current disposable VM or isolated-container procedure):
  1. Provision a fresh Kali/Debian/Ubuntu disposable VM, or — when VM/KVM is unavailable — a fresh isolated local Docker/Podman container from a local Kali/Debian/Ubuntu image. The VM remains primary where available. A container must have no host mounts and no privileged mode, must be fresh per scenario, and is rolled back by removal; keep the base image unchanged.
  2. In the guest, create a root-owned `/run/linuxsecmonitor-disposable-apt-test` marker containing `linuxsecmonitor-disposable-apt-guest-v1` (0o644); install the LinuxSecMonitor CLI to a root-owned trusted path; create a private evidence directory; ensure ClamAV has fresh usable signatures; and confirm no existing LinuxSecMonitor APT hook is installed.
  3. Run exactly one scenario per fresh guest with `LINUXSECMONITOR_RUN_REAL_APT=1`, `LINUXSECMONITOR_REAL_APT_SCENARIO=<scenario>`, `LINUXSECMONITOR_SYSTEM_CLI=<root-owned CLI>`, and `LINUXSECMONITOR_APT_EVIDENCE_DIR=<private evidence directory>`. Use the actual test function names:
     - safe-approve: `test_real_apt_safe_package_approval` (`-k safe_package_approval`)
     - clean-cancel: `test_real_apt_clean_package_cancellation_prevents_install` (`-k clean_package_cancellation`)
     - finding-cancel: `test_real_apt_finding_cancellation_prevents_package_scripts` (`-k finding_cancellation`)
     - finding-approve: `test_real_apt_finding_approval_runs_only_approved_script` (`-k finding_approval`)
     - incomplete-block: `test_real_apt_incomplete_coverage_blocks_without_scripts` (`-k incomplete_coverage_blocks`)
     - lifecycle: `test_real_lifecycle_recovery_and_preservation` (`-k lifecycle_recovery`)
  4. Verify the hook is the first effective pre-install hook, archives are scanned, review-lead and coverage behavior is correct, exact `INSTALL`/`CANCEL` input is enforced, no package scripts run on cancel or block, markers appear only on approval, Kali vulnerability assessment reports `unsupported`, and cleanup/rollback completes.
  5. Run a manual multi-package transaction (or equivalent) proving one transaction-level approval covers both archives; record that both packages were unpacked/configured and purged.
  6. Record evidence and guest/tool versions in status.log. Do not claim comprehensive coverage or CI automation.
