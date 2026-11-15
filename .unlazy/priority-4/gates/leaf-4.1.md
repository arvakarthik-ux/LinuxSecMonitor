# Gates: Installable Wrapper Lifecycle - 4.1

OWNS: pyproject.toml, main.py (wrapper-integration only), lsm_build_backend.py, MANIFEST.in, src/wrapper/install.py, src/wrapper/path.py, src/wrapper/config.py, src/wrapper/__init__.py (packaging only), tests/test_wrapper_install.py, tests/test_wrapper_path.py, tests/test_wrapper_config.py, tests/test_main.py, tests/test_wrapper_installed_wheel.py (new), tests/p4_1_home_rc_guard.py, .unlazy/priority-4/**
EXCLUDE: README.md (dirty with P3 work - do not touch), src/wrapper/core.py, src/wrapper/git_clone.py, scanner/**, tests/test_git_integration.py, tests/test_execution_guard.py (P3 work - no changes unless a directly required minimal fix is identified and justified first)

Scope: Package and expose the opt-in command wrapper so a user can install, inspect, and uninstall it without importing LinuxSecMonitor from a source checkout. Depends on existing P3 wrapper implementation. Not P4.2-P4.6.

Overall status: P4.1 COMPLETE; G1-G6 are satisfied. P4.2-P4.6 remain proposed.

Historical status amendment (2026-11-15): The proposed status above reflects the P4.1 closeout
point. Later user-authorized bounded scopes P4.2-P4.6 have passing evidence in their leaf gates
and the append-only status log.

- [x] G1: Wheel and sdist built from current project include src.wrapper and required modules
  CHECK: rm -rf /tmp/p41-dist && python3 -m build --no-isolation --outdir /tmp/p41-dist . && python3 -c "import glob,sys,tarfile,zipfile; whl=glob.glob('/tmp/p41-dist/*.whl'); sd=glob.glob('/tmp/p41-dist/*.tar.gz'); assert whl and sd, 'missing wheel or sdist'; z=set(zipfile.ZipFile(whl[0]).namelist()); t=set(tarfile.open(sd[0]).getnames()); req=['src/wrapper/__init__.py','src/wrapper/core.py','src/wrapper/install.py','src/wrapper/git_clone.py','src/wrapper/path.py','src/wrapper/config.py','scanner/execution_guard.py','scanner/child_environment.py','main.py']; wmiss=[r for r in req if r not in z]; smiss=[r for r in req if not any(n.endswith('/'+r) for n in t)]; print('wheel missing:',wmiss); print('sdist missing:',smiss); sys.exit(1 if wmiss or smiss else 0)"
  EXPECT: /wheel missing: \[\]/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: `python3 -m build --no-isolation --outdir /tmp/p41-final-d4nsjW/dist .` succeeded; wheel and sdist inspection reported `wheel missing: []` and `sdist missing: []` for all required modules.

- [x] G2: Clean temporary venv installs the wheel offline; src.wrapper imports resolve to venv site-packages, not the source checkout
  CHECK: rm -rf /tmp/p41-venv && python3 -m venv /tmp/p41-venv && /tmp/p41-venv/bin/python -m pip install --no-index --no-deps --quiet /tmp/p41-dist/*.whl && /tmp/p41-venv/bin/python -c "import src.wrapper, src.wrapper.install, src.wrapper.core; paths=[src.wrapper.__file__, src.wrapper.install.__file__, src.wrapper.core.__file__]; assert all(p.startswith('/tmp/p41-venv/') for p in paths), paths; assert '/home/kali/LinuxSecMonitor' not in ' '.join(paths), paths; print('installed:', paths[0])"
  EXPECT: /installed: \/tmp\/p41-venv\/.*site-packages/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: Created `/tmp/p41-final-d4nsjW/venv`, installed the fresh wheel with `pip install --no-index --no-deps`, and imported from `/tmp/p41-final-d4nsjW/outside`; `src.wrapper`, `src.wrapper.install`, and `src.wrapper.core` all resolved under the venv's `site-packages`.

- [x] G3: Focused existing tests pass (wrapper install/path/config + main CLI)
  CHECK: python -m pytest tests/test_wrapper_install.py tests/test_wrapper_path.py tests/test_wrapper_config.py tests/test_main.py -q
  EXPECT: /\d+ passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: `python3 -m pytest -vv tests/test_wrapper_install.py tests/test_wrapper_path.py tests/test_wrapper_config.py tests/test_main.py` — 212 passed in 21.02s with the shared `guard_primary_home_rc` autouse fixture active in all four modules. Isolated reverify on `codex/priority-4`: the same command — 213 passed in 18.14s.

- [x] G4: New installed-wheel integration test passes all P4.1 scenarios
  CHECK: python -m pytest tests/test_wrapper_installed_wheel.py -q
  EXPECT: /\d+ passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py` — 11 passed in 17.77s with the shared `guard_primary_home_rc` autouse fixture active. Temporary-HOME checks covered fresh bash resolution and `git --version`, clone dispatch through the installed wrapper to real Git outside the checkout (expected fail-closed return without a controlling TTY; no post-clone-review claim), reinstall idempotency, backup/uninstall, conflict and foreign-file preservation, broken-package behavior, and primary-HOME RC size/hash protection. After the later P4.2-P4.6 tests were added, isolated reverify on `codex/priority-4` ran the same command — 59 passed in 27.98s with the guard active.
  REQUIRED SCENARIOS (must be covered by tests in this file, all with temporary venv + temporary HOME):
  a. install under temp HOME + supported shell changes only expected user-scoped files (shims, RC block, backup) - nothing else
  b. fresh shell: git resolves through installed shim; git --version reaches real executable and succeeds
  c. local repo git clone invoked outside the checkout enters the installed wrapper then reaches the real git executable (entry observable; NOT a P4.2 post-clone review claim)
  d. repeated installation is idempotent (RC + shims byte-identical after reinstall)
  e. uninstall removes only LinuxSecMonitor-owned shims/RC block and restores original git resolution
  f. conflict case (pre-existing non-LSM file at shim path) is detected, not overwritten
  g. backup created on first install and pristine backup not clobbered by reinstall; restore path works
  h. missing/broken package: shim exits nonzero with clear message + documented recovery path; never silently falls back to unwrapped execution
  i. no test or setup step modifies the primary user's shell configuration (real HOME RC files untouched)

- [x] G5: Generated shim contains no source-checkout dependency
  CHECK: python3 -c "import os,tempfile,shutil,sys; from pathlib import Path; sys.path.insert(0,'/home/kali/LinuxSecMonitor'); from src.wrapper.install import WrapperInstaller; from src.wrapper.config import WrapperConfig; home=tempfile.mkdtemp(prefix='p41-shim-'); cfg=WrapperConfig(wrapper_dir=str(Path(home)/'.local'/'bin'), config_dir=str(Path(home)/'.config'/'linuxsecmonitor'), wrapper_commands=['git'], backup_shell_rc=True); old=dict(os.environ); os.environ['HOME']=home; os.environ['SHELL']='/bin/bash'; Path(home,'.bashrc').write_text('# test\n'); r=WrapperInstaller(cfg).install(shell='bash'); shim=Path(home)/'.local'/'bin'/'lsmonitor-git'; text=shim.read_text(); os.environ.clear(); os.environ.update(old); shutil.rmtree(home, ignore_errors=True); assert r.success, r.errors; bad=['/home/kali/LinuxSecMonitor','sys.path.insert','wrapper_root']; hits=[b for b in bad if b in text]; print('shim violations:', hits); assert not hits, hits"
  EXPECT: /shim violations: \[\]/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: Installed-wheel CLI from `/tmp/p41-final-d4nsjW/venv` installed into `/tmp/p41-final-d4nsjW/shim-home`; generated `lsmonitor-git` was checked for the checkout path, `sys.path.insert`, and `wrapper_root` — `shim violations: []`.

- [x] G6: Bounded security review completed with no unresolved blocking findings
  CHECK: (manual gate - orchestrator records lsm-security-auditor result for exactly these four areas: shell RC ownership, PATH behavior, uninstall safety, broken-shim handling)
  EXPECT: /no unresolved blocking findings/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: The OpenCode delegation record verifies parent session `ses_e344facdfffedO2GkHJKnDoAHs` (`lsm-orchestrator`) spawned child session `ses_e3441650bffeP0mHv7TTod6XWg` (`lsm-security-auditor`, model `opencode/nemotron-3.5-lightning-free`). The auditor's own stored response gives verdict APPROVE WITH CONDITIONS and reports no blocking findings across all five reviewed areas. All conditions are satisfied: (1) shared `guard_primary_home_rc` autouse fixture is imported by every G3 module and the G4 module (`tests/p4_1_home_rc_guard.py`); G3 passed 212 tests and G4 passed 11 tests with the fixture active, which snapshots only RC file size and SHA-256 without printing or modifying RC contents; (2) `_ensure_shell_rc_backup()` retains the `O_NOFOLLOW` availability guard at `src/wrapper/install.py:445-447`; (3) `_fail()` exit-127 behavior and the `main()` try/except guard remain at `src/wrapper/install.py:64-95`. Verdict: APPROVE WITH CONDITIONS; conditions satisfied; no blocking findings. G6 PASS.
