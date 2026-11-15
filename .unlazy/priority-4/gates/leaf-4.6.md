# Gates: Installed Zsh/Fish Fresh-Shell Activation - 4.6

Status: COMPLETE. This proposed unit was authorized only by the user request
for this task; it was not defined in the approved original Priority 4 roadmap.

Depends on completed P4.1-P4.5, the existing installed wrapper lifecycle, and
the existing P3 Tier 2 `python3 <script.py>` route.

Scope: For Zsh and Fish separately, build/install the current wheel offline,
install the wrapper into a temporary HOME using that shell's existing RC
integration, then launch a fresh interactive shell. Verify startup loads the
temporary PATH integration, `command -v python3` resolves to the installed
shim, and a harmless script in a temporary local Git repository runs only
after the existing scan path completes. Keep the primary-HOME RC guard active.
Use temporary `HOME`, `ZDOTDIR`, and `XDG_CONFIG_HOME` paths as appropriate,
and a test-only child-environment seam so Fish initialization and wrapped
execution cannot write under the real HOME. Do not change production code or
P3 semantics unless a reproducible activation defect is found.

- [x] G1: Offline installed fresh-shell activation routes both shells through the shim and existing scan flow
  CHECK: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledZshFishFreshShellActivation`
  EXPECT: `PASSED`
  EVIDENCE: 2 passed in 9.86s (Zsh and Fish). Each case built and installed the
  current wheel offline into a temporary venv, installed the selected shell's
  integration under temporary HOME, and launched a fresh interactive shell
  with initial PATH limited to `/usr/bin:/bin`. `command -v python3` returned
  the temporary installed shim. In a temporary local Git repository outside
  the checkout, the harmless Tier 2 script completed after event order
  `scan`, `scan_complete`, `marker_action`.

- [x] G2: Existing P3 Tier 2 classification and scanner behavior remains unchanged
  CHECK: `python3 -m pytest -vv tests/test_wrapper_commands.py::TestTier2Commands::test_python_script_tier2 tests/test_wrapper_core.py::TestScannerIntegration::test_tier2_runs_scans`
  EXPECT: `PASSED`
  EVIDENCE: 2 passed in 23.63s. No P3 source or behavior was changed.

- [x] G3: Primary-HOME shell configuration remains unchanged throughout P4.6 test activity
  CHECK: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py::TestInstalledZshFishFreshShellActivation`
  EXPECT: `PASSED`
  EVIDENCE: The same 2-test command passed in 9.86s with the imported
  `guard_primary_home_rc` autouse fixture active. Temporary HOME, ZDOTDIR,
  XDG_CONFIG_HOME, shell RC files, wheel/venv, repositories, Git config,
  scanner bootstrap, and markers were isolated under pytest temporary paths.
  Post-run check confirmed `/home/kali/.config/fish/config.fish` remained
  absent; the existing zsh RC files remained unchanged per the guard. The
  earlier P4.5 real-HOME Fish config creation and cleanup remain disclosed in
  the P4.5 status entry; this gate makes no claim that real HOME was never
  touched historically.

Non-goals: changing wrapper install behavior unless activation is reproducibly
broken; new tiers or command patterns; changing P3 classification, scan,
approval, or execution policy; direct-path/inline/bypass coverage; Git clone;
APT; system-wide enforcement; any work outside P4.6.
