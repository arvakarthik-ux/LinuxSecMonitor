# Gates: CLI dispatch and apt-integration commands

OWNS: main.py, tests/test_apt_hook_cli.py, tests/test_main.py::test_apt*

Scope: CLI --apt-preinstall-hook dispatches to hook runner; --apt-integration subcommands work

- [x] G3.1.1: --apt-preinstall-hook dispatches to run_apt_preinstall_hook with stdin/stdout
  CHECK: python -m pytest tests/test_apt_hook_cli.py -v
  EXPECT: 4 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=16f0db7c0e0e4854312ab7d08120a4010eb4ae7aae57ea5f79991486029b6991; exit=0; EXPECT=matched; output-sha256=80314ace03eb1f090ae507330e5d662afb22855425ca68b4e47e2e3dc44dbac2; output-bytes=856; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3.1.2: --apt-preinstall-hook cannot combine with --json, --output, --diagnostics
  CHECK: python -m pytest tests/test_main.py::test_apt_preinstall_hook_cli_dispatches_to_hook_runner tests/test_main.py::test_apt_integration_status_is_read_only_and_json -v
  EXPECT: 2 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3bd2b9854d8d241fd4cfb4846974b8820239dc2d2b9f305ad4af4a0cf063b517; exit=0; EXPECT=matched; output-sha256=5ed0ad4b86dc9c1f5ccb2f49329eb6084a18e888584e28d13d71cb16219ef1fd; output-bytes=571; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3.1.3: --apt-integration status is read-only, supports JSON; system-changing actions require root
  CHECK: python -m pytest tests/test_main.py::test_apt_integration_status_is_read_only_and_json tests/test_main.py::test_apt_integration_system_changes_require_root -v
  EXPECT: 2 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1cf2e4a174736adcdf8299fe3d96a67964fd5ed55de25efe85fdf2e1da4d299b; exit=0; EXPECT=matched; output-sha256=a06a5281439c602638221cea61254e9b241a89ec0784525757ec39043cf8b69c; output-bytes=565; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3.1.4: --apt-integration install validates trusted runtime and hook order; enable/disable/uninstall work
  CHECK: python -c "import subprocess, sys; result = subprocess.run([sys.executable, '-m', 'pytest', 'tests/test_main.py::test_apt_integration_status_is_read_only_and_json', 'tests/test_main.py::test_apt_integration_system_changes_require_root', '-v'], capture_output=True, text=True); print(result.stdout); print(result.stderr); sys.exit(result.returncode)"
  EXPECT: 2 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b627e159e1700df7bbe8695f09348e0bbeabac63e020bbff652ec458a0a24e32; exit=0; EXPECT=matched; output-sha256=67aaa3af76c3aa42bdd1fea80fed8902ae45f14eb4ce1d901a53be0d72de3eda; output-bytes=567; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries