# Gates: C6 Installed-Wrapper Execution Interception - leaf-2.1

OWNS: tests/test_repo_preexec_interception.py

Scope: Add dedicated installed-wrapper tests for C6's Git clone, shell-script, build-command, and dependency-install interception outcomes. Production source and existing P3/P4-owned files are outside this leaf.

- [x] G2.1.1: An installed Git clone may finish downloading, but the cloned repository is reviewed before a repository script is run
  CHECK: python3 -m pytest -q tests/test_repo_preexec_interception.py::test_installed_git_clone_reviews_before_repository_script_runs
  EXPECT: /1 passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4920c7d8ba7987db8eb99a32b18b36139918ac599117fd38b7e9f18d7c14abf7; exit=0; EXPECT=matched; output-sha256=349b8ae331d4ff184883b4afc5659dccb9dfbcdb67fd52d3df59efa16c832b54; output-bytes=99; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2.1.2: Installed shell-script, build-command, and dependency-install invocations are intercepted and inspected before their repository actions execute
  CHECK: python3 -m pytest -q tests/test_repo_preexec_interception.py::test_installed_shell_script_is_scanned_before_execution tests/test_repo_preexec_interception.py::test_installed_build_command_is_scanned_before_execution tests/test_repo_preexec_interception.py::test_installed_dependency_install_is_scanned_before_execution
  EXPECT: /3 passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=88fa912364db26b458febca42b6c651fda739a7d955ebb739ffe629d727d2ecb; exit=0; EXPECT=matched; output-sha256=b0e8e8f82cb7d36e06b736577334a859c28d809ad472cd539891ee1066914b24; output-bytes=98; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries
