# Gates: Trusted runtime and hook order validation

OWNS: scanner/apt_lifecycle.py, tests/test_apt_lifecycle.py::test_trusted*, tests/test_apt_lifecycle.py::test_hook_command*

Scope: Validate trusted runtime paths, ensure hook order precedence, reject shell metacharacters

- [x] G2.2.1: validate_trusted_runtime rejects non-root-owned or user-writable interpreter/module paths
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_trusted_runtime_rejects_user_writable_code_parent -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4727831a00061eaced0d894604d9fbb3128ff51842485684404be7096aa57d36; exit=0; EXPECT=matched; output-sha256=f76d98980edfb1dff356dc4a8e9bcdec414f9162fc213a3acc3874b9d82eb9e3; output-bytes=495; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2.2.2: validate_effective_hook_order ensures LinuxSecMonitor hook is first effective Pre-Install-Pkgs
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_managed_dropin_precedes_later_preconfigure_and_main_config -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=1a154b895b7a808a8be11439bf22d000830778aeddc67ba37aa6b41d1407e2dc; exit=0; EXPECT=matched; output-sha256=173274d8e004238a285919e627187db62d30ecc93163df350d1c77620a65fc7e; output-bytes=504; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2.2.3: hook_contents rejects shell metacharacters in python path
  CHECK: python -m pytest tests/test_apt_lifecycle.py::test_hook_command_rejects_shell_metacharacters -v
  EXPECT: 4 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6314022e21cd02ced0dd773995172c0da6354c4e6b17dfd75e388b580ea751ff; exit=0; EXPECT=matched; output-sha256=d147f3daef7f11bd5f7f403a2a7c423f7d8b26152c273dd9c51361591a8fb205; output-bytes=838; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries