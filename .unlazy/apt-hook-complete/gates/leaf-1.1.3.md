# Gates: Terminal approval and privilege dropping

OWNS: scanner/apt_hook.py, tests/test_apt_hook.py::test_*prompt*, tests/test_apt_hook.py::test_*drop*, tests/test_apt_hook.py::test_*terminal*, tests/test_apt_hook.py::test_*privilege*

Scope: Exact terminal approval, irreversible privilege drop to _apt, prompt failure modes

- [x] G1.3.1: _prompt_for_detection requires exact "INSTALL"; fails on nonexact, timeout, EOF, interrupt, no TTY
  CHECK: python -m pytest tests/test_apt_hook.py::test_prompt_fails_closed_when_no_terminal_can_be_opened tests/test_apt_hook.py::test_prompt_fails_closed_when_approval_terminal_is_unavailable tests/test_apt_hook.py::test_prompt_fails_closed_when_terminal_approval_times_out tests/test_apt_hook.py::test_prompt_cancels_when_user_interrupts -v
  EXPECT: 4 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3961ebe70fd4c9675f45a362496da479eab471d2d8feacc75580ea113f209927; exit=0; EXPECT=matched; output-sha256=b5207719430e257ba08e64adff721a64ce45bc97d467ec2beda9a0a04fc785e8; output-bytes=769; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G1.3.2: Hook opens terminal after dropping privileges (drop -> scan -> open -> prompt)
  CHECK: python -m pytest tests/test_apt_hook.py::test_hook_opens_terminal_after_dropping_privileges -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=536269e4dc96fe9e01ce795319210d4f86a8de2ba534851c3198d3d1ea7f56e6; exit=0; EXPECT=matched; output-sha256=a92f9a06a7438e6fdb52bf975cf8010a1673d20899fdb56f6de19729020812de; output-bytes=486; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G1.3.3: _drop_to_apt_sandbox_user irreversibly drops root IDs to _apt user (setgroups, setgid, setuid)
  CHECK: python -m pytest tests/test_apt_hook.py::test_root_scanner_privileges_are_irreversibly_dropped -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4e0b62779eaa50dd69b35b3ac7085d29204b110906e684d366ece5f2546319c4; exit=0; EXPECT=matched; output-sha256=20f2dc7a60fc3b856f0d96e53c9774df93d3d17f6b2cdec86da1f07ea43d6dda; output-bytes=489; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G1.3.4: Privilege drop failure blocks without scanning
  CHECK: python -m pytest tests/test_apt_hook.py::test_privilege_drop_failure_blocks_without_scanning -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=578f6c5b5fa4dd66ed5e813a1f576da95eab2eb893f8ef0d011e7a931dd77560; exit=0; EXPECT=matched; output-sha256=a28b93467eca86ab7893dd65ed0766ed8fb1f9995744863463d06b4a0cbe8f48; output-bytes=487; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G1.3.5: _terminal_safe escapes ANSI and newlines
  CHECK: python -m pytest tests/test_apt_hook.py::test_terminal_safe_escapes_ansi_and_newlines -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=09caf55e37b2e8fce14808a188ddc59d4e785f98c01e45bee36e5c145f79a1f5; exit=0; EXPECT=matched; output-sha256=06266225c5dd7daed8e7627962b1b70f09c82fae82872abd5b3eba8c5bd4425f; output-bytes=480; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries