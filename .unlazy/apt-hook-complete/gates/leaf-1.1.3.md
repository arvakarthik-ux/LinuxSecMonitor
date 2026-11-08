# Gates: Terminal approval and privilege dropping

OWNS: scanner/apt_hook.py, tests/test_apt_hook.py::test_*prompt*, tests/test_apt_hook.py::test_*drop*, tests/test_apt_hook.py::test_*terminal*, tests/test_apt_hook.py::test_*privilege*

Scope: Exact terminal approval, irreversible privilege drop to _apt, prompt failure modes

- [x] G1.3.1: _prompt_for_detection requires exact "INSTALL"; fails on nonexact, timeout, EOF, interrupt, no TTY
  CHECK: python -m pytest tests/test_apt_hook.py::test_prompt_fails_closed_when_no_terminal_can_be_opened tests/test_apt_hook.py::test_prompt_fails_closed_when_approval_terminal_is_unavailable tests/test_apt_hook.py::test_prompt_fails_closed_when_terminal_approval_times_out tests/test_apt_hook.py::test_prompt_cancels_when_user_interrupts -v
  EXPECT: 4 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3961ebe70fd4c9675f45a362496da479eab471d2d8feacc75580ea113f209927; exit=0; EXPECT=matched; output-sha256=a8134d0570b1fe6e562bf96799e8bdbcedd2d34131cf2348ff85afacd36f17ef; output-bytes=769; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.3.2: Hook opens terminal before dropping privileges
  CHECK: python -m pytest tests/test_apt_hook.py::test_hook_opens_terminal_before_dropping_privileges -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=244e5c5d62ee3f75cadefaf2689723a463f0ddef9cb1d3bd64cd3123df1255ca; exit=0; EXPECT=matched; output-sha256=fe1d99d8b9ade9946aea0534b711d3808a18b4f1693d05ebb35a55881cdf5d8b; output-bytes=487; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.3.3: _drop_to_apt_sandbox_user irreversibly drops root IDs to _apt user (setgroups, setgid, setuid)
  CHECK: python -m pytest tests/test_apt_hook.py::test_root_scanner_privileges_are_irreversibly_dropped -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4e0b62779eaa50dd69b35b3ac7085d29204b110906e684d366ece5f2546319c4; exit=0; EXPECT=matched; output-sha256=132a2f1b9837f06af0e6a757352da63eccfc322de3020c7ed877ca5b55d81bcf; output-bytes=489; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.3.4: Privilege drop failure blocks without scanning
  CHECK: python -m pytest tests/test_apt_hook.py::test_privilege_drop_failure_blocks_without_scanning -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=578f6c5b5fa4dd66ed5e813a1f576da95eab2eb893f8ef0d011e7a931dd77560; exit=0; EXPECT=matched; output-sha256=96e548cc6a546541cf95fe289360c0fcea718ba344514b81bbd196c37885afb6; output-bytes=487; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G1.3.5: _terminal_safe escapes ANSI and newlines
  CHECK: python -m pytest tests/test_apt_hook.py::test_terminal_safe_escapes_ansi_and_newlines -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=09caf55e37b2e8fce14808a188ddc59d4e785f98c01e45bee36e5c145f79a1f5; exit=0; EXPECT=matched; output-sha256=e502ae774a7c983b9b385ca40738f0bb9b758e09ddc1db48ddb89a22790b7e87; output-bytes=480; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries