# Gates: C7 Child-PATH Source Remediation - leaf-2.3

OWNS: src/wrapper/core.py

Scope: Prepend the managed-wrapper directory to the sanitized child PATH without forwarding caller-controlled PATH.

- [x] G2.3.1: Wrapper-launched subprocess PATH starts with the managed-wrapper directory and excludes caller-controlled PATH entries
  CHECK: python3 -m pytest -q tests/test_repo_preexec_bypass.py -k subprocess_environment
  EXPECT: /1 passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e719146ba5f97251aa2733f56b450b6ab35ad32ab597a364b7c82b06e5ec3a3e; exit=0; EXPECT=matched; output-sha256=dad6beda9e6adce2343894723a3b8ec22d746628eac5a38f4671f7cec4ca8798; output-bytes=112; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries
