# Gates: C7 Managed-Wrapper Bypass Resistance - leaf-2.2

OWNS: tests/test_repo_preexec_bypass.py

Scope: Verify alternate-shell and interpreter bypass resistance only when commands are mediated by installed wrapper shims. Verify controlled child PATH mediation and aliases to managed shims, not arbitrary aliases to system executables. Absolute executable paths and deliberate caller PATH reordering remain explicit limitations of this user-mediated PATH-wrapper design; this is not system-wide or unbypassable protection.

HISTORY: Original C7 gate outcomes before the Revision 6 scope amendment:
- G2.2.1: Alternate shells, direct interpreter invocations, and PATH manipulation cannot bypass repository review
- G2.2.2: Symlinked interpreter invocations and subprocesses cannot bypass repository review

- [x] G2.2.1: Alternate-shell and interpreter invocations through installed wrapper shims are reviewed, and managed PATH resolution selects the shim in the supported invocation environment
  CHECK: python3 -m pytest -q tests/test_repo_preexec_bypass.py -k "alternate_shells or direct_interpreter or wrapper_first_path"
  EXPECT: /6 passed/
  EVIDENCE: automatic-evidence=v1; definition-sha256=5669bf3d1cbfdffb8ef32740cfbcb064ccd7a24c97d0074a880d1a4a400607d9; exit=0; EXPECT=matched; output-sha256=0b7b09571e3ace2e8fc7d822aaf807137752e83572d9a112061fe0ec8fa91bf3; output-bytes=112; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2.2.2: Managed-shim aliases remain mediated and wrapper-launched child processes use controlled PATH containing the managed-wrapper directory
  CHECK: python3 -m pytest -q tests/test_repo_preexec_bypass.py -k "managed_shim_alias or subprocess_environment"
  EXPECT: /2 passed/
  EVIDENCE: automatic-evidence=v1; definition-sha256=d2536507983b45a4e9f7f663f7d06a248d9698d47b52577469dab0e0f2fd764b; exit=0; EXPECT=matched; output-sha256=0ddca668973492bc726ac0da65104b72bd81359704ccf84772407afa290cfdec; output-bytes=112; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries
