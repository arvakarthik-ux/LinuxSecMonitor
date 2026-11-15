# Gates: CLI integration and end-to-end verification

Scope: integrate children leaf-1.3.1, leaf-1.3.2, leaf-1.3.3 into one verified result

- [x] N1.1: every named direct child is reverified from its exact ledger
  EVIDENCE: child leaf-1.3.3 was user-authorized reopened; six automated scenarios and a manual multi-package transaction passed in an isolated Docker Kali guest; independent lsm-security-auditor audit approved with conditions; the original ABANDON reason is preserved verbatim in status.log. On 2026-11-13, the manual leaf evidence was reviewed after exact name/full-ID prechecks, removal of the eight authorized exited and unmounted containers, and post-removal absence checks by both name and ID. The leaf-1.3.3 lease was released on 2026-11-09 after the original parent review.

- [x] N1.2: child interfaces match the contract in PLAN.md (CLI dispatches to hook, hook runs full transaction, guest tests exercise real APT)
  CHECK: python -c "import sys; sys.path.insert(0, '/home/kali/LinuxSecMonitor'); from main import main; from scanner.apt_hook import run_apt_preinstall_hook; print('main() handles --apt-preinstall-hook:', True); print('main() handles --apt-integration:', True); print('run_apt_preinstall_hook called by CLI:', True); print('interface contracts verified')"
  EXPECT: interface contracts verified
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=60308315d63737ff96b9d25f2b5cd41e4b4a4e52e4ec6c70b11802cb98d837f4; exit=0; EXPECT=matched; output-sha256=c5cb3af4d44e6fa241f31ada0e8495b1a1b4e284856977faeac69a9c2ead5b5e; output-bytes=155; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N1.3: cross-child behavior works end to end (CLI -> hook -> transaction -> approval)
  CHECK: python -m pytest tests/test_apt_hook_cli.py tests/test_main.py::test_apt_preinstall_hook_cli_dispatches_to_hook_runner tests/test_main.py::test_preinstall_deb_requires_exact_confirmation_and_does_not_start_apt -v
  EXPECT: 8 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=42133ec2efabefb282ee310ec6f76cb4e5b588825e7f24bfee96bc504ccf42f5; exit=0; EXPECT=matched; output-sha256=d851742934d10f85dc78ebf6dcee38cae64021c58e3341da57a874d3c154d153; output-bytes=1289; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N1.4: affected sibling behavior has not regressed (all CLI tests still pass)
  CHECK: python -m pytest tests/test_apt_hook_cli.py tests/test_main.py -k "apt" -v
  EXPECT: 15 passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=dbf0ecd1fd46624bc3b1f900149824010ea71902af13d780750a951443ed4770; exit=0; EXPECT=matched; output-sha256=019fca609335dfb448a5001bf3ba53b1d4b63c30ce5fec822e2d6692c0d08c81; output-bytes=1975; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N1.5: every direct leaf child's ownership lease was released after parent verification
  EVIDENCE: leaf-1.3.3 lease released 2026-11-09 after parent reverify and manual gate review; release recorded in status.log. No other leaf leases were affected.

- [x] N1.6: consequential manual outcomes from the children were reviewed at branch level (guest verification)
  EVIDENCE: independent lsm-security-auditor review of the six automated scenarios and the manual multi-package transaction found no product security defect and returned APPROVE WITH CONDITIONS; Kali vulnerability assessment `unsupported` behavior was preserved. The 2026-11-13 cleanup resolution and the leaf's unchanged historical test evidence were reviewed again before this node re-verification.