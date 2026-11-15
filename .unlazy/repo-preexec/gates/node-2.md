# Gates: C6/C7 Execution Interception and Bypass Prevention

Scope: Integrate only the authorized C6 and C7 repo-preexec outcomes.

- [x] N1: The supporting PATH remediation, C6, and C7 ledgers are freshly reverified in that order
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root . --cwd . --reverify --jobs 1 .unlazy/repo-preexec/gates/leaf-2.3.md .unlazy/repo-preexec/gates/leaf-2.1.md .unlazy/repo-preexec/gates/leaf-2.2.md
  EXPECT: ALL MET
  EVIDENCE: automatic-evidence=v1; definition-sha256=117de80711d29f7d2f096a7bd85b3609a31bd1626fa58fc6983224f294ddbb71; exit=0; EXPECT=matched; output-sha256=462ebea66a8c9b767d591eb2985960b5c9ab69d44c149e51b497ac7dbbc6e90c; output-bytes=3389; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N2: The C6 and C7 dedicated test files pass together
  CHECK: python3 -m pytest -q tests/test_repo_preexec_interception.py tests/test_repo_preexec_bypass.py
  EXPECT: /12 passed/
  EVIDENCE: automatic-evidence=v1; definition-sha256=1bda9e1df0690496c2bbb8a439831f210fd81c9028baa888ef6ea76148f66e02; exit=0; EXPECT=matched; output-sha256=cdb7f3dd0ca5aa2f18941ab7046221b4df83e6223812a1cb3d5e5d9ebe9326e7; output-bytes=99; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N3: Branch test outcomes match their authorized contract rows
  EVIDENCE: manual-verification=completed; reviewed Revision 7 C6/C7 contract rows, child ledgers G2.1.1-G2.1.2 and G2.2.1-G2.2.2, supporting G2.3.1, and fresh N1/N2 results. C6 covers clone review before repository script execution and pre-execution inspection of shell, build, and dependency-install commands. C7 covers managed-shim alternate shells/interpreters, aliases to managed shims, and controlled child PATH; absolute executable paths and deliberate caller PATH reordering remain Revision 6 limitations.

- [x] N4: Every child lease is released only after parent verification and manual review
  EVIDENCE: manual-verification=completed; status.log records node-2:N1/N2 verification and N3 review before releases; supporting leaf-2.3 lease f48a84c501d68d5ff43f9663078f9cc3, C6/leaf-2.1 lease fc3f43bdaf0217cf756fd5829b817721, then C7/leaf-2.2 lease 2390eaf7936a76615c6990feeb326740 were released in that order.
