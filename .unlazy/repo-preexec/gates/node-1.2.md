# Gates: Approval workflow and fail-closed behavior

Scope: verify children leaf-1.2.1, leaf-1.2.2 compose to approve or block execution

- [x] N1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.2.1.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.2.2.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=51be2dcf4d003742ff06f53012e53a27db61d07218996b031a4e1ce0383cb9fd; exit=0; EXPECT=matched; output-sha256=30178e1e7adbbd792cc77752d81c025805bb3df6f79aa61ef3f048839aea6882; output-bytes=12395; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N2: explicit RUN approval required; rejects lowercase, trailing space, empty, EOF
  CHECK: python -m pytest tests/test_execution_guard.py -k "approval or cancel" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=90a4e293242aca82446eaebee39e4ab4dbcd002754fa8c512ce8e6c4454f1c27; exit=0; EXPECT=matched; output-sha256=c8cd5e5ed6893158b3832b7433937831bb2fa1889578d5ef5f141d9c3f967239; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N3: fail-closed blocks on incomplete scan, detection, scanner error, no TTY
  CHECK: python -m pytest tests/test_execution_guard.py -k "incomplete or detection or blocked or tty" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=fbf0e965cf81d5c223dbe6b0e7c21d9b3624d9c0d2c9fbe34eb80316c43e6b41; exit=0; EXPECT=matched; output-sha256=f7b6d4902b4ccb25fc868a19e86c309b7e3182ec2d1a4d297ebcc9c066d90c3e; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N4: command runs without shell, in resolved repo directory, with correct exit code
  CHECK: python -m pytest tests/test_execution_guard.py -k "argv or shell or exit" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e84f659d1720d4adf401ff4851fda06aa0ba84adbc09fbfacc58a78c2365d6b8; exit=0; EXPECT=matched; output-sha256=ae528ddf52dc0e37f08564a5eade01312942414c92ff99fd91c2b46a8865a90f; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N5: limitations documented (advisory only, not sandbox, concurrent writers not controlled)
  CHECK: python -c "from scanner.execution_guard import review_repository_for_execution; r = review_repository_for_execution('/tmp'); assert 'advisory' in str(r['limitations']).lower(); assert 'sandbox' in str(r['limitations']).lower(); print('Limitations documented')"
  EXPECT: Limitations documented
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=cadf320b7d7f5d6127c5bc9e3b80abe6d06649460b29114174c108f51010b83d; exit=0; EXPECT=matched; output-sha256=ffbfe7fc90203148c3aeb5f8b679ed30c7b719f834c0a86486f62f7d72ccac95; output-bytes=23; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N6: Manual review confirms every named child gate is met and source, tests, and criteria are unchanged
  EVIDENCE: Reviewed exact ledgers leaf-1.2.1 G1-G11 (11/11 met) and leaf-1.2.2 G1-G10 (10/10 met) after fresh sequential reverify. Both OWNS sets exactly match the node-1.2 group lease paths. Inspected run_reviewed_command fail-closed branches and tests for incomplete coverage, detection, invalid argv, runner errors, and secret omission; no counterexample found. This task changed only node-1.2 coordination gates, leaf dispatch state, and status records; no application source, tests, or existing criteria changed.

- [x] N7: Post-release record documents the successful parent group lease event
  EVIDENCE: GROUP-LEASE RELEASED event=a7d2a015c9b5dba87ee4e451aa30f1e9 group=8058686538dc03bd187c2aa3e6ce4d62 parent=node-1.2 children=leaf-1.2.1,leaf-1.2.2; original lease identity 8920cf1894a41ceaa6e5291e02cde3a8 and claim time preserved by the in-place promotion