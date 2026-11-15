# Gates: Git Command Integration - 3A.5

OWNS: src/wrapper/commands.py, src/wrapper/core.py, src/wrapper/detection.py, src/wrapper/scanners.py, src/wrapper/git_clone.py, scanner/execution_guard.py, tests/test_git_integration.py, tests/test_wrapper_commands.py, tests/test_execution_guard.py

Amendment (3A.5): ownership expanded for the post-clone review implementation —
`src/wrapper/git_clone.py` (replaces the unimplementable planned
`src/wrapper/commands/git.py`; a `commands/` package would collide with the
existing `src/wrapper/commands.py`), `scanner/execution_guard.py` (optional
`prompt` parameter only), and `tests/test_execution_guard.py` (focused prompt
test only). Gates G1-G8 below are existing 3A.5 classification/workflow
evidence; G9-G16 are the new post-clone objective gates and are written as
unchecked until executed with evidence.

Scope: Git command classification, clone/checkout workflows, hook/config analysis, approval integration

- [x] G1: Git commands correctly classified (clone, checkout, pull, fetch, merge, rebase, reset, submodule)
  CHECK: python -m pytest tests/test_git_integration.py::TestGitCommandClassification -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=98cb63e5fa599a0b8d16fbaaadb2541d436bced349870399a9946677b720cc67; exit=0; EXPECT=matched; output-sha256=b2a31b998db4b19c8151a352adb0e9840cba224cab655b671008d5abfbc2f16c; output-bytes=2725; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2: Git clone workflow - repository inspected before dangerous operations
  CHECK: python -m pytest tests/test_git_integration.py::TestGitCloneWorkflow -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b7fe26405621a583056d5705ed193924a200e143afb1e9a6cd633bd40cc2c870; exit=0; EXPECT=matched; output-sha256=f4c32343d5447e80ba3f1b8c20e0c272562c6aa6c6ca4b4d3706657083dc5eeb; output-bytes=689; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G3: Git checkout/switch/branch operations require scan and approval
  CHECK: python -m pytest tests/test_git_integration.py::TestGitCheckoutWorkflow -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3f007e53f3139b120c978a22e38ce63c7e841c954a5fcf2f636df48ba1f5ea0e; exit=0; EXPECT=matched; output-sha256=08e53d85628f036272ba28e2488786ea436b200bcbddce84915ad3f329f56af1; output-bytes=781; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G4: Git hook and configuration analysis integrated with security scanner
  CHECK: python -m pytest tests/test_git_integration.py::TestGitHookConfigAnalysis -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=26ffe0b6ec6a2fd438c2af173d2f079ff239f8193824a4829691005575b1e435; exit=0; EXPECT=matched; output-sha256=7e246e0e00034c5c1ca4ba5b06165c104f6fd1dc3293fc2647ec5228085b20ef; output-bytes=733; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G5: Approval and cancellation work for Git commands
  CHECK: python -m pytest tests/test_git_integration.py::TestGitApprovalCancellation -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=64de2efc0265443cea906b79ee0d0d0da9d437da05153aa2515216c284dc0d01; exit=0; EXPECT=matched; output-sha256=73f5689aa093caab005e60cd93de09223cab3b0eadda387c728e7517643cd4d4; output-bytes=713; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G6: Original argv preserved for Git commands
  CHECK: python -m pytest tests/test_git_integration.py::TestGitArgvPreserved -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b6c3c288f5c8a2032ab36ccdf009d03a4a7f098ec90aab181e5a87a8a0ff0049; exit=0; EXPECT=matched; output-sha256=0290759e2410db132c2f609c741e6cdff354d27a167cf792eba7f447f164e8f8; output-bytes=790; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G7: All 3A.5 focused tests pass
  CHECK: python -m pytest tests/test_git_integration.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=837fd999c3cf075ff8dd7a60f74682a4018ea91970b172c4f4add7a812aad27d; exit=0; EXPECT=matched; output-sha256=47d4c77401bb969450abfd21f7b6e65302c73e8bfc9b15f38a9f084b4a21c6d0; output-bytes=10804; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G8: Relevant existing regression tests still pass
  CHECK: python -m pytest tests/test_wrapper_commands.py tests/test_wrapper_core.py tests/test_wrapper_scanner_integration.py tests/test_execution_guard.py tests/test_repository_scanner.py tests/test_repository_malware_scanner.py tests/test_repository_security_scanner.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f1601871bcd94a1c1c84e556bb2cde77342a3f46ec365247405a4768cefc5562; exit=0; EXPECT=matched; output-sha256=bcc1eacfdf9c08baa8dfe740ee347a2caf4e75fdaa4b24e48ca1a0acb6508c49; output-bytes=20613; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G9: Git clone invocation parser handles Git 2.53 option semantics (value, attached/optional-value, boolean, negation, `--`, permutation), destination derivation (/abs/seed.git, /abs/seed.git/, file:///abs/seed.git, ../seed.git, explicit), and fails closed on 0/>2 positionals, unknown options, missing values, unsafe names
  CHECK: python -m pytest tests/test_git_integration.py::TestCloneInvocationParsing -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=120e47f85127a5aecd0da50d9b5e2d4d240c33b5ba413bb9648cb19d314d71a5; exit=0; EXPECT=matched; output-sha256=7e611044391f5c2665d28fc8a3c64806a621879764726e96ee0d0e990ef22204; output-bytes=2835; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G10: Real local offline clones are executed with original argv and reviewed post-clone: explicit destination and default destination accepted via exact RUN; failed clone returns Git's nonzero status without scanning or prompting; bare clones refuse to claim a worktree review and remain on disk
  CHECK: python -m pytest tests/test_git_integration.py::TestCloneExecutionWorkflow -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b1db3758af540ad274ad912ff7ce08612c436512514318a6b715d69a424b529b; exit=0; EXPECT=matched; output-sha256=61831d44a7257cea8bbba617ad139e65741e2440c2cc5c0e0509c2b0db5d95ae; output-bytes=1279; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G11: Post-clone review fail-closed paths: incomplete coverage, scanner error/unavailable, changed-during-scan, report/current hash mismatch, and malware findings block before any prompt; lowercase `run`, `RUN ` trailing space, empty/EOF, KeyboardInterrupt, and no-TTY never accept and return nonzero; non-malware HIGH finding is displayed and complete scan with exact RUN accepts
  CHECK: python -m pytest tests/test_git_integration.py::TestCloneReviewFailClosed -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c1f9c55ed39b803291fcdf39386ae8be33ef00714c8a7d2cfaa3ffa4375e481e; exit=0; EXPECT=matched; output-sha256=36875ffa9aeace138584c4a05962365de04666d67f929d6c719afc5a8d7ce547; output-bytes=1966; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G12: Post-clone review cache correctness: unchanged content reuses the complete cached result (single scan) but still prompts and can be cancelled; incomplete, stale-hash, and changed-during-scan cached entries are not used; post-prompt mutation invalidates the cache key, returns nonzero, and leaves the clone on disk
  CHECK: python -m pytest tests/test_git_integration.py::TestCloneReviewCaching -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=ee47fc576261cf3082675290649409205aa2bc1e5ed3f59bc20064eb284024d7; exit=0; EXPECT=matched; output-sha256=b623ba2fbd45ae4421513529b3ca7048268ec21f0004200a29b6818d5e135e47; output-bytes=1112; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G13: Post-clone acceptance is isolated: ApprovalManager.request_approval is never called by the clone path; a subsequent protected Tier 1 command still requires (and can refuse) its own approval even after a successful clone review; Tier 1 with no repository context is blocked before execution
  CHECK: python -m pytest tests/test_git_integration.py::TestPostCloneApprovalIsolation -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=65d57e6661da292ae419a83083bd2cd06633c7f3e375707d5a685e1b5a63f002; exit=0; EXPECT=matched; output-sha256=2efb8650566c0292a23db887f9ea9141d0cb544e9d84403997481d3e99ea61cd; output-bytes=779; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G14: execution_guard custom prompt support: a custom prompt is displayed, exact RUN remains mandatory (lowercase and trailing-space rejected), and the default prompt text is unchanged when prompt is None
  CHECK: python -m pytest tests/test_execution_guard.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4c58fb9a21ecee7b032b5989bfce4f904d51256c8d3158dffd3b9fbe1d96f6a5; exit=0; EXPECT=matched; output-sha256=ba1c946e6bf43bc8114204ed805a632260923076d66176c65258d46bbf79dbd4; output-bytes=3826; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G15: Relevant regression tests still pass after the post-clone implementation
  CHECK: python -m pytest tests/test_wrapper_core.py tests/test_wrapper_scanner_integration.py tests/test_execution_safety.py tests/test_child_environment.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0898ca01097da82d5575d1a4b5cc0c2d317398a03184beb89e1fb7f6da143266; exit=0; EXPECT=matched; output-sha256=1bb1ca391cc783b3cb04ef44ba3dd0fe6a61c4eef9524fd4ffe4e61df16bbf86; output-bytes=17706; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G16: All 3A.5 focused tests pass after the amendment
  CHECK: python -m pytest tests/test_git_integration.py tests/test_execution_guard.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7fa5bd6c1fc5bd887b69ec002a264afc071e8c395bb3b32a3d404b3b4ee6b24d; exit=0; EXPECT=matched; output-sha256=dd1b7f844f627020203a3614650ab3898784dc5dcab155acc2070e28c0eae0ab; output-bytes=14232; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries