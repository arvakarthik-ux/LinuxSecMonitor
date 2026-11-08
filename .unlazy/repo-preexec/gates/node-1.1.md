# Gates: Repository identification and inspection

Scope: verify children leaf-1.1.1, leaf-1.1.2, leaf-1.1.3 compose to identify and inspect repositories

- [x] N1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.1.1.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.1.2.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.1.3.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9712c516268ab0723e25ae72eb84b5e62b95eb1adb05351009e37a4d107b9e86; exit=0; EXPECT=matched; output-sha256=bbe61793411e96b032e5fae9d2bb4d013bb20b1524d80f591e08c9227d91b128; output-bytes=16275; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N2: repository identification resolves paths safely, rejects symlinks, handles nested repos
  CHECK: python -m pytest tests/test_repository_scanner.py -k "invalid_root_paths or symlink" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=432a18654df2d4482cc453892e49b842ae8ecbd4425b5238416cda5ea57ce81b; exit=0; EXPECT=matched; output-sha256=8c5bb6de813be923e4769530be516225827a3e7c234dd46d3258615d258e7274; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N3: repository malware scan runs ClamAV on staged snapshot, never executes repo code
  CHECK: python -m pytest tests/test_repository_malware_scanner.py -k "malware" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=53e61ba0ea205d8c9f58b4587e868369668367a77952d6ae11cb03f9f024cc68; exit=0; EXPECT=matched; output-sha256=21993a071b820aadd18881a13dcfe6842e68b9c9c98273e23fd15a68c9b7d9f1; output-bytes=99; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N4: repository security static review finds heuristic leads, Git hooks, tokens, private keys
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "security or heuristic or token or key" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=2bf44390e72d97bbe8c8573ddfb0dc37a4cd7d31065f91fb81cf37ff13c37834; exit=0; EXPECT=matched; output-sha256=b94868f37d490c049d68ca6520b4dd7338955511671bceb7743f94a67c88b0db; output-bytes=99; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] N5: repository inventory lists files, manifests, skips .git, handles limits
  CHECK: python -m pytest tests/test_repository_scanner.py -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=62af4373bcb0d1b5ad54a446c8f6575d89aca71e81ab04c935509e26dbc95921; exit=0; EXPECT=matched; output-sha256=044af7835ebc0e80d6e13d203b5537ecf4f236c8dbcf40820ee786efac8e4bd0; output-bytes=99; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries