# Gates: Repository identification and inspection

Scope: verify children leaf-1.1.1, leaf-1.1.2, leaf-1.1.3 compose to identify and inspect repositories

- [x] N1: every named direct child is reverified from its exact ledger
  CHECK: node /home/kali/.agents/skills/unlazy/scripts/gate-check.mjs --root /home/kali/LinuxSecMonitor --cwd /home/kali/LinuxSecMonitor --reverify --jobs 1 /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.1.1.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.1.2.md /home/kali/LinuxSecMonitor/.unlazy/repo-preexec/gates/leaf-1.1.3.md
  EXPECT: ALL MET
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9712c516268ab0723e25ae72eb84b5e62b95eb1adb05351009e37a4d107b9e86; exit=0; EXPECT=matched; output-sha256=afac6189e47edef6c9baa1e9fe5c1dd44a8e8b8a8f5a34da5f0ab37aa9ede2ef; output-bytes=16329; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N2: repository identification resolves paths safely, rejects symlinks, handles nested repos
  CHECK: python -m pytest tests/test_repository_scanner.py -k "invalid_root_paths or symlink" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=432a18654df2d4482cc453892e49b842ae8ecbd4425b5238416cda5ea57ce81b; exit=0; EXPECT=matched; output-sha256=8c5bb6de813be923e4769530be516225827a3e7c234dd46d3258615d258e7274; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N3: repository malware scan runs ClamAV on staged snapshot, never executes repo code
  CHECK: python -m pytest tests/test_repository_malware_scanner.py -k "malware" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=53e61ba0ea205d8c9f58b4587e868369668367a77952d6ae11cb03f9f024cc68; exit=0; EXPECT=matched; output-sha256=19cd19134c7de50bfd71adc9152e2416667ce7505e7968c5a04ad0225c7e375f; output-bytes=99; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N4: repository security static review finds heuristic leads, Git hooks, tokens, private keys
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "security or heuristic or token or key" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=2bf44390e72d97bbe8c8573ddfb0dc37a4cd7d31065f91fb81cf37ff13c37834; exit=0; EXPECT=matched; output-sha256=4ae32d4b44fc6466e40994b34ac502cb93aa0f22a73a6b922c7819980d353b2f; output-bytes=99; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] N5: repository inventory lists files, manifests, skips .git, handles limits
  CHECK: python -m pytest tests/test_repository_scanner.py -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=62af4373bcb0d1b5ad54a446c8f6575d89aca71e81ab04c935509e26dbc95921; exit=0; EXPECT=matched; output-sha256=590dbc4f5c123295cd127dfad099b8f0f74b5daff9de9099967616ab6655a2b8; output-bytes=99; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries