# Gates: Repository malware and inventory scanning

OWNS: scanner/repository_malware_scanner.py, tests/test_repository_malware_scanner.py

Scope: malware scan runs ClamAV on staged snapshot, never executes repo code, handles limits

- [x] G1: scan_repository_malware stages files using no-follow directory descriptors
  CHECK: python -c "import os; from scanner.repository_malware_scanner import _supports_safe_walk; print(f'Supports safe walk: {_supports_safe_walk()}')"
  EXPECT: Supports safe walk: True
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0d3a5971161ad37a9ab3e7b8afd66e788eb24d7a4b4d329af90eacde8ac26908; exit=0; EXPECT=matched; output-sha256=2a7a63eb35556b03562d0f84e3ef177215d83402a077668af35eb24b84ecbd04; output-bytes=25; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G2: scan_repository_malware copies regular files only, skips symlinks, .git, non-regular
  CHECK: python -m pytest tests/test_repository_malware_scanner.py -k "symlink or git or non_regular" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9599a8d8b606393eadd7c0ad2a660a86513e433a1cd2f04f76ae762caddb24dc; exit=0; EXPECT=matched; output-sha256=9371d13fd3f9668ee79d49be6d48ec286e34875696728814881636b95c132356; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G3: scan_repository_malware runs ClamAV with --infected --recursive --scan-archive=yes --alert-encrypted --alert-exceeds-max
  CHECK: python -c "import subprocess; from scanner.repository_malware_scanner import scan_repository_malware; import tempfile; import os; d = tempfile.mkdtemp(); r = scan_repository_malware(d); print(f'status={r.status}, files={r.files_scanned}')"
  EXPECT: status=no_detection
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e2a74f11ffddd17fbfad4db51d2f4aebeb1333c7d824d223bcddb476b1e9f845; exit=0; EXPECT=matched; output-sha256=6276f3ba4102efbdd35a4d46b00d7fcb8011ec3b8011e05e5bb39f3239b37386; output-bytes=29; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G4: scan_repository_malware returns detections with mapped repository-relative paths
  CHECK: python -m pytest tests/test_repository_malware_scanner.py -k "detection" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7608cf3a8c8567b7f6acc9f72805539163e1d03e1878467d47c28ca2cde88a40; exit=0; EXPECT=matched; output-sha256=3ce2335b55e893fe5a82f0e91853f310d3afd5be8acab17aaaf184030b6ca8fe; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G5: scan_repository_malware handles encrypted archives, scan limits, timeouts
  CHECK: python -m pytest tests/test_repository_malware_scanner.py -k "encrypted or limit or timeout" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=51c08aba65783b90b38664b2205ccda2c2b163cb39e5d2262051647db0930d0e; exit=0; EXPECT=matched; output-sha256=da6904f29d5f8a13e0be2b49b4969f75a7bd47428c6daba0d2011ce3dd85a32a; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G6: scan_repository_malware returns status in {detected, no_detection, incomplete, error, unavailable}
  CHECK: python -m pytest tests/test_repository_malware_scanner.py -k "clean or detection or incomplete or unavailable or error" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=79e4d14ee4447df98781268c7e733f5e13f64fccb4666bf941807d8de6aa1649; exit=0; EXPECT=matched; output-sha256=d7094fdd4681bc5b1e7add09b3c5f6b4d16b1f3375d2ddb3ce61b08ea98666e7; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G7: coverage_complete is True only when no errors, no limitations, no skipped entries, no detections
  CHECK: python -c "from scanner.repository_malware_scanner import RepositoryMalwareAssessment; a = RepositoryMalwareAssessment('no_detection', coverage_complete=True); print(f'coverage_complete={a.coverage_complete}')"
  EXPECT: coverage_complete=True
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=de077b7b81e4e3af4cc998891cabd175ed3ddfc3d8706167d9b438bd5d7afb06; exit=0; EXPECT=matched; output-sha256=66ae19cf186336a4b3c2b83bff8286d52e58c7089463b95be830aa9ad3c937d4; output-bytes=23; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries

- [x] G8: scan_repository_malware uses trusted /usr/bin/clamscan, not PATH
  CHECK: python -c "from scanner.repository_malware_scanner import _find_clamscan; import tempfile; import os; d = tempfile.mkdtemp(); path, err = _find_clamscan(d); print(f'clamscan path: {path}, error: {err}')"
  EXPECT: clamscan path: /usr/bin/clamscan
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6248abd9ff2d69b5ceb6777b8fbf7d237548ef3d15400033986cd33b882bbf51; exit=0; EXPECT=matched; output-sha256=77bfe7dcb5315f76343d097d8b582473dd66e01cdc02f77bfa274bbde64151ad; output-bytes=46; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=1e35329a0108/13 entries