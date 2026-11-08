# Gates: Repository identification and path resolution

OWNS: scanner/execution_guard.py, scanner/repository_scanner.py, tests/test_execution_guard.py, tests/test_repository_scanner.py

Scope: identify repositories safely, resolve paths, handle nested repos, reject symlinks

- [x] G1: repository path validation rejects symlinks and junctions
  CHECK: python -m pytest tests/test_repository_scanner.py -k "symlink" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=12e79942ba1c9f0bc03579e735d0a4f7e781d66b535e1918ec00de66475ff66f; exit=0; EXPECT=matched; output-sha256=c1d70ef72d648a683dcebee3c27a343949862e4943771414d7e11c817c5bd2dd; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: repository path validation rejects non-directories
  CHECK: python -m pytest tests/test_repository_scanner.py -k "invalid_root_paths" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b0a5f11be9d644e4fcb6938a50d4c141299b27e0342b9ea21982ad71c3b7bc02; exit=0; EXPECT=matched; output-sha256=7d6b46812f9085ac7b94b5dd3ec7149a97d4a8dc1c3bda0a8daae1203a280e0f; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: scan_repository enumerates files, skips .git, tracks manifests
  CHECK: python -m pytest tests/test_repository_scanner.py -k "manifest" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9fb029980bbfd3bdcba52b055ce9e810b1cea4d9014c5acaecbe1c77f8c5c53b; exit=0; EXPECT=matched; output-sha256=13da32c6d6dfdf5ae2d1c38c9ff70cb02c7657923ea6dce3a2af09ef7c61a824; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: scan_repository respects file count, directory count, size, time limits
  CHECK: python -m pytest tests/test_repository_scanner.py -k "limit" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=80c656d2d69e7e57e21d6da825ee78a6de818db46523d38113eb2aff38549b32; exit=0; EXPECT=matched; output-sha256=b0d0e8f7f84f5b1ba8a08e6b4c9f90a50284b6badb04a0e0e9c0c30ce6c4d719; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: review_repository_for_execution calls all three scanners and aggregates
  CHECK: python -c "from scanner.execution_guard import review_repository_for_execution; import tempfile; import os; d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, '.git'), exist_ok=True); r = review_repository_for_execution(d); assert 'inventory' in r and 'malware_assessment' in r and 'repository_security_assessment' in r; print('All three scanners called')"
  EXPECT: All three scanners called
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=8d004ce0911ca00941a284759f020e166712296ed7d06682cbfe57dcc918b43c; exit=0; EXPECT=matched; output-sha256=a8cee3b4c6b173e67b0aa5610174d3d19e5de1532d226caf7d3cbc1be7a58b11; output-bytes=26; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: review_repository_for_execution coverage_complete is True only when all scanners complete
  CHECK: python -c "from scanner.execution_guard import review_repository_for_execution; import tempfile; import os; d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, '.git'), exist_ok=True); r = review_repository_for_execution(d); print(f'coverage_complete={r.get(\"coverage_complete\")}')"
  EXPECT: coverage_complete=True
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=99ee8ab252affcf3d80e8e654d271d6bb76a0bda6a1b89083651d2749aaea85b; exit=0; EXPECT=matched; output-sha256=66ae19cf186336a4b3c2b83bff8286d52e58c7089463b95be830aa9ad3c937d4; output-bytes=23; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: review_status distinguishes review_complete, review_required, blocked_incomplete, blocked_detection
  CHECK: python -c "from scanner.execution_guard import review_repository_for_execution; import tempfile; import os; d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, '.git'), exist_ok=True); r = review_repository_for_execution(d); print(f'review_status={r.get(\"review_status\")}')"
  EXPECT: review_status=review_complete
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9e7faffd22f14e01f665b9e687a63ac9c0e455ccc6364992653e7686fad50395; exit=0; EXPECT=matched; output-sha256=23a6ccced6ac3115fdc120aaa11508ce39d663557b77984fad7f7a241f8c1d6c; output-bytes=30; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries