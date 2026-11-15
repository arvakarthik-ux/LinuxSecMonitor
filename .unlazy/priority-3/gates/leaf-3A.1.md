# Gates: Wrapper Framework Core - 3A.1

OWNS: src/wrapper/**, tests/test_wrapper*.py

Scope: Implement wrapper framework core with command identification, tier classification, repository detection, and content-bound caching

- [x] G1: Wrapper identifies command and finds repo root
  CHECK: python -m tests.test_wrapper_core test_command_identification test_repo_root_detection
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=418c461a066434f21fa442ded7f5ace3103cf74458f509a572cc486118fa7234; exit=0; EXPECT=matched; output-sha256=d2f33f0883bd5d3a5150ce26b90c4bc718405828add688f28f7208b2836eab33; output-bytes=2278; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G2: Tier classification matches spec (Tier 1/2/3)
  CHECK: python -m tests.test_wrapper_commands test_tier_classification
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=af6a75e4e53c4d789e45f1b7c0f6fb0a36355bae565de47690eac5a881428435; exit=0; EXPECT=matched; output-sha256=04821a62ea5b34b1d16c8fcb9ed3b5da98912f2078e52e617c51402b4a16b183; output-bytes=4741; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G3: Cache hit/miss/expiry works correctly
  CHECK: python -m tests.test_wrapper_cache test_cache_hit_miss_expiry
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d073c965b67fbf0ef50fbf3954e47bfa58c5320e3370f097ac30c711b375c348; exit=0; EXPECT=matched; output-sha256=1a872628f56c0e69a268c436405df173a9c61de593666195b0db62a81154c5c6; output-bytes=2711; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G4: Bypass detection for absolute paths, built-ins, inline
  CHECK: python -m tests.test_wrapper_detection test_bypass_detection
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=9e9ec8b9a4f820ba1e1c7e761aff343a31c93f56b11b1f3929ccf6a34abda92f; exit=0; EXPECT=matched; output-sha256=6b6740bf5e7ca1ddf3ecb191cc415cb493fe7a53742533b9164065bbc47d4bed; output-bytes=1982; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G5: Repository detection handles nested, worktree, submodule, symlink cases
  CHECK: python -m tests.test_wrapper_detection test_repo_detection_edge_cases
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=27d37b9ffc731611b0b9fce6bcd3019aa00b31c8a94e8d626fb02a076e97c896; exit=0; EXPECT=matched; output-sha256=4c5e5c9c65695af7521f6b42baf42dbfb5a83593f12b05b98c459bde9f5296b4; output-bytes=1982; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G6: Cache invalidated on repo content, config, scanner, malware db changes
  CHECK: python -m tests.test_wrapper_cache test_cache_invalidation
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=7020f0efe2ef1295cbd47d429142689fa32979cbfe4ead778426da7291833aca; exit=0; EXPECT=matched; output-sha256=1a872628f56c0e69a268c436405df173a9c61de593666195b0db62a81154c5c6; output-bytes=2711; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G7: Wrapper core integrates with existing scanners
  CHECK: python -m tests.test_wrapper_core test_scanner_integration
  EXPECT: /passed/
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e54a0c4b625fac0ee7321fad961f15877b7460acc897eb1e850817249b090b40; exit=0; EXPECT=matched; output-sha256=b09af29e428f5f3c9a001fa8199792c88651db17e047d31be8de6cf396b46f1b; output-bytes=2278; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G8: All 3A.1 focused tests pass
  CHECK: python -m pytest tests/test_wrapper_core.py tests/test_wrapper_commands.py tests/test_wrapper_detection.py tests/test_wrapper_cache.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=52d58aee3da413993ecfcb194f6f63478e8f51d73feb4481021dea65920ab349; exit=0; EXPECT=matched; output-sha256=5f7ce6495fd84a38e46a8f2dc06e3787ae9702bb081b3a85c83dedfb8e191865; output-bytes=10516; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries

- [x] G9: Relevant existing regression tests still pass
  CHECK: python -m pytest tests/test_execution_guard.py tests/test_repository_scanner.py tests/test_repository_malware_scanner.py tests/test_repository_security_scanner.py -v
  EXPECT: PASSED
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d2c55dfdfed4b69e10389623b738b9139447e9f486094df58d756dad2d022d37; exit=0; EXPECT=matched; output-sha256=6081e201ae4532a7176b848547b4cadd14b4465188c5d69cee9e155a7355a4ec; output-bytes=13780; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=ae11111556e7/18 entries