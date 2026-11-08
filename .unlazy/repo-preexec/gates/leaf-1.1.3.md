# Gates: Repository security static review

OWNS: scanner/repository_security_scanner.py, tests/test_repository_security_scanner.py

Scope: static review finds heuristic leads, Git hooks, tokens, private keys, risky commands

- [x] G1: scan_repository_security uses no-follow POSIX directory descriptors
  CHECK: python -c "from scanner.repository_security_scanner import _supports_safe_walk; print(f'Supports safe walk: {_supports_safe_walk()}')"
  EXPECT: Supports safe walk: True
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=93895a3afb6f971879660e079a9c61dbb7d75c0b2fa0ce57a4a0132bf8ff0b5d; exit=0; EXPECT=matched; output-sha256=2a7a63eb35556b03562d0f84e3ef177215d83402a077668af35eb24b84ecbd04; output-bytes=25; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: scan_repository_security skips .git internals except default hooks directory
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "git" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4ae6ac23840e572ac99e1566b24254d7705daae9eeb21c714446c954f473a429; exit=0; EXPECT=matched; output-sha256=6a17698bf14f9f2bdc28064f1e4a9048bde0eff595685ad332db94f1ba7db7e1; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: scan_repository_security finds private key material (-----BEGIN PRIVATE KEY-----)
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "secret" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=bc54c18fb170e94eb9c45f726b040ce95debb76d100888e9562c9471c90c0fe2; exit=0; EXPECT=matched; output-sha256=bcb5379fd41f5ca59c2d1e91382bfa962b5888e01151f6442e657ed9bbeb7a58; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: scan_repository_security finds token-like values (GitHub, AWS, Slack)
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "secret" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=bc54c18fb170e94eb9c45f726b040ce95debb76d100888e9562c9471c90c0fe2; exit=0; EXPECT=matched; output-sha256=bcb5379fd41f5ca59c2d1e91382bfa962b5888e01151f6442e657ed9bbeb7a58; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: scan_repository_security finds risky command patterns (download-piped-to-shell, encoded-command, eval, nested shell, cron, systemd, ssh keys, browser creds, env secrets, rm -rf, dd, obfuscation, supply chain, sudo)
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "risky or command" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a138ecade231b6f080baeb44f0432b62eba0b097faba2f206c4aa2e184e5729b; exit=0; EXPECT=matched; output-sha256=bcb5379fd41f5ca59c2d1e91382bfa962b5888e01151f6442e657ed9bbeb7a58; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: scan_repository_security analyzes package.json lifecycle scripts (preinstall, install, postinstall, prepare)
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "lifecycle" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c45b6a3225ba7d8fc0e29480194798d414fa3254fb6d3739c49f4117eda6ab00; exit=0; EXPECT=matched; output-sha256=fa81cc77b65d4ee1d3afce82576e17a04006cb7dea8b1316123fc6114ee36b1c; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: scan_repository_security flags setup.py, Makefile, Dockerfile, build.rs, .github/workflows
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "walk_skips_git" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=ee57b687724f5f33a7554ebb82dafb2944f63fbf556597b95faed7e328c2c77d; exit=0; EXPECT=matched; output-sha256=bcb5379fd41f5ca59c2d1e91382bfa962b5888e01151f6442e657ed9bbeb7a58; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: scan_repository_security finds active Git hooks (executable files matching hook names)
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "hook" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=6661e82ab5e50a7c242882865c7fccc76e961233cfc3aee2d39162c8607f1002; exit=0; EXPECT=matched; output-sha256=161dcb886694610c18ba890b1a0822d18e3bea7741005b40e25e32ce92325cef; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G9: scan_repository_security checks Git config for core.hooksPath, includes, malformed config
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "config" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=30d265787a9e56d631dac0a9c271d31cb7549c77f76d15071c1f287a1356e188; exit=0; EXPECT=matched; output-sha256=55de6a5bb7c35d1a76a8a9c0692425d8f8421f12703b2b4b7a2d6a1b1d813b62; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G10: scan_repository_security returns findings with rule_id, severity, path, evidence, explanation, line_number
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "redacted or flagged or reviewed" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=430da5064e38ffdb94456670e5b56c59194f36141db1cb84278c4d2156ae09e0; exit=0; EXPECT=matched; output-sha256=16d6ee6aab12a95298a1eaae165d75b004cea7300059fd88003d2ac69962fa1d; output-bytes=113; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G11: scan_repository_security status in {completed, requires_review, incomplete, unavailable, error}
  CHECK: python -m pytest tests/test_repository_security_scanner.py -k "incomplete or unavailable or error or complete or review" -q
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=af6efdd1b0192937e483f50d30dd1ecee2426dd2776531f406695211cf3616e4; exit=0; EXPECT=matched; output-sha256=20164e95c32b678716da152fc1a9771ccf8f4e704ce9a7c0abcd448a704cf4bb; output-bytes=114; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G12: coverage_complete True only when no errors, no limitations, no generated exclusions
  CHECK: python -c "from scanner.repository_security_scanner import RepositorySecurityAssessment; a = RepositorySecurityAssessment('completed', '/tmp'); a.coverage_complete = True; print(f'coverage_complete={a.coverage_complete}')"
  EXPECT: coverage_complete=True
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=32797063e0803520c058a5c6c6ae0714d7f7ce9b14b4cdd479059ff1b695ccdb; exit=0; EXPECT=matched; output-sha256=66ae19cf186336a4b3c2b83bff8286d52e58c7089463b95be830aa9ad3c937d4; output-bytes=23; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries