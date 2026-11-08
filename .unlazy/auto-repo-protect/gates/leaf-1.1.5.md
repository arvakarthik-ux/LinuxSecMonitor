# Gates: Execution Path Coverage - Dependency Installation

OWNS: .unlazy/auto-repo-protect/coverage/dependency.md, .unlazy/auto-repo-protect/gates/leaf-1.1.5.md

Scope: Analyze dependency installation for interception feasibility, inspection timing, and bypasses

- [x] G1: npm/Node.js dependency installation covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/dependency.md && grep -q "npm install\|npx\|yarn\|pnpm" .unlazy/auto-repo-protect/coverage/dependency.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=18d73547a6a85bcf5267b650b6bcb52da6ce317b56ec3e06d0b5c6d6c992f047; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: pip/Python dependency installation covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/dependency.md && grep -q "pip install\|pipx\|uv\|poetry" .unlazy/auto-repo-protect/coverage/dependency.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=b8f0ed461ef050e78807a1ee7824c4ba4990404e825c3e32edcc1f5513ea2709; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: Cargo/Rust dependency installation covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/dependency.md && grep -q "cargo install\|cargo add\|cargo fetch" .unlazy/auto-repo-protect/coverage/dependency.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=67cc8ef90fab24153825a49daf1bfb62c329a4091a8085a12b86c6f547fd01c8; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: Go dependency installation covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/dependency.md && grep -q "go get\|go mod" .unlazy/auto-repo-protect/coverage/dependency.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e1fa7dbd6aeedcdba61e137ddbc2e15f226f87f307d66114e4f8b850f2287b6e; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: Other package managers (gem, composer, bun, deno) covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/dependency.md && grep -q "gem install\|bundle install\|composer install\|bun\|deno" .unlazy/auto-repo-protect/coverage/dependency.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=c54c8a50594cc6bcf479b6e2afec52a6fbbdfaf873f9fc1806c2aeabe4efb1e1; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: Lockfile and Git/URL dependency handling documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/dependency.md && grep -q "lockfile\|Git.*dependenc\|URL.*dependenc" .unlazy/auto-repo-protect/coverage/dependency.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=5cb6d194f68ce2b78cb83ef9f09f95d5914e6d30b67c052ff65de0bea29daa26; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: Universal wrapper architecture designed
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/dependency.md && grep -q "Universal.*Wrapper\|wrapper.*architect" .unlazy/auto-repo-protect/coverage/dependency.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=e5ea24809d676e65d1ce4f548f854d85a99e9dd208e0cdced71f4c8ebaa3e54b; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: Bypass analysis for dependency installation complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/dependency.md && grep -q "Bypass" .unlazy/auto-repo-protect/coverage/dependency.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=84a9bb0ccf547487088953fb5c67ea9426f5d7c07d018a4393e3b237505ed221; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G9: Coverage matrix includes dependency operations
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/dependency.md && grep -q "Coverage Matrix\|Summary" .unlazy/auto-repo-protect/coverage/dependency.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=f0bf7a028f740fc6cea41138e22a9405cef1992fde8f68c3af4a6a1a5c6d23f3; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries