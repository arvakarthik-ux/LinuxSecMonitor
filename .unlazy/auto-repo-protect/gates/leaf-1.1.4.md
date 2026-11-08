# Gates: Execution Path Coverage - Build Systems

OWNS: .unlazy/auto-repo-protect/coverage/build.md, .unlazy/auto-repo-protect/gates/leaf-1.1.4.md

Scope: Analyze build system execution for interception feasibility, inspection timing, and bypasses

- [x] G1: Make coverage documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/build.md && grep -q "Make\|make " .unlazy/auto-repo-protect/coverage/build.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=0559d6ddf841ca3136ca21933e0ee74add967eba8df2f2d4d3415c34564c6d2b; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: CMake coverage documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/build.md && grep -q "CMake\|cmake" .unlazy/auto-repo-protect/coverage/build.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=843fe11a6eee26e535619db00467fde4cb47948b289fda4d9deb9961eff310e2; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: Cargo/Rust coverage documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/build.md && grep -q "Cargo\|cargo" .unlazy/auto-repo-protect/coverage/build.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=a2b6e4dae4c5eb6426bd1e398fad77830d75bb38948b6b0d499e58f7e09c5ecf; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: npm/Node.js build coverage documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/build.md && grep -q "npm run\|npx" .unlazy/auto-repo-protect/coverage/build.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=79f1d12abc62888d08a8d1fd23b535f15542425a9a9a51263566b7c741a45748; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: Other build systems (Meson, Bazel, Gradle, Autotools, SCons) covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/build.md && grep -q "Meson\|Bazel\|Gradle\|Autotools\|SCons" .unlazy/auto-repo-protect/coverage/build.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d764bd7f705be10f42187d0a35ed2d9f0dd94c58477fba7151e4e41d957f5525; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: Build-time execution risks documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/build.md && grep -q "build-time\|execute_process\|build.rs" .unlazy/auto-repo-protect/coverage/build.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=8d3658bdb2e8a9eeb8195cc0788700fc4539f1da31869c6d498a74aaf046c38c; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G8: Bypass analysis for build systems complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/build.md && grep -q "Bypass" .unlazy/auto-repo-protect/coverage/build.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=838091b8c1a96d8737bc9f2bcc5e8c64dac683603a77daf3fd0c38d835e73241; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G9: Coverage matrix includes build operations
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/build.md && grep -q "Coverage Matrix\|Summary" .unlazy/auto-repo-protect/coverage/build.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=46e7c804042dc680e2f5247acffe7aacec9201ad02a75495513a99a778eb4fd3; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries