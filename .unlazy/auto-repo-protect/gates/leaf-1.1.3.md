# Gates: Execution Path Coverage - Interpreter Execution

OWNS: .unlazy/auto-repo-protect/coverage/interpreter.md, .unlazy/auto-repo-protect/gates/leaf-1.1.3.md

Scope: Analyze interpreter execution for interception feasibility, inspection timing, and bypasses

- [x] G1: Python execution methods covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/interpreter.md && grep -q "python -c\|python script" .unlazy/auto-repo-protect/coverage/interpreter.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=415dec17cf5ecc6759d44036a5c0f80e7d59eefe69ca12626b54291f2a9439c7; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G2: Node.js execution methods covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/interpreter.md && grep -q "node -e\|node script" .unlazy/auto-repo-protect/coverage/interpreter.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=4a088ab7bfe4fbf916f9ddcaa51db708d7bafaf63024514c11186446daae4359; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G3: Other interpreters (Perl, Ruby, PHP, Deno, Bun) covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/interpreter.md && grep -q "perl\|ruby\|php\|deno\|bun" .unlazy/auto-repo-protect/coverage/interpreter.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=8eeb144e2ab66288b884d08425cd713dd211da0595a4cf36d83b4d996293bd4c; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G4: Dynamic execution risks documented
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/interpreter.md && grep -q "eval\|exec\|dynamic" .unlazy/auto-repo-protect/coverage/interpreter.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=31b56ed95ae7ad1a39652566d1ffa0a748efac7c04f240df87b08e80e4448bf6; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G5: Package installation execution covered
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/interpreter.md && grep -q "pip install\|npm install\|cargo install" .unlazy/auto-repo-protect/coverage/interpreter.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=3d592d51471bee2b1452ea3f351c0b300e015ef16d3b6d1c32b8ed8996126309; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G6: Bypass analysis for interpreter execution complete
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/interpreter.md && grep -q "Bypass" .unlazy/auto-repo-protect/coverage/interpreter.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=144b4e892a45d36e0291cdca235dbd1196cecfdb476c70178edf2409c2bfe80c; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries

- [x] G7: Coverage matrix includes interpreter operations
  CHECK: bash -c 'test -f .unlazy/auto-repo-protect/coverage/interpreter.md && grep -q "Coverage Matrix\|Summary" .unlazy/auto-repo-protect/coverage/interpreter.md && echo passed'
  EXPECT: passed
  CWD: /home/kali/LinuxSecMonitor
  EVIDENCE: automatic-evidence=v1; definition-sha256=d580c76995b71d0ae0967f306fb8f3c4d0a14978e4f3b97ce824749feee7ae09; exit=0; EXPECT=matched; output-sha256=2700165975f68815c97d605c56eca8e90d497ade1264b6282401d13fee99ac27; output-bytes=7; shell=/bin/sh; cwd=/home/kali/LinuxSecMonitor; path=180b53e155e7/17 entries