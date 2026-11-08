# Threat Model

## Protected Assets

| Asset | Description | Value |
|---|---|---|
| **User's code & data** | Source code, configs, credentials, keys | High |
| **System integrity** | OS, installed packages, kernel | Critical |
| **Network access** | Outbound connections, lateral movement | High |
| **Compute resources** | CPU, memory, disk (cryptojacking) | Medium |
| **Supply chain trust** | Downstream users of user's packages | High |
| **Reputation** | Compromised accounts, leaked secrets | High |

---

## Attacker Capabilities

### Threat Actor: Malicious Repository Author
**Goal**: Execute code on victim's machine when they interact with the repo

**Capabilities**:
- Craft repository with malicious content
- Use obfuscation, encoding, polyglot files
- Exploit build tools, package managers, Git hooks
- Social engineering (convincing README, fake legitimacy)
- Time-bomb: benign initially, malicious later

**Access**: Repository content only (no direct system access)

---

### Threat Actor: Compromised Dependency
**Goal**: Execute code via transitive dependency

**Capabilities**:
- Malicious code in npm/PyPI/crates.io package
- Hijacked maintainer account
- Typosquatting, dependency confusion
- Malicious `postinstall`, `build.rs`, `setup.py`

**Access**: Executes during `install`/`build` with user privileges

---

### Threat Actor: Malicious CI/CD / Build System
**Goal**: Execute code during build

**Capabilities**:
- Malicious GitHub Actions, GitLab CI, Jenkins scripts
- Compromised build runners
- Supply chain attacks (SolarWinds-style)

**Access**: Build environment (often elevated)

---

### Threat Actor: Local User (Insider)
**Goal**: Bypass protections, execute unauthorized code

**Capabilities**:
- Modify wrapper scripts
- Use absolute paths
- Disable shell config
- Run commands in containers/VMs
- `sudo` / privilege escalation

**Access**: Full user account control

---

## Untrusted Repository Assumptions

1. **All repository content is untrusted** - files, filenames, symlinks, Git config
2. **Repository can change at any time** - concurrent modifications during scan
3. **Repository can be arbitrarily large** - resource exhaustion via limits
4. **Repository can contain malicious filenames** - path traversal, encoding, control chars
5. **Git metadata can be manipulated** - hooks, config, submodules
6. **No code execution during inspection** - scanners are read-only
7. **Filenames and content may contain terminal control sequences** - must escape on output

---

## Privilege Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                      KERNEL (Ring 0)                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              LSM / eBPF (Optional)                  │   │
│  │  - execve filtering                                 │   │
│  │  - Requires root, kernel module                     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                      USER SPACE (Ring 3)                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  LinuxSecMonitor Daemon (Optional, systemd --user)  │   │
│  │  - Scan caching, approval persistence               │   │
│  │  - Runs as user, no elevated privileges             │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Wrapper Scripts (~/.local/bin/)                    │   │
│  │  - Intercept commands, invoke scanners              │   │
│  │  - Runs as user, invoked by shell                   │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Scanner Processes (ClamAV, Python)                 │   │
│  │  - Run as user, resource limited                    │   │
│  │  - No-follow directory descriptors                  │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Real Commands (git, npm, pip, make, etc.)          │   │
│  │  - Execute with user privileges                     │   │
│  │  - Only after approval                              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Key Boundaries**:
- **Wrapper → Scanner**: Same user, no privilege escalation
- **Scanner → Repository**: Read-only, no-follow, resource limits
- **Wrapper → Real Command**: `execve` with same credentials, after approval
- **Daemon (if used)**: User service, no root, IPC via Unix socket

---

## Trusted Components

| Component | Trust Basis | Verification |
|---|---|---|
| LinuxSecMonitor Python code | Installed from trusted source | Package signature, hash |
| Wrapper scripts | Generated at install | Hash verification at runtime |
| ClamAV (`/usr/bin/clamscan`) | System package | Path verification, not PATH |
| Python interpreter | System package | Shebang/path verification |
| Configuration files | User-controlled | User edits, no auto-update |
| Audit log | Append-only | User-readable |

**Not Trusted**:
- Repository content (files, Git metadata, config)
- User's shell environment (PATH, aliases, functions)
- Package manager registries (can serve malicious packages)
- Network downloads during install/build
- User's terminal (can be spoofed)

---

## Root/Admin Limitations

**Even with root, LinuxSecMonitor cannot**:
1. **Intercept shell built-ins** (`source`, `eval`, `.`) - no `execve`
2. **See inline code** - `bash -c "evil"` only shows `bash` executable
3. **Enforce in containers/VMs** - separate kernel/namespaces
4. **Prevent `sudo` bypass** - `sudo` resets environment
5. **Stop kernel exploits** - outside scope
6. **Enforce on other users** - per-user installation only

**Root Can**:
- Deploy system-wide wrappers (`/usr/local/bin/`)
- Install eBPF LSM for kernel-level `execve` filtering
- Configure systemd user services globally
- Set mandatory shell config (`/etc/bash.bashrc`)

---

## Concurrent Modifications

**Threat**: Repository changes during scan

**Attack Vectors**:
- Git operations in background (`git pull`, `git checkout`)
- Build processes writing files
- Malicious repository with `inotify` triggers
- Symlink races (TOCTOU)

**Defenses**:
1. **Staged copy**: Malware scanner copies to temp with verification
2. **File stability checks**: Compare stat before/after open and copy
3. **Revalidation**: Re-check critical files after scan
4. **Coverage tracking**: Mark incomplete if changes detected
5. **No-follow descriptors**: `O_NOFOLLOW | O_DIRECTORY` prevents symlink races

**Residual Risk**: Changes between approval and execution
- **Mitigation**: Repo content hash in approval, short TTL, single-use

---

## Execution Bypasses

### Documented Bypasses (Cannot Be Prevented)

| Bypass | Mechanism | Mitigation |
|---|---|---|
| Absolute path | `/usr/bin/npm install` | Document, log |
| Shell built-in | `source script.sh`, `eval "cmd"` | Document, cannot prevent |
| Inline interpreter | `bash -c "cmd"`, `python -c "code"` | Document, log wrapper pass-through |
| Non-interactive | Cron, systemd, SSH, CI | Different environment |
| `sudo` | Resets PATH, env | Different user context |
| Container/VM | Separate kernel/user space | Not in scope |
| `command` / `builtin` | Shell bypasses functions | Document |
| `exec` | Replaces shell process | Document |
| `exec -a` | Changes argv[0] | Logs real executable |

### Bypasses That Reduce Protection (Partial)

| Bypass | Impact | Mitigation |
|---|---|---|
| Modify wrapper script | User can disable | Log wrapper hash at startup |
| `PATH` manipulation | Move wrapper out of PATH | Install in fixed location |
| Shell config removal | Remove wrapper activation | systemd user service for daemon |
| `BASH_ENV` / `ENV` | Non-interactive shell config | Document limitation |
| `--ignore-scripts` | Skips PM lifecycle | Log, still scans repo |

---

## Scanner Compromise Risks

### ClamAV
- **Risk**: Malicious signature database, ClamAV exploit
- **Mitigation**: Run in isolated process, resource limits, no network during scan

### Python Scanners
- **Risk**: Malicious repository content exploits scanner bug
- **Mitigation**:
  - No `eval`/`exec` on repository content
  - Regex patterns compiled, not dynamic
  - Resource limits (time, memory, files)
  - No-follow directory descriptors

### Configuration
- **Risk**: User modifies config to disable checks
- **Mitigation**: Config changes increment policy version, invalidate approvals

---

## Residual Risks

### Accepted Risks (Documented, Not Fixed)

| Risk | Likelihood | Impact | Acceptance |
|---|---|---|---|
| Shell built-in execution | High | High | **Accepted** - Fundamental shell design |
| Inline interpreter code | High | High | **Accepted** - No file artifact |
| Direct binary paths | Medium | High | **Accepted** - User choice |
| Container/VM escape | Low | Critical | **Accepted** - Out of scope |
| `sudo` privilege escalation | Medium | High | **Accepted** - Different trust boundary |
| Kernel exploits | Very Low | Critical | **Accepted** - Out of scope |
| Malicious wrapper modification | Low | High | **Mitigated** - Hash logging, user control |
| TOCTOU repo modification | Medium | Medium | **Mitigated** - Hash binding, short TTL |

### Risks Requiring User Awareness

1. **This is advisory, not a sandbox** - Explicitly stated in every report
2. **Bypasses exist and are documented** - User must understand limitations
3. **Approval binds to repo state at scan time** - Changes invalidate
4. **No protection for non-wrapped commands** - Only listed commands intercepted
5. **No cross-user protection** - Per-user installation only

---

## Security Assumptions

1. **User's shell is not actively malicious** - Can modify RC files but won't silently subvert
2. **System packages (ClamAV, Python) are uncompromised** - Supply chain trust
3. **Repository is scanned before first dangerous command** - User doesn't bypass initially
4. **User reads and understands findings** - Approval is informed
5. **Audit log is reviewed periodically** - For anomaly detection
6. **Configuration changes are intentional** - Policy version tracks changes

---

## Threat Model Summary

| Threat | Protected? | Mechanism | Residual |
|---|---|---|---|
| Malicious `postinstall` | ✅ | Wrapper intercepts `npm install` | Absolute path bypass |
| Malicious `build.rs` | ✅ | Wrapper intercepts `cargo build` | Absolute path bypass |
| Git hook execution | ✅ | Detected in security scan | `--no-verify` bypass |
| `git clone` malicious repo | ✅ | Post-clone scan + warn | No pre-clone hook |
| `curl \| bash` | ⚠️ | Detected if in repo | Inline not intercepted |
| `source malicious.sh` | ❌ | Cannot intercept built-in | **Accepted** |
| `bash -c "evil"` | ❌ | No file to scan | **Accepted** |
| Supply chain (dep) | ✅ | PM wrapper scans deps | `--ignore-scripts` |
| Compromised ClamAV | ⚠️ | Resource limits, no network | **Accepted** |
| TOCTOU repo change | ⚠️ | Staged copy, hash binding | Between approval/exec |
| Malicious wrapper mod | ⚠️ | Hash logging, user control | **Accepted** |

**Overall**: Protects against **routine dangerous operations** (install, build, checkout) with **documented bypasses** for advanced/edge cases. Not a security boundary - clearly labeled as advisory.