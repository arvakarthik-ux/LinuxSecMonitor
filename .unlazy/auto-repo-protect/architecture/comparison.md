# Enforcement Architecture Comparison

## Mechanisms Evaluated

### 1. Shell Startup Hooks / Pre-Execution Callbacks

#### How It Works
- Bash: `PROMPT_COMMAND`, `DEBUG` trap, `preexec` (via plugin)
- Zsh: `precmd`, `preexec` functions
- Fish: `fish_prompt`, `fish_preexec`
- Executes before each command prompt / command execution

#### Required Privileges
- User-level only
- No root required
- Modifies user's shell config (`.bashrc`, `.zshrc`, `config.fish`)

#### Supported Execution Paths
| Path | Coverage |
|---|---|
| Interactive shell commands | ✅ Full |
| Scripts with shebang | ❌ Non-interactive |
| `bash -c "cmd"` | ❌ Non-interactive |
| `source script` | ⚠️ Same process |
| `eval "cmd"` | ⚠️ Same process |
| Cron / systemd / SSH | ❌ Non-interactive |
| Direct binary `/usr/bin/bash` | ❌ Bypasses config |

#### Performance Impact
- Negligible for prompt hooks
- `DEBUG` trap: runs before EVERY command (including pipelines, subshells)
- Can slow down interactive use if heavy logic

#### Installation Complexity
- Low: Append to shell RC files
- Per-shell configuration needed
- User can remove/disable easily

#### Compatibility
- Kali: Bash default, Zsh available, Fish available
- Debian: Bash default, others available
- Works across SSH, tmux, screen

#### Known Bypasses
1. **Direct binary paths**: `/bin/bash`, `/usr/bin/bash`
2. **Non-interactive shells**: Scripts, `bash -c`, cron, systemd
3. **Built-ins**: `source`, `eval`, `.` (no new process)
4. **Alternate shells**: zsh, fish, ksh, dash (need separate config)
5. **Environment variables**: `BASH_ENV`, `ENV` for non-interactive
6. **User modification**: User can edit/remove RC entries

#### Security Limitations
- **Advisory only** - cannot enforce
- Runs in user's process context
- Can be disabled by malicious repository code if it modifies RC files
- No protection for non-interactive execution

#### Maintenance
- Low: Shell config changes rarely
- Must handle shell updates, new shell versions
- Per-user installation

---

### 2. PATH-Based Command Wrappers

#### How It Works
- Create wrapper scripts in `$HOME/.local/bin` (early in PATH)
- Wrappers intercept common commands: `git`, `npm`, `pip`, `make`, `cargo`, `bash`, `python`, etc.
- Wrappers scan/analyze then exec real command

#### Required Privileges
- User-level only
- Requires `$HOME/.local/bin` early in PATH
- No root required

#### Supported Execution Paths
| Path | Coverage |
|---|---|
| `npm install` | ✅ If wrapper in PATH |
| `git clone` | ✅ If wrapper in PATH |
| `python script.py` | ✅ If wrapper in PATH |
| `/usr/bin/npm` | ❌ Absolute path bypass |
| `bash -c "cmd"` | ❌ No file to wrap |
| `source script` | ❌ Built-in |

#### Performance Impact
- Low: One extra process per wrapped command
- Scan time depends on repository size
- Caching can reduce repeated scans

#### Installation Complexity
- Medium: Create wrappers, manage PATH, handle updates
- Need wrapper per command (git, npm, pip, cargo, go, make, cmake, python, node, etc.)
- Shell-agnostic (works in any shell if PATH correct)

#### Compatibility
- Kali/Debian: Standard PATH includes `~/.local/bin`
- Works in all shells (bash, zsh, fish, etc.)
- Requires user's PATH to prioritize wrapper directory

#### Known Bypasses
1. **Absolute paths**: `/usr/bin/git`, `/usr/bin/npm`, `/bin/bash`
2. **Direct binary invocation**: `command git`, `builtin git`
3. **No file artifact**: `bash -c`, `eval`, `source`, pipelines
4. **Built-in commands**: `cd`, `source`, `eval`, `exec` (shell built-ins)
5. **Subshells**: `( npm install )` - may or may not use wrapper
6. **Sudo**: `sudo npm install` - different PATH
7. **Containers/VMs**: Different environment

#### Security Limitations
- **Advisory only** - cannot enforce
- Easily bypassed by absolute paths
- No kernel-level enforcement
- Wrapper runs with user privileges

#### Maintenance
- Medium: Update wrappers for new commands, fix bugs
- Must track command-line interface changes
- Per-user or system-wide installation

---

### 3. Git Command Wrappers / Git Hook Integration

#### How It Works
- **Wrapper**: PATH wrapper for `git` command
- **Hooks**: `pre-commit`, `pre-merge-commit`, `post-checkout`, `post-merge`, `pre-rebase`, `pre-push`

#### Required Privileges
- User-level (wrapper)
- Repository-level (hooks in `.git/hooks/`)

#### Supported Execution Paths
| Path | Coverage |
|---|---|
| `git commit` | ✅ pre-commit hook |
| `git merge` | ✅ pre-merge-commit |
| `git checkout` | ✅ post-checkout |
| `git pull` | ✅ post-merge |
| `git clone` | ❌ No hook (pre-clone doesn't exist) |
| `git submodule` | ⚠️ Per-submodule hooks |
| `/usr/bin/git` | ❌ Bypasses wrapper |

#### Performance Impact
- Hooks: Runs at Git operation time
- Can slow down Git operations if heavy
- `pre-commit` runs on every commit

#### Installation Complexity
- Wrapper: Same as PATH wrapper
- Hooks: Must install per-repository (or use `core.hooksPath`)

#### Compatibility
- Git: Universal on Linux
- Hooks: Standard Git feature
- `core.hooksPath`: Global hook directory (Git 2.9+)

#### Known Bypasses
1. **`--no-verify`**: Skips `pre-commit`, `commit-msg`, `pre-push`
2. **Direct binary**: `/usr/bin/git`
3. **No pre-clone hook**: Clone happens before any hook
4. **Submodules**: Separate repositories
5. **`GIT_CONFIG_NOSYSTEM`**: Ignores system config

#### Security Limitations
- **Advisory only** - `--no-verify` explicitly bypasses
- Hooks run after some operations (post-checkout, post-merge)
- Cannot block `git clone` (no hook exists)
- Repository-controlled hooks can be malicious

#### Maintenance
- Low: Git hooks stable
- Wrapper maintenance same as PATH wrapper

---

### 4. Package Manager Specific Wrappers / Plugins

#### How It Works
- **npm**: `npm hooks` (limited), wrapper scripts
- **pip**: `--pre`/`--post` install hooks (not standard), wrapper
- **Cargo**: No native hooks, wrapper
- **Go**: No native hooks, wrapper
- **Composer**: `scripts` in composer.json (runs after install)

#### Required Privileges
- User-level

#### Supported Execution Paths
| Path | Coverage |
|---|---|
| `npm install` | ✅ Wrapper |
| `pip install` | ✅ Wrapper |
| `cargo install` | ✅ Wrapper |
| Native plugin APIs | Limited/None |

#### Performance Impact
- Low: Only on package manager commands
- Scan time added to install

#### Installation Complexity
- High: Different API per package manager
- npm: No official pre-install hook
- pip: No official pre-install hook
- Cargo: No hooks at all

#### Known Bypasses
- Direct binary paths
- Flags to skip: `--ignore-scripts`, `--no-build-isolation`
- Alternative registries/sources

#### Security Limitations
- No standard pre-install hook in any major PM
- Wrappers are advisory only

---

### 5. Central LinuxSecMonitor Service / Daemon

#### How It Works
- Background daemon (systemd service or user service)
- IPC: Unix socket, D-Bus, or REST API
- Shell wrappers / Git hooks / PM wrappers communicate with daemon
- Daemon performs scans, caches results, manages approvals

#### Required Privileges
- User-level service (systemd `--user`)
- Or system service (requires root for install)

#### Supported Execution Paths
| Path | Coverage |
|---|---|
| All wrapper paths | ✅ Via IPC |
| Direct binaries | ❌ Still bypassed |
| Non-interactive | ❌ No wrapper |

#### Performance Impact
- Daemon: Constant memory usage
- Scans: Offloaded from wrappers (async possible)
- Caching: Shared across all wrappers

#### Installation Complexity
- High: systemd service, IPC protocol, security
- User service: `systemctl --user enable linuxsecmonitor`
- System service: Requires root, package install

#### Compatibility
- systemd: Standard on Kali/Debian
- User services: Supported
- D-Bus: Available

#### Known Bypasses
- Same as wrappers (direct binaries, built-ins)
- Daemon not in execution path

#### Security Limitations
- Still advisory - wrappers can be bypassed
- IPC adds attack surface
- Daemon runs with user privileges

#### Maintenance
- High: Daemon code, IPC protocol, service management
- Updates require service restart

---

### 6. Linux-Level Execution Enforcement (LSM / eBPF)

#### How It Works
- **LSM (Linux Security Modules)**: Kernel hooks on security decisions
  - `bprm_check_security`: Before execve
  - `file_open`: File access
  - Custom LSM module (requires kernel build)
- **eBPF (Extended Berkeley Packet Filter)**:
  - `bpf_prog_type_lsm`: LSM-style hooks via eBPF
  - `tracepoint/syscalls/sys_enter_execve`: Trace execve
  - `kprobe/__x64_sys_execve`: Kernel probe
  - Can filter/block execve based on path, args, cwd, credentials

#### Required Privileges
- **Root required** for loading LSM/eBPF programs
- `CAP_SYS_ADMIN` / `CAP_BPF` for eBPF
- Kernel 5.7+ for eBPF LSM (5.10+ recommended)

#### Supported Execution Paths
| Path | Coverage |
|---|---|
| `execve()` syscall | ✅ All processes |
| Direct binary | ✅ Intercepted |
| `bash -c` | ✅ Intercepted (bash execve) |
| `source` / `eval` | ❌ No execve (builtin) |
| Shell built-ins | ❌ No execve |

#### Performance Impact
- eBPF: Microseconds per execve (JIT compiled)
- LSM: Kernel overhead, typically < 1% CPU
- Can filter by cwd, executable path, arguments

#### Installation Complexity
- **Very High**: Kernel module / eBPF program development
- Requires kernel headers, clang/LLVM for eBPF
- Signing for production (kernel lockdown)
- Distribution-specific kernel versions

#### Compatibility
- Kali: Kernel 6.x+, eBPF LSM supported
- Debian 12: Kernel 6.x, eBPF LSM supported
- Requires kernel with `CONFIG_BPF_LSM=y`
- Kernel updates may break eBPF programs

#### Known Bypasses
1. **Shell built-ins**: `source`, `eval`, `exec` (no execve)
2. **Interpreter inline**: `python -c` (python execves, but code in arg)
3. **Ptrace/seccomp**: Can be bypassed with effort
4. **Kernel exploits**: Root can disable

#### Security Limitations
- **Cannot intercept shell built-ins** (source, eval, .)
- **Cannot see inline code**: `bash -c "evil"` - only sees bash executable
- Requires root to deploy
- Kernel complexity, potential for kernel panic

#### Maintenance
- Very High: Kernel version tracking, eBPF verifier changes
- Must test on each kernel update
- Signing for secure boot

---

### 7. Systemd / Container-Based Isolation

#### How It Works
- **systemd-run**: Run commands in isolated scope
- **systemd-nspawn**: Lightweight containers
- **Podman/Docker**: Full containers
- **bubblewrap**: Unprivileged sandboxing

#### Required Privileges
- systemd-run: User-level
- nspawn: Root for some features
- Podman: Rootless supported
- bubblewrap: User-level (setuid binary or user namespace)

#### Supported Execution Paths
| Path | Coverage |
|---|---|
| Explicit `systemd-run` | ✅ User invokes |
| Transparent | ❌ Not automatic |
| Container build | ✅ Inside container |

#### Performance Impact
- systemd-run: Low overhead
- Containers: Higher (namespace setup)
- bubblewrap: Low

#### Installation Complexity
- Medium: systemd standard, bubblewrap available

#### Known Bypasses
- Not automatic - user must invoke
- Direct execution bypasses isolation

#### Security Limitations
- Not an interception mechanism
- Requires explicit user opt-in per command

---

## Comparison Matrix

| Criterion | Shell Hooks | PATH Wrappers | Git Hooks | PM Wrappers | Daemon | LSM/eBPF |
|---|---|---|---|---|---|---|
| **Privileges** | User | User | User | User | User/Root | Root |
| **Interactive cmds** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Scripts/shebang** | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **Inline (`bash -c`)** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅* |
| **Built-ins (`source`)** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **`git clone`** | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |
| **PM install** | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **Enforcement** | Advisory | Advisory | Advisory* | Advisory | Advisory | **Block** |
| **Install complexity** | Low | Medium | Low | High | High | Very High |
| **Kali/Debian compat** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (kernel 6+) |
| **Maintenance** | Low | Medium | Low | High | High | Very High |
| **Root required** | No | No | No | No | User/No | **Yes** |

*eBPF sees `execve` of interpreter but not inline code passed as argument

---

## Recommendation

### Primary: **PATH Wrapper + Explicit CLI (Current Architecture Extended)**

**Why:**
1. **Practical**: Works today without root, kernel changes, or complex deployment
2. **Comprehensive**: Covers all major package managers, build tools, Git
3. **Reuses existing code**: Inventory, malware, security scanners already built
4. **Clear limitations**: Advisory only - honestly communicated
4. **User-controlled**: User installs/removes wrappers
5. **Extensible**: Daemon can be added later for caching

### Architecture:
```
┌─────────────────────────────────────────────────────────────┐
│                     User Shell                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ PATH Wrappers: git, npm, pip, cargo, go, make,      │   │
│  │ python, node, bash, sh, zsh, fish, cmake, meson,    │   │
│  │ gradle, bazel, npx, yarn, pnpm, uv, poetry, etc.    │   │
│  └─────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────┘
                            │ Detect repo, scan, prompt
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              LinuxSecMonitor Core (Python)                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │ Inventory   │ │ Malware     │ │ Security Analysis   │   │
│  │ Scanner     │ │ Scanner     │ │ (secrets, hooks,    │   │
│  │             │ │ (ClamAV)    │ │  risky patterns)    │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
│                            │                                │
│                            ▼                                │
│                  ┌─────────────────┐                        │
│                  │ Execution Guard │                        │
│                  │ (Approval +     │                        │
│                  │  Fail-Closed)   │                        │
│                  └─────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

### Secondary: **Optional eBPF LSM (Future, Opt-In)**

For high-security environments that can accept:
- Root deployment
- Kernel version pinning
- Kernel update testing
- No shell built-in coverage

Provides actual blocking of `execve` for wrapped commands.

### Rejected Alternatives

| Alternative | Reason |
|---|---|
| Shell hooks only | Misses scripts, non-interactive, `git clone`, PM install |
| Git hooks only | No pre-clone, `--no-verify` bypass, per-repo |
| Daemon only | Still needs wrappers for interception |
| Systemd/containers | Not automatic interception |
| Full LSM kernel module | Higher complexity than eBPF, same limitations |

---

## Deployment Strategy

### Phase 1: User-Space Wrappers (Priority 3)
- Shell-agnostic wrapper framework
- Auto-detect repository context
- Integrate with existing scanners
- Shell function installation script

### Phase 2: Daemon for Caching (Optional)
- systemd user service
- Shared scan cache across wrappers
- Approval persistence

### Phase 3: eBPF LSM (Future, Opt-In)
- Block execve for unapproved commands
- Requires root, signed kernel module
- Documented as "enhanced enforcement mode"