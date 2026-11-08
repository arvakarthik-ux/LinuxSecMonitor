# Shell Execution Coverage Analysis

## Operation Categories

### A. Explicit Shell Script Execution
- `./install.sh`
- `bash install.sh`
- `sh install.sh`
- `bash -c "commands"`
- `sh -c "commands"`
- `source install.sh` / `. install.sh`
- `exec install.sh`

### B. Shell Features That Execute Code
- Command substitution: `$(cmd)` or `` `cmd` ``
- Process substitution: `<(cmd)` `>(cmd)`
- Pipeline to shell: `curl ... | bash`, `wget ... | sh`
- Here-documents with shell: `bash <<'EOF' ... EOF`
- `eval` with shell commands
- `exec` replacing shell

### C. Alternate Shells
- `zsh`, `fish`, `ksh`, `dash`, `tcsh`
- Absolute paths: `/bin/bash`, `/usr/bin/zsh`
- `env bash`, `env sh`

### D. Non-Interactive Shells
- Scripts with shebang: `#!/bin/bash`
- Cron jobs, systemd services, CI scripts
- SSH forced commands

---

## Analysis by Operation Type

### 1. Direct Script Execution: `./install.sh`

**How it works:**
- Kernel checks shebang (`#!/bin/bash`), invokes interpreter
- Interpreter reads and executes script

**Inspection Points:**
| Point | Feasibility | Can Block? |
|---|---|---|
| Before `execve` (kernel) | Requires LSM/eBPF | Yes (kernel-level) |
| Shell startup (`.bashrc`, `/etc/bash.bashrc`) | High | Only interactive |
| Wrapper script in PATH | Medium | Only if wrapper invoked |
| `LD_PRELOAD` hook | High | Yes (but fragile) |
| eBPF uprobe on `execve` | High | Yes (kernel-level) |

**Bypass Analysis:**
- Absolute path `/bin/bash ./install.sh` bypasses PATH wrappers
- Direct `/usr/bin/bash ./install.sh` bypasses all user-space wrappers
- `exec` syscall directly from compiled binary bypasses shell entirely
- Shebang points directly to interpreter

**Verdict:** **Cannot reliably block at user level.** Kernel-level (LSM/eBPF) required for enforcement.

---

### 2. Explicit Interpreter: `bash install.sh` / `sh install.sh`

**How it works:**
- User explicitly invokes shell with script as argument
- Shell reads script and executes

**Inspection Points:** Same as direct execution

**Bypass Analysis:** Same as direct execution

**Verdict:** **Cannot reliably block at user level.**

---

### 3. Inline Shell: `bash -c "commands"` / `sh -c "commands"`

**How it works:**
- Shell executes command string directly
- No script file to scan

**Inspection Points:**
| Point | Feasibility | Can Block? |
|---|---|---|
| Wrapper intercepts `bash -c` | Medium | Only if wrapper invoked |
| eBPF on `execve` with args | High | Yes |
| Audit `bash` command line | Medium | Post-execution |

**Bypass Analysis:**
- Direct `/bin/bash -c` bypasses PATH
- No file to scan (commands in argv)
- Nested: `bash -c 'bash -c "evil"'` - inner bash not visible

**Verdict:** **Very difficult to intercept.** No persistent artifact to scan.

---

### 4. Pipeline to Shell: `curl ... | bash` / `wget ... | sh`

**How it works:**
- Downloaded content piped directly to shell stdin
- Shell reads from stdin, executes immediately

**Inspection Points:**
| Point | Feasibility | Can Block? |
|---|---|---|
| Wrapper intercepts `bash` with stdin pipe | Low | Shell doesn't know source |
| Network-level inspection | Low | Encrypted HTTPS |
| eBPF on pipe + execve | Medium | Complex |

**Bypass Analysis:**
- `curl ... | bash` - no file written
- `curl ... | sh` - same
- `wget -O- ... | bash` - same
- Encrypted download prevents network inspection
- Can be nested: `curl ... | bash -c 'bash'`

**Verdict:** **Cannot intercept at user level.** Kernel-level required.

---

### 5. Source/Eval: `source install.sh` / `. install.sh` / `eval "cmd"`

**How it works:**
- Executes in **current shell process**
- No new process created
- No `execve` call

**Inspection Points:**
| Point | Feasibility | Can Block? |
|---|---|---|
| Shell builtin hook | None standard | No |
| Wrapper function override | Medium | Only if wrapper loaded |
| eBPF uretprobe on builtin | Very low | Not practical |

**Bypass Analysis:**
- Built-in shell commands - no execve
- `eval` executes string in current context
- `source` reads file in current shell
- Completely invisible to process monitoring

**Verdict:** **Cannot intercept.** Runs in existing shell process.

---

### 6. Alternate Shells: `zsh`, `fish`, `ksh`, `dash`

**How it works:**
- Different binaries, different configs
- May not read bash startup files

**Inspection Points:**
| Point | Feasibility | Can Block? |
|---|---|---|
| PATH wrapper for each shell | Medium | Only if wrapper invoked |
| eBPF on all shell execve | High | Yes |

**Bypass Analysis:**
- Each shell needs separate wrapper
- Direct binary paths bypass PATH
- Different startup files (`.zshrc`, `.config/fish/config.fish`)

**Verdict:** **Requires per-shell wrappers + kernel enforcement for completeness.**

---

### 7. Non-Interactive / Shebang Scripts

**How it works:**
- `#!/bin/bash` at top of file
- Kernel invokes interpreter directly
- Runs non-interactively (no RC files)

**Inspection Points:**
| Point | Feasibility | Can Block? |
|---|---|---|
| Kernel shebang handler | Requires LSM | Yes |
| eBPF on execve | High | Yes |
| File scan before execution | Manual only | Advisory |

**Bypass Analysis:**
- Shebang points directly to interpreter
- Non-interactive = no `.bashrc` / `/etc/bash.bashrc`
- `env` shebang: `#!/usr/bin/env bash` - resolves via PATH

**Verdict:** **Kernel-level enforcement needed for reliable blocking.**

---

## Shell Execution Coverage Matrix

| Operation | File to Scan | Pre-Exec Block (User) | Pre-Exec Block (Kernel) | Bypass Risk |
|---|---|---|---|---|
| `./script.sh` | Yes (script file) | No | LSM/eBPF | High (abs path) |
| `bash script.sh` | Yes (script file) | No | LSM/eBPF | High (abs path) |
| `bash -c "cmd"` | No (inline) | No | LSM/eBPF | Very High |
| `curl \| bash` | No (stream) | No | LSM/eBPF | Very High |
| `source script.sh` | Yes (script file) | No | No (builtin) | Very High |
| `eval "cmd"` | No (inline) | No | No (builtin) | Very High |
| `zsh script.sh` | Yes | No | LSM/eBPF | High |
| Shebang script | Yes | No | LSM/eBPF | High |

---

## Key Findings

1. **User-space wrappers (PATH, aliases, functions) are fundamentally incomplete** - they can be bypassed by absolute paths, direct binary invocation, and built-in shell commands.

2. **No file artifact exists for inline commands** (`bash -c`, `eval`, pipelines) - nothing to scan before execution.

3. **Built-in commands (`source`, `eval`, `.`) execute in current process** - no `execve`, invisible to process monitoring.

4. **Kernel-level enforcement (LSM/eBPF) is the only comprehensive approach** - intercepts all `execve` calls regardless of invocation method.

5. **Practical user-space approach: Directory-based advisory scanning**
   - Scan repository when user enters directory (shell `PROMPT_COMMAND`, `chpwd`)
   - Block dangerous commands via shell function wrappers
   - Accept bypasses exist but raise barrier for casual execution
   - Clearly document as **advisory, not a security boundary**

---

## Recommended Practical Approach

Since kernel-level enforcement requires root, complexity, and maintenance:

**Layer 1: Repository-aware shell integration (advisory)**
- Shell hook (`PROMPT_COMMAND` / `chpwd`) detects repository root
- Auto-scans on directory entry (cached, incremental)
- Wraps common dangerous commands (`bash`, `sh`, `./*`, `npm`, `pip`, `make`, `cargo`)
- Shows findings before execution, prompts for approval
- **Clearly labeled as convenience/advisory**

**Layer 2: Explicit CLI (current `--safe-run`)**
- User explicitly invokes `linuxsecmonitor --safe-run <repo> -- <cmd>`
- Full scan + explicit approval + execution
- **Actual enforcement** (within same process tree)

**Layer 3: Optional kernel enforcement (future, opt-in)**
- eBPF/LSM program for `execve` filtering
- Requires root, signed kernel module
- Only for high-security environments