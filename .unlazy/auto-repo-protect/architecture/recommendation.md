# Recommended Architecture: PATH Wrapper + Explicit CLI

## Overview

This document describes the recommended architecture for automatic repository pre-execution protection in LinuxSecMonitor.

The architecture extends the existing Priority 1 implementation (repository scanners + execution guard) with **shell-agnostic PATH wrappers** that automatically detect repository contexts, scan before execution, and require explicit approval for risky operations.

**Key Principle**: Advisory by default, explicit enforcement via `--safe-run` CLI. No false claims of universal protection.

---

## Architecture Components

### 1. Wrapper Framework (`linuxsecmonitor-wrapper`)

**Purpose**: Intercept command execution, detect repository context, scan, approve, execute.

**Location**: `$HOME/.local/bin/` (user) or `/usr/local/bin/` (system)

**Commands Wrapped**:
| Category | Commands |
|---|---|
| Version Control | `git` |
| Package Managers | `npm`, `npx`, `yarn`, `pnpm`, `pip`, `pip3`, `pipx`, `uv`, `poetry`, `pipenv`, `cargo`, `cargo-install`, `go`, `gem`, `bundle`, `composer`, `bun`, `deno` |
| Build Tools | `make`, `cmake`, `meson`, `ninja`, `bazel`, `gradle`, `mvn`, `scons`, `autoreconf`, `configure` |
| Interpreters | `python`, `python3`, `node`, `bun`, `deno`, `perl`, `ruby`, `php`, `lua` |
| Shells | `bash`, `sh`, `zsh`, `fish`, `ksh`, `dash` |

**Wrapper Logic**:
```python
def wrapper_main(argv):
    # 1. Identify command (argv[0] basename)
    cmd = Path(argv[0]).name

    # 2. Find repository root (walk up from cwd)
    repo_root = find_repository_root(Path.cwd())

    # 3. Check if command is "dangerous" in this context
    if not is_dangerous_command(cmd, argv, repo_root):
        return exec_real_command(argv)  # Pass through

    # 4. Scan repository (cached if recent)
    report = scan_repository(repo_root)

    # 5. Check for findings requiring approval
    if requires_approval(report, cmd, argv):
        # 6. Show findings, prompt for approval
        if not prompt_approval(report, cmd, argv):
            return EXIT_CANCELLED

    # 7. Execute real command
    return exec_real_command(argv)
```

### 2. Repository Detection

**Algorithm**: Walk up from current working directory
```python
def find_repository_root(cwd: Path) -> Path | None:
    for parent in [cwd] + list(cwd.parents):
        if (parent / ".git").exists():
            return parent
        # Also check for other repo markers
        if any((parent / f).exists() for f in
               ["package.json", "Cargo.toml", "pyproject.toml", "go.mod", "pom.xml"]):
            # Verify it's a repo (has .git or is project root)
            if (parent / ".git").exists() or is_project_root(parent):
                return parent
    return None
```

**Cache**: Repository scan results cached by `(repo_path, repo_mtime, scan_config_hash)`
- TTL: 5 minutes or until repo mtime changes
- Stored in `$XDG_CACHE_HOME/linuxsecmonitor/`

### 3. Dangerous Command Classification

**Tier 1 - Always Scan + Approve**:
- Package installs: `install`, `ci`, `add`, `install <pkg>`, `get`
- Build commands that execute code: `make install`, `cmake --build`, `cargo install`
- Git operations that change working tree: `checkout`, `switch`, `merge`, `pull`, `rebase`

**Tier 2 - Scan, Warn, Auto-Approve**:
- Build commands: `make`, `cmake`, `cargo build`, `go build`
- Interpreter execution: `python script.py`, `node script.js`
- Test commands: `npm test`, `cargo test`, `pytest`

**Tier 3 - Pass Through**:
- Read-only: `git status`, `git log`, `git diff`
- Info commands: `npm list`, `cargo metadata`, `pip list`
- Help: `--help`, `--version`

### 4. Scan Pipeline (Reuses Priority 1)

```
Repository Path
       │
       ▼
┌──────────────────┐
│ Inventory Scan   │  (files, manifests, limits)
│ scan_repository  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Malware Scan     │  (ClamAV on staged snapshot)
│ scan_repository  │
│ _malware         │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Security Scan    │  (secrets, hooks, risky cmds,
│ scan_repository  │   package.json scripts, etc.)
│ _security        │
└────────┬─────────┘
         │
         ▼
    ┌────────┐
    │ Report │  (aggregated findings)
    └────────┘
```

### 5. Approval Flow

```
┌─────────────────────────────────────────────────────────┐
│  ⚠️  LinuxSecMonitor: Repository scan findings          │
│                                                         │
│  Repository: /home/user/project                         │
│  Command: npm install                                   │
│                                                         │
│  Findings:                                              │
│  ▸ MALWARE: 1 detection (EICAR test file in test/)     │
│  ▸ SECRETS: GitHub token in .env.example                │
│  ▸ RISKY: postinstall script downloads binary           │
│                                                         │
│  Coverage: Complete (inventory ✓, malware ✓, security ✓)│
│                                                         │
│  Type exactly RUN to proceed, or CANCEL to abort:       │
└─────────────────────────────────────────────────────────┘
```

**Approval Rules**:
- Exact `RUN` required (case-sensitive, no whitespace)
- 5-minute timeout (configurable)
- EOF/Ctrl+C/Timeout → Cancel
- No TTY → Cancel (fail-closed)
- Approval bound to: `(repo_path, repo_content_hash, command, argv, scan_config_hash)`

### 6. Execution Guard Integration (Reuses Priority 1)

```python
from scanner.execution_guard import review_repository_for_execution, run_reviewed_command

# Wrapper uses existing functions
report = review_repository_for_execution(repo_root)
# ... show report, get approval ...
exit_code = run_reviewed_command(report, repo_root, argv, terminal=tty)
```

### 7. Explicit CLI (Current `--safe-run`)

For commands that cannot be wrapped or user wants explicit control:
```bash
linuxsecmonitor --safe-run /path/to/repo -- npm install
linuxsecmonitor --review-repository /path/to/repo
```

---

## Data Flow

```
User types: npm install express
                │
                ▼
┌────────────────────────────────────────────────┐
│ Wrapper (npm in ~/.local/bin/)                 │
│ 1. Detect repo: /home/user/project             │
│ 2. Check cache: valid?                         │
│ 3. Classify: "npm install" = Tier 1 (dangerous)│
│ 4. Scan repo (or use cached)                   │
│ 5. Findings: postinstall script in express     │
│ 6. Prompt: "Type RUN to proceed"               │
│ 7. User types: RUN                             │
│ 8. Execute: /usr/bin/npm install express       │
└────────────────────────────────────────────────┘
                │
                ▼
         Real npm runs
```

---

## Configuration

**File**: `$XDG_CONFIG_HOME/linuxsecmonitor/config.toml` or `~/.config/linuxsecmonitor/config.toml`

```toml
[scan]
# Scan timeouts (seconds)
inventory_timeout = 30
malware_timeout = 120
security_timeout = 20

# Limits
max_files = 100000
max_file_size = 52428800  # 50MB
max_total_size = 1073741824  # 1GB

[cache]
enabled = true
ttl_seconds = 300
directory = "~/.cache/linuxsecmonitor"

[approval]
timeout_seconds = 300
require_tty = true
# Approval binding includes:
# - repo path + content hash
# - command + argv
# - scan config hash
# - policy version

[commands]
# Tier 1: Always scan + approve
tier1_approve = [
    "install", "ci", "add", "install *",
    "make install", "cargo install",
    "git checkout", "git switch", "git merge", "git pull", "git rebase"
]

# Tier 2: Scan + warn
tier2_warn = [
    "build", "test", "run", "start",
    "python *", "node *", "cargo build", "go build"
]

# Tier 3: Pass through
tier3_passthrough = [
    "status", "log", "diff", "show",
    "list", "info", "help", "--help", "--version"
]

[wrappers]
enabled = [
    "git", "npm", "npx", "yarn", "pnpm",
    "pip", "pip3", "uv", "poetry", "pipenv",
    "cargo", "go", "gem", "bundle", "composer",
    "make", "cmake", "meson", "ninja",
    "python", "python3", "node", "bun", "deno",
    "bash", "sh", "zsh", "fish"
]
```

---

## Installation

### User Installation (Recommended)
```bash
# Run once
linuxsecmonitor --install-wrappers

# Adds to ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish:
# export PATH="$HOME/.local/bin:$PATH"
# Creates wrappers in ~/.local/bin/
```

### System Installation (Optional)
```bash
# Requires root
linuxsecmonitor --install-wrappers --system

# Installs to /usr/local/bin/
# Adds to /etc/profile.d/linuxsecmonitor.sh
```

### Uninstall
```bash
linuxsecmonitor --uninstall-wrappers
```

---

## Cache Invalidation

Cache key: `(repo_path, repo_mtime_ns, scan_config_hash, policy_version)`

Invalidated when:
1. Repository mtime changes (new commits, file changes)
2. Scan config changes (timeout, limits)
3. Policy version increments (new risky patterns)
4. Manual: `linuxsecmonitor --clear-cache`

---

## Bypass Documentation (Required in Wrapper Output)

Every wrapper execution that passes through without scanning logs:
```
[LinuxSecMonitor] Passed through: command not in dangerous tier
[LinuxSecMonitor] Bypass: absolute path /usr/bin/npm used
[LinuxSecMonitor] Bypass: shell built-in 'source' cannot be intercepted
```

---

## Error Handling

| Error | Behavior |
|---|---|
| Scan timeout | Fail-closed: block, show partial results |
| ClamAV unavailable | Fail-closed: block (malware scan incomplete) |
| No TTY for approval | Fail-closed: block |
| Repository not found | Pass through (no repo context) |
| Wrapper not in PATH | Pass through (real command runs) |
| Permission denied on cache | Warning, continue without cache |

---

## Testing Strategy

### Unit Tests (Per Wrapper)
- Repository detection from various cwd depths
- Command classification (tier 1/2/3)
- Cache hit/miss/expiry
- Approval flow (mock TTY)
- Bypass detection

### Integration Tests
- Full wrapper → scan → approve → execute flow
- Multiple wrappers in same shell session
- Cache sharing across wrappers
- Config file parsing

### Bypass Verification Tests
- Absolute path execution
- Shell built-ins
- Non-interactive shells
- `sudo` environment

---

## Performance Targets

| Operation | Target |
|---|---|
| Wrapper overhead (cache hit) | < 50ms |
| Wrapper overhead (cache miss, small repo) | < 2s |
| Wrapper overhead (cache miss, large repo) | < 10s |
| Memory usage (daemon) | < 50MB |
| Cache size (typical) | < 100MB |

---

## Security Considerations

### What This Architecture DOES Protect
- ✅ Package manager installs with lifecycle scripts
- ✅ Git operations changing working tree (checkout, merge, pull)
- ✅ Build commands executing repository code
- ✅ Interpreter execution of repository scripts
- ✅ Malware detection before execution
- ✅ Secret detection before execution

### What This Architecture DOES NOT Protect (Documented)
- ❌ Direct binary paths: `/usr/bin/npm`, `/bin/bash`
- ❌ Shell built-ins: `source`, `eval`, `.`, `exec`
- ❌ Inline interpreter: `bash -c "cmd"`, `python -c "code"`
- ❌ Non-interactive shells: cron, systemd, SSH, CI
- ❌ `sudo` / privilege escalation
- ❌ Container/VM execution
- ❌ Malicious code modifying wrapper scripts
- ❌ Kernel-level exploits

### Fail-Closed Guarantees
- Incomplete scan → Block
- Malware detected → Block (unless explicit override policy)
- No TTY → Block
- Approval timeout → Block
- Wrapper crash → Block (real command not executed)

---

## Future Enhancements (Post-Priority 3)

1. **eBPF LSM Integration**: Optional kernel enforcement for Tier 1 commands
2. **Policy Engine**: Organization-wide policies, central management
3. **Remote Attestation**: Verify wrapper integrity
4. **CI/CD Integration**: GitHub Actions, GitLab CI wrappers
5. **SBOM Generation**: Software Bill of Materials on scan