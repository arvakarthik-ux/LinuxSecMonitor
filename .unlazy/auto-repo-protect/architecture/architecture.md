# Automatic Repository Protection Architecture

## Executive Summary

This document describes the architecture for **automatic repository pre-execution protection** in LinuxSecMonitor. The system extends the existing Priority 1 implementation (repository inventory, malware scanning, security analysis, and execution guard) with **shell-agnostic PATH wrappers** that automatically detect repository contexts, scan before dangerous operations, and require explicit approval.

**Key Principle**: Advisory by default, explicit enforcement via `--safe-run` CLI. No false claims of universal protection.

---

## 1. Existing Implementation Analysis

### Reused Components (Priority 1)

| Component | File | Purpose |
|---|---|---|
| Repository Inventory | `scanner/repository_scanner.py` | File listing, manifests, limits |
| Malware Scanner | `scanner/repository_malware_scanner.py` | ClamAV on staged snapshot |
| Security Scanner | `scanner/repository_security_scanner.py` | Secrets, hooks, risky patterns, manifests |
| Execution Guard | `scanner/execution_guard.py` | Approval flow, fail-closed, safe exec |
| CLI Integration | `main.py` | `--review-repository`, `--safe-run` |

### Verified Capabilities (Priority 1 Gates)
- ✅ 93 gates met, 7 abandoned (Debian guest tests)
- ✅ 525 tests passing
- ✅ Repository identification with symlink rejection
- ✅ Malware scanning with ClamAV (no-follow, staged)
- ✅ Security analysis (secrets, hooks, risky commands, manifests)
- ✅ Explicit RUN approval (case-sensitive, timeout, no-TTY block)
- ✅ Fail-closed on incomplete/error/detection
- ✅ Safe argv execution (no shell, resolved cwd)

---

## 2. Security Requirements

### Functional Requirements
| ID | Requirement |
|---|---|
| FR1 | Detect dangerous operations before execution |
| FR2 | Identify repository context automatically |
| FR3 | Scan repository (inventory, malware, security) |
| FR4 | Present findings with severity classification |
| FR5 | Require explicit approval for risky operations |
| FR6 | Block on incomplete scans, detections, errors |
| FR7 | Execute approved commands safely (argv, no shell) |
| FR8 | Record audit trail of all operations |

### Non-Functional Requirements
| ID | Requirement |
|---|---|
| NFR1 | No root required for core functionality |
| NFR2 | Works on Kali and Debian 12+ |
| NFR3 | Shell-agnostic (bash, zsh, fish, etc.) |
| NFR4 | Advisory mode clearly documented |
| NFR5 | Bypass vectors explicitly documented |
| NFR6 | Sub-2s overhead for cached scans |
| NFR7 | Resource limits on all scanners |

---

## 3. Threat Model Summary

### Protected Against
- Malicious package lifecycle scripts (`postinstall`, `build.rs`, `setup.py`)
- Git operations changing working tree (`checkout`, `merge`, `pull`)
- Build commands executing repository code (`make`, `cmake`, `cargo build`)
- Interpreter execution of repository scripts
- Malware in repository files
- Exposed secrets and credentials

### Not Protected (Documented Bypasses)
- Shell built-ins: `source`, `eval`, `.`
- Inline interpreter: `bash -c "cmd"`, `python -c "code"`
- Absolute binary paths: `/usr/bin/npm`, `/bin/bash`
- Non-interactive: cron, systemd, SSH, CI
- `sudo` / privilege escalation
- Container/VM execution

---

## 4. Execution-Path Coverage Matrix

| Operation Category | Example Commands | Interception | Inspection Timing | Enforcement | Bypass Risk |
|---|---|---|---|---|---|
| **Git** | `git checkout`, `git merge`, `git pull` | Wrapper | Post-op scan + warn future | Advisory | High (`--no-verify`, direct binary) |
| **Git** | `git clone` | Wrapper | Post-clone scan | Advisory | High (no pre-clone hook) |
| **Shell** | `./install.sh`, `bash script.sh` | Wrapper | Pre-exec scan | Advisory | High (abs path, built-ins) |
| **Shell** | `bash -c "cmd"`, `source script` | ❌ | N/A | None | **Complete** |
| **Python** | `python script.py` | Wrapper | Pre-exec scan | Advisory | Medium (abs path) |
| **Python** | `python -c "code"` | ❌ | N/A | None | **Complete** |
| **Node.js** | `node script.js` | Wrapper | Pre-exec scan | Advisory | Medium (abs path) |
| **Package** | `npm install`, `pip install` | Wrapper | Pre-install scan | Advisory | High (flags, direct binary) |
| **Build** | `make`, `cmake`, `cargo build` | Wrapper | Pre-build scan | Advisory | Medium (abs path, alt config) |
| **Dependency** | `npm install pkg`, `cargo add` | Wrapper | Pre-install scan | Advisory | High |

---

## 5. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        USER SHELL                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ PATH Wrappers (~/.local/bin/): git, npm, pip, cargo, go,    │   │
│  │ make, cmake, python, node, bash, sh, zsh, fish, etc.       │   │
│  └────────────────────────────┬────────────────────────────────┘   │
└───────────────────────────────│────────────────────────────────────┘
                                │ Detect repo, classify, scan
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  LINUXSECMONITOR CORE (Python)                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ Inventory Scanner│  │ Malware Scanner  │  │ Security Scanner │  │
│  │ (metadata,       │  │ (ClamAV on       │  │ (secrets, hooks, │  │
│  │  manifests)      │  │  staged files)   │  │  risky patterns, │  │
│  │                  │  │                  │  │  manifests)      │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│            │                    │                    │              │
│            └────────────────────┼────────────────────┘              │
│                                 ▼                                  │
│                    ┌────────────────────────┐                      │
│                    │   Aggregated Report    │                      │
│                    │  (severity, confidence)│                      │
│                    └────────────┬───────────┘                      │
│                                 │                                  │
│                                 ▼                                  │
│                    ┌────────────────────────┐                      │
│                    │   Execution Guard      │                      │
│                    │  (Approval + Fail-Closed)                      │
│                    └────────────┬───────────┘                      │
└────────────────────────────────┼──────────────────────────────────┘
                                 │ Approved: exec real command
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      REAL COMMAND EXECUTION                         │
│  argv array, shell=False, cwd=repo_root, no env leakage            │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. Operation Interception Workflow

### Detection & Classification
```
User: npm install express
         │
         ▼
┌──────────────────────────────────────────────────────────┐
│ Wrapper (npm in ~/.local/bin/)                           │
│ 1. Identify command: "npm"                               │
│ 2. Find repo root: /home/user/project                    │
│ 3. Classify: "npm install" = TIER 1 (dangerous)         │
│ 4. Check cache: valid?                                   │
│ 5. Scan repo (or use cached)                             │
│ 6. Findings: postinstall script in express               │
│ 7. Prompt: "Type RUN to proceed"                         │
│ 8. User: RUN                                             │
│ 9. Execute: /usr/bin/npm install express                 │
└──────────────────────────────────────────────────────────┘
```

### Command Tiers
| Tier | Commands | Action |
|---|---|---|
| **Tier 1** | `install`, `ci`, `add`, `checkout`, `merge`, `pull`, `make install`, `cargo install` | Scan + **Require Approval** |
| **Tier 2** | `build`, `test`, `run`, `python script.py`, `node script.js` | Scan + **Warn** |
| **Tier 3** | `status`, `log`, `diff`, `list`, `--help` | **Pass Through** |

---

## 7. Scanner Integration Design

### Reused Scanners (No Modification)

| Scanner | Input | Output | Reused As-Is |
|---|---|---|---|
| `scan_repository` | repo Path | `RepositoryScanResult` | ✅ |
| `scan_repository_malware` | repo Path | `RepositoryMalwareAssessment` | ✅ |
| `scan_repository_security` | repo Path, include_generated | `RepositorySecurityAssessment` | ✅ |

### Scan Pipeline
```python
def scan_repository_complete(repo: Path) -> ScanReport:
    # Parallel execution possible
    inventory = scan_repository(repo)
    malware = scan_repository_malware(repo)
    security = scan_repository_security(repo)

    return ScanReport(
        repository=repo,
        inventory=inventory,
        malware=malware,
        security=security,
        repo_content_hash=compute_repo_hash(repo),
        config_hash=current_config_hash()
    )
```

### Resource Limits (Inherited)
- Inventory: 100k files, 1GB total, 30s timeout
- Malware: 100k files, 512MB total, 120s ClamAV timeout
- Security: 50k files, 64MB total, 20s timeout

---

## 8. Approval and Cancellation Design

### Approval Requirements
| Finding Severity | Approval Required |
|---|---|
| CRITICAL | Yes (no override) |
| HIGH | Yes |
| MEDIUM | Acknowledgment |
| LOW | None |

| Command Tier | Approval Required |
|---|---|
| Tier 1 (dangerous) | Yes |
| Tier 2 (warn) | No (auto-approve) |
| Tier 3 (passthrough) | No |

### Approval Mechanism
- **Exact string**: `RUN` (case-sensitive, no whitespace)
- **Timeout**: 5 minutes (configurable)
- **EOF/Ctrl+C**: Cancel
- **No TTY**: Cancel (fail-closed)

### Approval Binding (Cryptographic)
```python
approval_context = {
    "repo_path": str(repo_root),
    "repo_content_hash": compute_repo_hash(repo_root),  # Git commit or file hash
    "command": cmd,
    "argv": argv,
    "scan_config_hash": current_config_hash(),
    "policy_version": POLICY_VERSION,
    "scan_report_hash": hash(scan_report),
    "timestamp": datetime.now().isoformat()
}
```

### Cancellation
- Any non-`RUN` input → Cancel
- Timeout → Cancel
- Ctrl+C/EOF → Cancel
- No TTY → Cancel
- Result: Command not executed, `command_status = "cancelled"`

---

## 9. Fail-Closed Behavior

### Blocking Conditions
| Condition | Status | Message |
|---|---|---|
| Inventory error | `blocked_incomplete` | "Repository inventory failed" |
| Malware scan error | `blocked_incomplete` | "Malware scan failed" |
| Security scan error | `blocked_incomplete` | "Security scan failed" |
| Scan timeout | `blocked_incomplete` | "Scan timed out" |
| Coverage incomplete | `blocked_incomplete` | "Scan coverage incomplete" |
| Malware detected | `blocked_detection` | "Malware detected: {detections}" |
| CRITICAL finding | `blocked_detection` | "Critical security finding" |

### Implementation
```python
def should_block(report: ScanReport) -> tuple[bool, str]:
    if not all([report.inventory.coverage_complete,
                report.malware.coverage_complete,
                report.security.coverage_complete]):
        return True, "Incomplete scan coverage"
    if report.malware.status == "detected":
        return True, "Malware detected"
    if any(f.severity == "CRITICAL" for f in report.security.findings):
        return True, "Critical finding"
    return False, ""
```

---

## 10. TOCTOU Protection

### Time-of-Check/Time-of-Use Risks

| Stage | Risk | Mitigation |
|---|---|---|
| Repo detection | Symlink race | `is_symlink()` before `resolve()` |
| Path resolution | TOCTOU | `resolve(strict=True)` |
| Staging copy | File replacement | Verify stat before/after open and copy |
| Scanning | Concurrent modification | Re-verify after scan |
| Approval | Repo change before exec | Repo content hash in approval |
| Execution | Repo change during exec | Single-use approval, short TTL |

### Stable Snapshot (Malware Scanner)
```python
# Reuses _stage_repository_files from malware scanner
# - O_NOFOLLOW | O_DIRECTORY descriptors
# - File verification after open and after copy
# - Size/time limits during copy
# - Returns staged files + path mapping
```

### Approval Binding
```python
approval_context = {
    "repo_content_hash": compute_repo_hash(repo_root),  # Invalidates on any change
    "scan_config_hash": current_config_hash(),
    "policy_version": POLICY_VERSION,
    "scan_report_hash": hash(scan_report)
}
```

---

## 11. Bypass Analysis

### Complete Bypasses (Cannot Prevent)
| Bypass | Why | Documentation |
|---|---|---|
| Shell built-ins (`source`, `eval`, `.`) | No `execve`, same process | Required in docs |
| Inline interpreter (`bash -c`, `python -c`) | No file artifact | Required in docs |
| Absolute paths (`/usr/bin/npm`) | Bypasses PATH | Required in docs |

### Partial Bypasses (Reduce Coverage)
| Bypass | Impact | Mitigation |
|---|---|---|
| Direct binary paths | Misses wrapper | Log pass-through |
| `--ignore-scripts` | Skips PM lifecycle | Still scans repo |
| `sudo` | Different PATH/env | Document |
| Container/VM | Separate environment | Out of scope |

### Bypass Logging
Every wrapper pass-through logs:
```
[LinuxSecMonitor] PASSTHROUGH: /usr/bin/npm install (absolute path)
[LinuxSecMonitor] PASSTHROUGH: source script.sh (shell built-in)
[LinuxSecMonitor] PASSTHROUGH: bash -c "cmd" (inline interpreter)
```

---

## 12. Performance Considerations

### Targets
| Metric | Target |
|---|---|
| Wrapper overhead (cache hit) | < 50ms |
| Wrapper overhead (cache miss, small repo) | < 2s |
| Wrapper overhead (cache miss, large repo) | < 10s |
| Memory (daemon, optional) | < 50MB |
| Cache size (typical) | < 100MB |

### Optimization
- **Caching**: Scan results cached by `(repo_path, mtime, config_hash)`
- **TTL**: 5 minutes default
- **Incremental**: Re-scan only on repo mtime change
- **Parallel**: Inventory + Malware + Security can run concurrently

---

## 13. Kali and Debian Compatibility

| Component | Kali | Debian 12 |
|---|---|---|
| Bash/Zsh/Fish | ✅ Default | ✅ Available |
| `~/.local/bin` in PATH | ✅ Default | ✅ Default |
| systemd user services | ✅ | ✅ |
| ClamAV (`/usr/bin/clamscan`) | ✅ | ✅ |
| Python 3.11+ | ✅ | ✅ |
| eBPF LSM (kernel 6+) | ✅ Kernel 6.x | ✅ Kernel 6.x |

### Installation
```bash
# User (recommended)
linuxsecmonitor --install-wrappers
# Adds to ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish
# Creates wrappers in ~/.local/bin/

# System (optional, root)
linuxsecmonitor --install-wrappers --system
# /usr/local/bin/, /etc/profile.d/
```

---

## 14. Implementation Phases

### Phase 3A: Wrapper Framework (Week 1-2)
- Wrapper generator script
- Command classification (Tier 1/2/3)
- Repository detection
- Cache implementation

### Phase 3B: Scanner Integration (Week 2-3)
- Connect wrappers to existing scanners
- Report aggregation
- Approval flow integration

### Phase 3C: Shell Integration (Week 3)
- Bash/Zsh/Fish installer
- PATH management
- Config file support

### Phase 3D: Testing & Hardening (Week 4)
- Bypass verification tests
- Performance benchmarks
- Documentation

---

## 15. Test Strategy

### Unit Tests
- Wrapper command classification
- Repository detection (nested, symlinks, non-repo)
- Cache hit/miss/expiry
- Approval flow (mock TTY)
- Bypass detection

### Integration Tests
- Full wrapper → scan → approve → execute
- Multiple wrappers same session
- Cache sharing
- Config parsing

### Bypass Verification
- Absolute path execution
- Shell built-ins (`source`, `eval`)
- Inline interpreter (`bash -c`)
- `sudo` environment

---

## 16. Known Limitations

1. **Advisory only** - Not a sandbox or security boundary
2. **Shell built-ins cannot be intercepted** - `source`, `eval`, `.`
3. **Inline code cannot be scanned** - `bash -c`, `python -c`
4. **Absolute paths bypass wrappers** - `/usr/bin/npm`
5. **Non-interactive shells not covered** - cron, systemd, CI
6. **Container/VM not covered** - Separate environment
6. **`sudo` resets environment** - Different PATH
7. **No cross-user protection** - Per-user installation
8. **Malicious repo can modify wrappers** - User controls wrappers
9. **TOCTOU between approval and exec** - Mitigated by hash binding

---

## 17. Unresolved Technical Decisions

| Decision | Options | Status |
|---|---|---|
| Cache backend | Filesystem / SQLite / Redis | Filesystem (simpler) |
| Approval TTL | 1h / 24h / 7d | 24h default |
| Parallel scans | Sequential / concurrent | Sequential (simpler) |
| Config format | TOML / YAML / JSON | TOML |
| Daemon for caching | Optional / Required | Optional (Phase 3B) |
| eBPF LSM integration | Phase 3 / Future | Future (opt-in) |

---

## 18. Appendix: File Structure

```
.unlazy/auto-repo-protect/
├── PLAN.md
├── GATES.md
├── coverage/
│   ├── git.md
│   ├── shell.md
│   ├── interpreter.md
│   ├── build.md
│   └── dependency.md
├── architecture/
│   ├── comparison.md
│   ├── recommendation.md
│   └── architecture.md (this file)
├── workflow/
│   ├── workflow.md
│   └── threat-model.md
├── plan/
│   └── implementation-plan.md
└── gates/
    ├── node-1.1.md
    ├── node-1.2.md
    ├── node-1.3.md
    ├── node-1.4.md
    ├── node-1.5.md
    ├── leaf-1.1.1.md
    ├── leaf-1.1.2.md
    ├── leaf-1.1.3.md
    ├── leaf-1.1.4.md
    ├── leaf-1.1.5.md
    ├── leaf-1.2.1.md
    ├── leaf-1.2.2.md
    ├── leaf-1.3.1.md
    ├── leaf-1.3.2.md
    ├── leaf-1.4.1.md
    └── leaf-1.5.1.md
```