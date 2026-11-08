# Security Workflow Design

## Overview

This document describes the complete security workflow for automatic repository protection, from operation detection through approval to execution.

---

## Workflow Stages

### Stage 1: Detect Supported Operation

**Trigger**: User executes a wrapped command

**Detection Logic**:
```python
def is_supported_operation(cmd: str, argv: list[str], cwd: Path) -> bool:
    # 1. Check if command is in wrapper list
    if cmd not in WRAPPED_COMMANDS:
        return False

    # 2. Check if in repository context
    repo_root = find_repository_root(cwd)
    if not repo_root:
        return False

    # 3. Classify command risk tier
    tier = classify_command(cmd, argv, repo_root)
    if tier == Tier.PASSTHROUGH:
        return False

    return True
```

**Output**: `(repo_root, tier, argv)` or `None` (pass through)

---

### Stage 2: Identify Repository & Working Directory

**Repository Identification**:
- Walk up from `cwd` to find `.git` directory
- Fallback: Project markers (`package.json`, `Cargo.toml`, `pyproject.toml`, `go.mod`, `pom.xml`, `build.gradle`, `meson.build`, `CMakeLists.txt`, `Makefile`)

**Working Directory Resolution**:
- Use `cwd` as execution directory
- Repository root for scanning
- Command executes in `cwd` (not necessarily repo root)

**Path Safety**:
- Resolve all paths with `Path.resolve(strict=True)`
- Reject symlinks for repository root
- Validate `cwd` is within or equal to repo root

---

### Stage 3: Resolve Paths Safely

**Repository Path Validation** (reuses Priority 1):
```python
def validate_repository_path(path: Path) -> Result:
    # 1. Expand user (~)
    path = path.expanduser()

    # 2. Check symlink BEFORE resolve
    if path.is_symlink():
        return Error("Repository path must not be a symlink")

    # 3. Resolve
    resolved = path.resolve(strict=False)

    # 4. Verify directory
    if not resolved.is_dir():
        return Error("Not a directory")

    return Ok(resolved)
```

**Command Path Validation**:
- Arguments passed as `argv` array (no shell parsing)
- No shell interpolation
- Working directory validated as above

---

### Stage 4: Obtain Stable Inspection Target

**Problem**: Repository may change during scan (TOCTOU)

**Solution**: Stable Snapshot Approach

```python
def create_inspection_snapshot(repo_root: Path) -> Path:
    # 1. Create temp directory with secure permissions
    with tempfile.TemporaryDirectory(prefix="linuxsecmonitor-scan-") as tmp:
        snapshot = Path(tmp) / "repo"

        # 2. Copy with safety checks (reuses malware scanner staging)
        # - No symlink following
        # - Size/file limits
        # - Verify file stability during copy
        stage_repository_files(repo_root, snapshot)

        # 3. Return snapshot path for scanning
        return snapshot
```

**Staging Reuses**: `scanner.repository_malware_scanner._stage_repository_files`
- No-follow directory descriptors (`O_NOFOLLOW | O_DIRECTORY`)
- File verification after open and after copy
- Limits: files, directories, total bytes, time

**Alternative for Large Repos**: Scan in-place with revalidation
- Record file mtimes/sizes before scan
- Re-verify after scan
- Mark incomplete if changes detected

---

### Stage 5: Run Scanners

**Pipeline** (All reuse Priority 1 implementations):

```python
def scan_repository_complete(repo_path: Path, include_generated: bool = False) -> ScanReport:
    # 1. Inventory (fast, metadata only)
    inventory = scan_repository(repo_path)

    # 2. Malware (ClamAV on staged files)
    malware = scan_repository_malware(repo_path)

    # 3. Security (static analysis)
    security = scan_repository_security(repo_path, include_generated=include_generated)

    return ScanReport(
        repository=repo_path,
        inventory=inventory,
        malware=malware,
        security=security,
        scan_time=datetime.now(),
        config_hash=current_config_hash()
    )
```

**Fail-Closed Behavior**:
- Any scanner error → `blocked_incomplete`
- Malware detection → `blocked_detection` (configurable)
- Timeout → `blocked_incomplete`
- Coverage incomplete → `blocked_incomplete`

---

### Stage 6: Inspect Dependencies, Installation Instructions, Build Files

**Dependency Manifest Analysis** (part of security scan):

| File | What's Checked |
|---|---|
| `package.json` | `scripts` (preinstall, install, postinstall, prepare), `dependencies`, `devDependencies`, `optionalDependencies` |
| `requirements.txt` / `pyproject.toml` | Direct URL deps, git deps, `--extra-index-url` |
| `Cargo.toml` | `build.rs`, `build-dependencies`, `[patch]`, `[replace]`, git deps |
| `go.mod` / `go.sum` | `replace` directives, indirect deps, module proxies |
| `pom.xml` | Plugins, profiles, repositories |
| `composer.json` | `scripts`, `repositories`, `require-dev` |
| `Gemfile` | `git:` sources, `:github`, `:path`, `gemspec` |
| `Makefile` / `CMakeLists.txt` | `$(shell)`, `execute_process`, custom commands |
| `.github/workflows/` | CI triggers, permissions, secrets |
| `Dockerfile` | `RUN` commands, `ADD`/`COPY` from URLs |

**Risk Classification**:
- **Critical**: Malware detection, active exploit patterns
- **High**: Secrets, `postinstall`/`build.rs` downloading/executing, `eval`/`exec`
- **Medium**: `preinstall`/`prepare`, suspicious URLs, `go:generate`
- **Low**: Build file presence, CI workflow existence

---

### Stage 7: Generate Detailed Report

**Report Structure**:
```python
@dataclass
class ScanReport:
    repository: Path
    scan_time: datetime
    config_hash: str
    repo_content_hash: str  # For approval binding

    inventory: RepositoryInventory
    malware: MalwareAssessment
    security: SecurityAssessment

    # Aggregated for display
    summary: ScanSummary

    # Approval binding
    approval_context: ApprovalContext
```

**Display Format** (Text + JSON):
```
LinuxSecMonitor — Pre-Execution Scan
Repository: /home/user/project
Command: npm install express
Scan Time: 2026-11-04 10:30:15
Coverage: Complete ✓

┌─ FINDINGS ────────────────────────────────────────────────┐
│ CRITICAL (1)                                              │
│   ▸ MALWARE: EICAR-Test-Signature in test/fixture.exe    │
│                                                           │
│ HIGH (3)                                                  │
│   ▸ SECRET: GitHub token in .env.example:15              │
│   ▸ RISKY: postinstall script downloads binary           │
│   ▸ HOOK: Active pre-commit hook executes shell          │
│                                                           │
│ MEDIUM (2)                                                │
│   ▸ DEPENDENCY: Git dependency in package.json           │
│   ▸ GENERATE: go:generate directive in main.go           │
└────────────────────────────────────────────────────────────┘

Type exactly RUN to proceed, or CANCEL to abort:
```

---

### Stage 8: Classify Findings by Severity and Confidence

**Severity Levels**:
| Level | Criteria | Action |
|---|---|---|
| CRITICAL | Malware detection, active exploit, ransomware | Block (no override) |
| HIGH | Secrets, download-and-execute, active hooks, `build.rs`/`postinstall` with network | Block by default, override with explicit approval |
| MEDIUM | Git deps, `go:generate`, CI workflows, suspicious URLs | Warn, require acknowledgement |
| LOW | Build file presence, inactive hooks, informational | Info only |

**Confidence Levels**:
| Level | Criteria |
|---|---|
| CONFIRMED | Malware signature match, exact secret pattern |
| HIGH | Heuristic match with low false positive rate |
| MEDIUM | Pattern match with known false positives |
| LOW | Informational, presence-based |

**Display**: Severity + Confidence (e.g., "HIGH/CONFIRMED", "MEDIUM/HIGH")

---

### Stage 9: Require Explicit Approval

**Approval Requirements**:

| Tier | Approval Required | Default |
|---|---|---|
| CRITICAL finding | Yes (no override) | Blocked |
| HIGH finding | Yes | Blocked |
| MEDIUM finding | Acknowledgment | Warn |
| LOW finding | No | Info |
| Tier 1 command (no findings) | Yes | Blocked |
| Tier 2 command | Warning only | Auto-approve |
| Tier 3 command | None | Pass through |

**Approval Mechanism** (Reuses `execution_guard.confirm_execution`):
- Exact string `RUN` (case-sensitive)
- 5-minute timeout (configurable)
- EOF/Ctrl+C → Cancel
- No TTY → Cancel (fail-closed)
- Binary terminal support

**Approval Binding** (Cryptographic):
```python
approval_context = {
    "repo_path": str(repo_root),
    "repo_content_hash": compute_repo_hash(repo_root),  # Git commit hash or file hash
    "command": cmd,
    "argv": argv,
    "scan_config_hash": current_config_hash(),
    "policy_version": POLICY_VERSION,
    "scan_report_hash": hash(scan_report),
    "timestamp": datetime.now().isoformat()
}
```

**Approval Storage**:
- Local: `~/.cache/linuxsecmonitor/approvals/`
- Keyed by `approval_context` hash
- TTL: 24 hours (configurable)
- Single-use: Approval consumed on execution

---

### Stage 10: Prevent Execution on Incomplete/Failed Inspection

**Blocking Conditions**:
| Condition | Status | Message |
|---|---|---|
| Inventory scan error | `blocked_incomplete` | "Repository inventory failed: {error}" |
| Malware scan error | `blocked_incomplete` | "Malware scan failed: {error}" |
| Security scan error | `blocked_incomplete` | "Security scan failed: {error}" |
| Any scan timeout | `blocked_incomplete` | "Scan timed out" |
| Coverage incomplete | `blocked_incomplete` | "Scan coverage incomplete: {limitations}" |
| Malware detected | `blocked_detection` | "Malware detected: {detections}" |
| Critical finding | `blocked_detection` | "Critical security finding: {finding}" |

**Fail-Closed Implementation**:
```python
def should_block(report: ScanReport) -> tuple[bool, str]:
    if not report.inventory.coverage_complete:
        return True, "Inventory incomplete"
    if not report.malware.coverage_complete:
        return True, "Malware scan incomplete"
    if not report.security.coverage_complete:
        return True, "Security scan incomplete"
    if report.malware.status == "detected":
        return True, "Malware detected"
    if any(f.severity == "CRITICAL" for f in report.security.findings):
        return True, "Critical finding"
    return False, ""
```

---

### Stage 11: Permit Execution According to Approved Decision

**Execution Flow**:
```python
def execute_approved(report: ScanReport, repo_root: Path, argv: list[str], approval: Approval) -> int:
    # 1. Verify approval matches current context
    if not verify_approval(approval, report, argv):
        return EXIT_APPROVAL_INVALID

    # 2. Mark approval as consumed (single-use)
    consume_approval(approval)

    # 3. Execute via execution guard (reuses Priority 1)
    return run_reviewed_command(
        report=report.to_dict(),
        repository=repo_root,
        command=argv,
        terminal=get_tty(),
        json_output=False
    )
```

**Execution Safety** (from `execution_guard`):
- `shell=False` (argv array, no shell)
- `cwd=repo_root.resolve(strict=True)`
- No environment leakage
- Command stdout/stderr passed through (or to stderr for JSON)

---

### Stage 12: Record Outcome

**Audit Log Entry**:
```python
@dataclass
class AuditEntry:
    timestamp: datetime
    repo_path: str
    repo_content_hash: str
    command: str
    argv: list[str]
    tier: str
    scan_report_hash: str
    findings_summary: dict  # counts by severity
    approval_hash: str
    outcome: str  # "executed", "cancelled", "blocked", "error"
    exit_code: int | None
    duration_ms: int
```

**Storage**:
- Local: `~/.local/share/linuxsecmonitor/audit.log` (JSONL)
- Rotated daily, retained 90 days (configurable)
- No sensitive data (secrets redacted in findings)

---

## Approval Expiration & Invalidation

**Expiration**:
- TTL: 24 hours (configurable)
- Single-use: Consumed on execution
- New scan required after expiry

**Invalidation Triggers**:
1. Repository content changed (new commit, file modification)
2. Scan configuration changed
3. Policy version incremented
4. Manual: `linuxsecmonitor --revoke-approvals`

**Revalidation**:
```python
def is_approval_valid(approval: Approval, current_report: ScanReport) -> bool:
    if approval.repo_content_hash != current_report.repo_content_hash:
        return False  # Repo changed
    if approval.scan_config_hash != current_config_hash():
        return False  # Config changed
    if approval.policy_version != POLICY_VERSION:
        return False  # Policy changed
    if approval.expired():
        return False  # TTL expired
    return True
```

---

## TOCTOU Protection Summary

| Stage | Protection |
|---|---|
| Detection | N/A (read-only) |
| Repo ID | Path validation (no symlinks) |
| Path Resolution | `resolve(strict=True)`, symlink check |
| Stable Target | Staged copy with file verification |
| Scanning | Re-verify file stability after scan |
| Approval | Bound to repo content hash |
| Execution | Re-verify approval at exec time |

**Residual Risk**: Repository modified between approval and execution
- **Mitigation**: Short approval TTL (24h), single-use, repo hash binding
- **Acceptance**: Advisory system - user can re-scan if concerned