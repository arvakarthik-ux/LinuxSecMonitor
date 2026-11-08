# Priority 3 Implementation Plan

## Overview

This plan decomposes the automatic repository protection architecture into independently testable work units for Priority 3 implementation.

---

## Work Units

### 3A.1: Wrapper Framework Core
**Owner**: leaf-1.1.1
**Depends**: None
**Tier**: mechanical

**Files to Create**:
- `src/wrapper/__init__.py` - Package init
- `src/wrapper/core.py` - Wrapper base class, entry point
- `src/wrapper/commands.py` - Command definitions, tier classification
- `src/wrapper/detection.py` - Repository detection logic
- `src/wrapper/cache.py` - Scan result caching

**Interfaces**:
```python
class CommandWrapper:
    def __init__(self, command_name: str, argv: list[str])
    def should_intercept(self) -> bool
    def execute(self) -> int
```

**Acceptance Gates**:
- G1: Wrapper identifies command and finds repo root
- G2: Tier classification matches spec (Tier 1/2/3)
- G3: Cache hit/miss/expiry works correctly
- G4: Bypass detection for absolute paths, built-ins, inline

---

### 3A.2: Shell Integration
**Owner**: leaf-1.1.2
**Depends**: 3A.1
**Tier**: mechanical

**Files to Create**:
- `src/wrapper/install.py` - Shell installer (bash, zsh, fish)
- `src/wrapper/path.py` - PATH management utilities
- `src/wrapper/config.py` - Config file parsing (TOML)

**Interfaces**:
```python
def install_wrappers(shell: str, user: bool = True) -> Result
def uninstall_wrappers(shell: str, user: bool = True) -> Result
def load_config(path: Path) -> WrapperConfig
```

**Acceptance Gates**:
- G1: Installs to `~/.local/bin/` and updates shell RC
- G2: Works for bash, zsh, fish
- G3: Config file parsed correctly
- G4: Uninstall removes all traces

---

### 3A.3: Scanner Integration
**Owner**: leaf-1.1.3
**Depends**: 3A.1
**Tier**: mechanical

**Files to Create**:
- `src/wrapper/scanners.py` - Scanner orchestration
- `src/wrapper/report.py` - Report aggregation, severity classification
- `src/wrapper/approval.py` - Approval flow, binding, storage

**Interfaces**:
```python
def scan_repository_complete(repo: Path) -> ScanReport
def classify_findings(report: ScanReport) -> FindingsSummary
def prompt_approval(report: ScanReport, cmd: str, argv: list) -> bool
def verify_approval(approval: Approval, report: ScanReport) -> bool
```

**Acceptance Gates**:
- G1: All three scanners execute and aggregate
- G2: Findings classified by severity (CRITICAL/HIGH/MEDIUM/LOW)
- G3: Approval prompt shows findings, requires exact RUN
- G4: Approval binding includes repo hash, config hash, policy version
- G5: Fail-closed on incomplete/error/detection

---

### 3A.4: Command Execution Safety
**Owner**: leaf-1.1.4
**Depends**: 3A.3
**Tier**: mechanical

**Files to Create**:
- `src/wrapper/execute.py` - Safe command execution
- `src/wrapper/audit.py` - Audit logging

**Interfaces**:
```python
def execute_approved(report: ScanReport, repo: Path, argv: list[str]) -> int
def log_audit(entry: AuditEntry) -> None
```

**Acceptance Gates**:
- G1: Executes via argv (no shell), resolved cwd
- G2: No environment leakage
- G3: Audit entry recorded with all required fields
- G3: Approval consumed (single-use)

---

### 3A.5: Git Operations Coverage
**Owner**: leaf-1.1.5
**Depends**: 3A.1
**Tier**: mechanical

**Files to Create**:
- `src/wrapper/commands/git.py` - Git-specific logic

**Acceptance Gates**:
- G1: `git checkout`, `merge`, `pull`, `rebase` classified Tier 1
- G2: `git clone` triggers post-clone scan
- G3: `git status`, `log`, `diff` classified Tier 3 (passthrough)
- G4: Bypass detection for `--no-verify`, absolute paths

---

### 3B.1: Enforcement Architecture Decision
**Owner**: leaf-1.2.1
**Depends**: None
**Tier**: judgment

**Files to Create**:
- `docs/architecture/comparison.md` - Mechanism comparison
- `docs/architecture/recommendation.md` - Recommended architecture

**Acceptance Gates**:
- G1: All 7 mechanisms evaluated with criteria
- G2: Clear recommendation with rationale
- G3: Rejected alternatives documented with reasons
- G4: Decision record for implementation proof

---

### 3B.2: Architecture Design Document
**Owner**: leaf-1.2.2
**Depends**: 3B.1
**Tier**: judgment

**Files to Create**:
- `docs/architecture/architecture.md` - Complete architecture

**Acceptance Gates**:
- G1: Executive summary, existing analysis, requirements
- G2: Threat model, coverage matrix, architecture diagram
- G3: Workflow, scanner integration, approval design
- G4: Fail-closed, TOCTOU, bypass analysis
- G5: Performance, compatibility, implementation phases
- G6: Known limitations, unresolved decisions

---

### 3C.1: Security Workflow Design
**Owner**: leaf-1.3.1
**Depends**: 3A.3
**Tier**: judgment

**Files to Create**:
- `docs/workflow/workflow.md` - Complete workflow stages

**Acceptance Gates**:
- G1: All 12 stages defined with pseudocode
- G2: Approval binding, expiration, invalidation
- G3: Fail-closed conditions enumerated
- G4: TOCTOU protections per stage

---

### 3C.2: Threat Model
**Owner**: leaf-1.3.2
**Depends**: None
**Tier**: judgment

**Files to Create**:
- `docs/workflow/threat-model.md` - Complete threat model

**Acceptance Gates**:
- G1: Assets, actors, capabilities defined
- G2: Privilege boundaries, trusted components
- G3: Bypass analysis, residual risks
- G4: Accepted risks explicitly documented

---

### 3D.1: Complete Architecture Document
**Owner**: leaf-1.4.1
**Depends**: 3A.1-3A.5, 3B.1-3B.2, 3C.1-3C.2
**Tier**: judgment

**Files to Create**:
- `docs/architecture/architecture.md` - Final integrated document

**Acceptance Gates**:
- G1: All design components integrated
- G2: Cross-references between sections
- G3: Consistent terminology
- G4: Ready for implementation handoff

---

### 3E.1: Priority 3 Implementation Plan
**Owner**: leaf-1.5.1
**Depends**: 3D.1
**Tier**: judgment

**Files to Create**:
- `docs/plan/implementation-plan.md` - This document

**Acceptance Gates**:
- G1: All work units defined with owners, deps, gates
- G2: Dependency graph acyclic
- G3: Test strategy per unit
- G4: Acceptance criteria measurable

---

## Dependency Graph

```
3A.1 (Wrapper Core)
    │
    ├──→ 3A.2 (Shell Integration)
    ├──→ 3A.3 (Scanner Integration) ──→ 3A.4 (Execution Safety)
    ├──→ 3A.5 (Git Commands)
    │
3B.1 (Architecture Comparison) ──→ 3B.2 (Architecture Design)
    │
3C.1 (Workflow Design) ←── 3A.3
3C.2 (Threat Model)
    │
3D.1 (Complete Architecture) ←── 3B.2, 3C.1, 3C.2
    │
3E.1 (Implementation Plan) ←── 3D.1
```

---

## Test Strategy

### Unit Tests (Per Work Unit)
| Unit | Test Focus |
|---|---|
| 3A.1 | Command detection, repo finding, tier classification, cache |
| 3A.2 | Shell RC modification, PATH, config parsing, uninstall |
| 3A.3 | Scanner orchestration, finding classification, approval flow |
| 3A.4 | Safe exec (argv, no shell), audit logging, approval consumption |
| 3A.5 | Git command classification, post-clone scan trigger |
| 3B.1 | Mechanism comparison completeness |
| 3B.2 | Architecture document completeness |
| 3C.1 | Workflow stage coverage |
| 3C.2 | Threat model coverage |
| 3D.1 | Document integration |
| 3E.1 | Plan completeness |

### Integration Tests
- Full wrapper → scan → approve → execute flow
- Multiple wrappers in same shell session
- Cache sharing across wrappers
- Config file changes invalidate cache

### Bypass Verification Tests
- Absolute path execution (`/usr/bin/npm`)
- Shell built-ins (`source`, `eval`, `.`)
- Inline interpreter (`bash -c "cmd"`)
- `sudo` environment
- `--no-verify` Git flag

### Performance Tests
- Wrapper overhead (cache hit < 50ms, miss < 2s small repo)
- Memory usage (< 50MB daemon)
- Scan timeouts respected

---

## Regression Risks

| Risk | Mitigation |
|---|---|
| Wrapper breaks existing commands | Extensive passthrough tests |
| Scanner changes break integration | Scanner interfaces frozen, versioned |
| Shell config corruption | Backup before install, verified uninstall |
| Cache corruption | Cache versioning, auto-rebuild |
| Approval binding too strict | Test repo modifications, config changes |

---

## Security Acceptance Criteria

### Must Pass (Blocking)
- [ ] All Tier 1 commands require approval
- [ ] Incomplete scan blocks execution
- [ ] Malware detection blocks execution
- [ ] No TTY blocks execution
- [ ] Exact RUN required (case-sensitive)
- [ ] Approval bound to repo content hash
- [ ] Approval single-use
- [ ] Execution via argv, no shell
- [ ] Audit log recorded

### Should Pass (Non-Blocking)
- [ ] Tier 2 commands warn but auto-approve
- [ ] Tier 3 commands pass through
- [ ] Cache reduces scan time > 90%
- [ ] Bypass detection logs appropriately
- [ ] Config changes invalidate cache

### Nice to Have
- [ ] Daemon caching reduces memory
- [ ] Parallel scanner execution
- [ ] eBPF LSM opt-in design

---

## Timeline Estimate

| Phase | Work Units | Duration |
|---|---|---|
| Phase 1: Core Framework | 3A.1, 3A.2 | 2 weeks |
| Phase 2: Scanner Integration | 3A.3, 3A.4, 3A.5 | 2 weeks |
| Phase 3: Architecture & Workflow | 3B.1, 3B.2, 3C.1, 3C.2 | 1 week |
| Phase 4: Integration & Testing | 3D.1, 3E.1 + integration tests | 1 week |
| **Total** | | **6 weeks** |

---

## Files Created/Modified Summary

### New Files (Priority 3)
```
src/wrapper/
├── __init__.py
├── core.py
├── commands.py
├── commands/
│   └── git.py
├── detection.py
├── cache.py
├── install.py
├── path.py
├── config.py
├── scanners.py
├── report.py
├── approval.py
├── execute.py
├── audit.py
├── wrapper_entry.py  # Generated wrapper script template
docs/
├── architecture/
│   ├── comparison.md
│   ├── recommendation.md
│   └── architecture.md
├── workflow/
│   ├── workflow.md
│   └── threat-model.md
└── plan/
    └── implementation-plan.md
```

### Modified Files (Priority 1 Reuse)
```
scanner/execution_guard.py      # Reused as-is
scanner/repository_scanner.py    # Reused as-is
scanner/repository_malware_scanner.py  # Reused as-is
scanner/repository_security_scanner.py # Reused as-is
main.py                          # Extended with --install-wrappers
```

---

## Next Steps

1. **Start 3A.1**: Implement wrapper core with command detection and repo finding
2. **Parallel 3B.1**: Document architecture comparison (already done in design phase)
3. **Gate Review**: Each work unit gated by acceptance criteria
4. **Integration**: Combine into full system after individual units verified