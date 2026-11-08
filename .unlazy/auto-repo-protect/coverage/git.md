# Git Operations Coverage Analysis

## Operation: `git clone <url> <directory>`

### When Repository Content Becomes Available
- Git downloads objects and checks out files to the target directory
- Repository content is fully available **after** `git clone` completes
- No repository-controlled code executes during clone (only Git internal code)

### Inspection Timing
- **Can inspect before dangerous operations**: YES - after clone completes, before user runs any commands
- **Cannot inspect during clone**: Repository doesn't exist yet
- **Recommended approach**: Post-clone hook or wrapper that scans the newly created directory

### Enforcement Mechanism
| Mechanism | Feasibility | Blocks Execution? | Bypass Risk |
|---|---|---|---|
| Git `post-checkout` hook | High | No (runs after checkout) | User can skip with `--no-checkout` or manually checkout |
| Shell wrapper `git` function/alias | Medium | Only if user uses wrapper | Direct `/usr/bin/git` bypass |
| PATH wrapper (`git` in PATH before system) | Medium | Only if wrapper invoked | Absolute path `/usr/bin/git` bypass |
| Git config `core.hooksPath` wrapper | Low | No | Config can be overridden |
| Systemd/LSM enforcement | Low | Yes (kernel-level) | Requires root, complex |

### Bypass Analysis
- User runs `/usr/bin/git clone` directly
- User clones with `--no-checkout` then manually checks out
- User uses alternate Git binary
- Git submodules: separate clones may not trigger wrapper

### Verdict
**Post-clone inspection is practical and recommended.** Cannot block the clone itself, but can scan immediately after and warn/block subsequent operations in that repository.

---

## Operation: `git pull` / `git fetch` / `git merge`

### When Repository Content Changes
- `git fetch`: Downloads objects, no working tree changes
- `git pull`: Fetch + merge, updates working tree
- `git merge`: Merges commits, updates working tree

### Inspection Timing
- **Can inspect before execution**: Only if wrapper intercepts command
- **Post-execution inspection**: Always possible (scan after merge)
- **Pre-execution inspection of incoming changes**: Difficult (requires fetching first)

### Enforcement Mechanism
| Mechanism | Feasibility | Blocks Execution? | Bypass Risk |
|---|---|---|---|
| Git `pre-merge-commit` hook | Medium | Yes (before merge commit) | `--no-verify` bypasses |
| Shell wrapper | Medium | Only if wrapper invoked | Direct binary bypass |
| Post-merge scan + block future ops | High | No (advisory) | User can run commands before scan |

### Bypass Analysis
- `git pull --no-verify` skips hooks
- Direct `/usr/bin/git` bypasses wrappers
- Fast-forward merges may not trigger merge hooks

### Verdict
**Post-merge inspection with advisory blocking of subsequent operations.** Pre-merge blocking via hooks is unreliable due to `--no-verify`.

---

## Operation: `git checkout` / `git switch`

### When Repository Content Changes
- Switches branches, updates working tree
- Can execute `post-checkout` hook

### Inspection Timing
- **Post-checkout hook**: Runs after working tree updated
- **Pre-checkout**: No standard hook

### Enforcement Mechanism
| Mechanism | Feasibility | Blocks Execution? | Bypass Risk |
|---|---|---|---|
| Git `post-checkout` hook | Medium | No (runs after) | `--no-verify` bypasses |
| Shell wrapper | Medium | Only if wrapper invoked | Direct binary bypass |

### Bypass Analysis
- `git checkout --no-verify` (for some operations)
- Direct `/usr/bin/git` bypasses wrappers

### Verdict
**Post-checkout scan with advisory blocking.** Cannot reliably block checkout itself.

---

## Operation: `git submodule update --init --recursive`

### When Repository Content Becomes Available
- Clones submodules into nested directories
- Each submodule is a separate repository

### Inspection Timing
- **Post-submodule-update**: Can scan each submodule
- **During clone**: Same as `git clone`

### Enforcement Mechanism
| Mechanism | Feasibility | Blocks Execution? | Bypass Risk |
|---|---|---|---|
| Post-update scan of all submodules | High | Advisory only | Submodules cloned directly bypass |

### Bypass Analysis
- User runs `git submodule update` directly
- User clones submodules manually
- Nested repositories may not be discovered by parent scan

### Verdict
**Recursive post-update scan of all submodules.** Each submodule treated as independent repository.

---

## Summary: Git Operations Coverage Matrix

| Operation | Pre-Execution Block | Post-Execution Scan | Advisory Block Future Ops | Bypass Risk |
|---|---|---|---|---|
| `git clone` | No | Yes | Yes | High (direct binary, --no-checkout) |
| `git pull` | Hook (unreliable) | Yes | Yes | High (--no-verify, direct binary) |
| `git fetch` | N/A | Yes (no tree change) | N/A | Medium |
| `git merge` | Hook (unreliable) | Yes | Yes | High (--no-verify) |
| `git checkout` | Hook (unreliable) | Yes | Yes | High (--no-verify) |
| `git submodule update` | No | Yes (recursive) | Yes | High |

**Key Finding**: Git operations cannot be reliably blocked at the Git level. The practical approach is **post-operation scanning with advisory blocking of subsequent dangerous commands** in the repository directory.