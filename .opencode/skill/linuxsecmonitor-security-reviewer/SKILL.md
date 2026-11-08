# LinuxSecMonitor Security Reviewer Skill

This skill provides project-specific security review guidance for LinuxSecMonitor.

## APT Transaction Safety

When reviewing APT hook code (`scanner/apt_hook.py`, `scanner/apt_lifecycle.py`):

**Protocol Parsing:**
- `parse_pre_install_v3` must reject malformed input (size limits, control chars, invalid encoding)
- Never accept incomplete transactions; fail closed on any parse error
- Validate every archive path: absolute, no `..`, `.deb` suffix, not symlink, root-owned, not user-writable

**Archive Validation (`_safe_archive_path`):**
- `O_NOFOLLOW` open → `fstat` → capture identity → re-verify after scan
- Reject: traversal, symlinks, non-regular files, size > `MAX_PACKAGE_BYTES`, non-root-owned paths
- Root-protection chain check: every parent directory root-owned, not writable by others (except sticky)

**Privilege Dropping (`_drop_to_apt_sandbox_user`):**
- Runs as root from APT, must drop to `_apt` user via `setgid`/`setuid` + `setgroups`
- Verify real/effective/saved IDs all dropped (`getresuid`/`getresgid`)
- Terminal opened *after* privilege drop (never held with root)

**Scanner Execution (`_scan_with_trusted_path`):**
- Uses trusted PATH `/usr/sbin:/usr/bin:/sbin:/bin` (not caller's PATH)
- Restores original PATH after scan

**Approval (`_prompt_for_detection`):**
- Exact `INSTALL` match only; lowercase, spaces, empty, EOF, timeout, interrupt → cancel
- Opens `/dev/tty` as `_apt` user after privilege drop
- 300s timeout via `select.select`

**Transaction Blocking:**
- Blocks on: incomplete coverage, error, unavailable, detection, archive mismatch, changed archive, missing terminal
- `**CONFIGURE**`/`**REMOVE**` without matching archive → block
- Vulnerability assessment aggregated before approval; `error`/`requires_review` → block

## Pre-Installation Execution Guarantees

When reviewing `--preinstall-deb` (`main.py:_run_preinstall_deb`):

**Snapshot Creation (`_create_package_snapshot`):**
- Size-limited copy with `O_NOFOLLOW`, identity verification before/after
- `0o700` temp dir, `0o600` package file
- Fails if package changes during copy (dev/ino/size/mtime/ctime)

**APT Sandbox Permissions (`_prepare_snapshot_for_apt`):**
- `chgrp` to `_apt` GID, `chmod 0710` dir, `chmod 0640` file
- Only `_apt` group can traverse/read; not world-accessible
- Uses `sudo` only if not root

**Approval:**
- Exact `INSTALL` required; shows scope warning about unscanned dependencies
- `sudo -v` for admin auth *after* user approval
- APT runs with `--no-remove`; APT's own confirmation remains

## Package Extraction

When reviewing `.deb` scanning (`scanner/malware_scanner.py`):

- Uses `dpkg-deb --ctrl-tar` and `dpkg-deb --fs-tar` (no full extraction to persistent paths)
- ClamAV scans extracted contents in temp directory
- Maintainer scripts read as bounded text (size limits, no execution)
- Static heuristics: download-to-shell, destructive-device, startup-persistence patterns
- All temp cleaned up on exit (success or failure)

## Privilege Boundaries

**APT Hook:** Root → `_apt` before any archive access; terminal after drop
**Pre-install Deb:** Normal user scan; `sudo` only for permissions + APT after approval
**Wrapper:** No privilege escalation; uses trusted PATH for subprocesses
**Lifecycle:** Requires root for install/enable/disable/uninstall; atomic writes to root-owned paths

## Wrapper Security

When reviewing `src/wrapper/`:

**Command Classification (`commands.py`):**
- TIER_1_DANGEROUS: git checkout/pull/merge, npm/pip/cargo install, docker build/run, make install
- TIER_2_WARN: git status/diff/log, npm/pip/cargo build/test, make, python, shells
- TIER_3_PASSTHROUGH: explicit passthrough patterns
- BYPASS: absolute paths, shell builtins, inline interpreters (`bash -c`), sudo
- UNKNOWN defaults to TIER_2_WARN for known dangerous commands

**Repository Detection (`detection.py`):**
- Finds Git root via `git rev-parse --show-toplevel` (no shell, bounded timeout)
- Handles nested repos, avoids trusting repo metadata

**Scanner Orchestration (`scanners.py`):**
- Private snapshot copy (excludes `.git`, symlinks)
- Content hash before/after snapshot + scan → detects concurrent modification
- Parallel bounded execution with 120s timeout per scanner
- `coverage_complete` false if repository changed during scan

**Approval (`approval.py`):**
- Bound to: repo content hash, argv, cwd, config hash, scanner versions, malware DB version
- TTL 300s; consumed approvals cannot be reused
- `RUN` token exact match (like APT's `INSTALL`)

**Path Resolution (`path.py`):**
- Resolves executables without trusting PATH
- Uses allowlist of trusted directories

## Fail-Open vs Fail-Closed

**Always Fail-Closed:**
- Protocol parsers (APT, OSV, dpkg-query)
- Archive validation
- Privilege dropping
- Approval prompts (missing terminal, timeout, interrupt, non-exact token)
- Scanner coverage (incomplete/error/unavailable → block)
- TOCTOU checks (identity mismatch, concurrent modification)
- Lifecycle atomic writes (hard-link, fails on race)

**Never Fail-Open:**
- No "unknown = safe" for vulnerability assessment (`no_known_match` ≠ safe)
- No bypass for incomplete ClamAV coverage
- No automatic approval for heuristic findings
- No trust of caller PATH, environment, or repository metadata

## TOCTOU and Race Conditions

**APT Archives:**
- `O_NOFOLLOW` open → `fstat` identity → scan → re-verify identity
- Root-protection chain validated while still root

**Pre-install Snapshot:**
- Copy with size limit, verify dev/ino/size/mtime/ctime unchanged
- Permissions set before APT access

**Repository Snapshot:**
- Private copy to `0o700` temp
- Content hash of original → snapshot → post-scan original
- Any change → `repository_changed_during_scan` = true → `coverage_complete` = false

**Lifecycle Configs:**
- `_atomic_write`: temp file → `fsync` → hard-link (atomic, fails on EEXIST) → `fsync` directory
- Validates with `apt-config -c` before activation
- State file tracks hook SHA-256, python path, format version

## Approval and Cancellation Correctness

**Token Requirements:**
- Exact `INSTALL` (APT) or `RUN` (wrapper) — case-sensitive, no trimming
- Lowercase, extra whitespace, empty, EOF, Ctrl-C, timeout → cancel

**Binding:**
- APT: transaction archives + vulnerability assessment + scanner versions
- Wrapper: repo content hash + argv + cwd + config hash + scanner versions + malware DB version

**TTL and Consumption:**
- 300s default TTL
- `consumed` flag prevents reuse
- Re-validation on consume (all binding factors must match)

**JSON Mode:**
- Human preview to stderr (includes approval prompt context)
- Command args deliberately omitted from JSON output
- Child stdout/stderr routed to stderr so stdout remains valid JSON