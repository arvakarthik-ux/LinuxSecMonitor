"""Bounded static review of repository files without executing their contents.

Findings are heuristic review leads, not malware or safety verdicts. The
scanner reads regular files through no-follow directory descriptors on POSIX,
skips Git internals except the default local hooks directory, and never invokes
Git, a shell, a build tool, or a package manager.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILES = 50_000
MAX_DIRECTORIES = 10_000
MAX_DIRECTORY_ENTRIES = 20_000
MAX_DIRECTORY_DEPTH = 128
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SCAN_SECONDS = 20.0
READ_CHUNK_BYTES = 64 * 1024
MAX_GIT_CONFIG_BYTES = 1024 * 1024

_PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
_TOKEN_PATTERNS = (
    ("github-token-like-value", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{25,})\b")),
    ("aws-access-key-id-like-value", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token-like-value", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
)
_RISKY_COMMAND_PATTERNS = (
    ("download-piped-to-shell", re.compile(rb"(?im)\b(?:curl|wget)\b[^\r\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b")),
    ("encoded-command-decoding", re.compile(rb"(?im)\b(?:base64\s+(?:--decode|-d)|powershell\s+[^\r\n]*-enc(?:odedcommand)?)\b")),
    ("shell-evaluation", re.compile(rb"(?im)(?:\beval\s+\$\(|\beval\s+\"\$\(|\bexec\s*\(\s*['\"](?:sh|bash)\b)")),
    ("privileged-or-destructive-command", re.compile(rb"(?im)(?:\bsudo\s+(?:rm|chmod|chown|dd)\b|\brm\s+-rf\s+/(?:\s|$)|\bchmod\s+[0-7]*[2467]55\b)")),
)
_LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare")
_EXECUTION_FILES = {"setup.py", "makefile", "dockerfile", "build.rs"}
_GIT_HOOK_NAMES = {
    "applypatch-msg", "commit-msg", "fsmonitor-watchman", "post-applypatch",
    "post-checkout", "post-commit", "post-merge", "post-receive",
    "post-rewrite", "post-update", "pre-applypatch", "pre-commit",
    "pre-merge-commit", "pre-push", "pre-rebase", "pre-receive",
    "prepare-commit-msg", "push-to-checkout", "reference-transaction", "update",
}
_PYTHON_CACHE_DIRECTORIES = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
_PYTHON_BYTECODE_SUFFIXES = {".pyc", ".pyo"}
_URL_DEPENDENCY = re.compile(rb"(?im)^\s*(?:-e\s+|--editable\s+|[A-Za-z0-9_.-]+\s*@\s*)?(?:git\+|https?://|ssh://)\S+")


@dataclass(frozen=True)
class RepositorySecurityFinding:
    """One heuristic that a reviewer should inspect in context."""

    rule_id: str
    severity: str
    path: str
    evidence: str
    explanation: str
    line_number: int | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "evidence": self.evidence,
            "explanation": self.explanation,
        }
        if self.line_number is not None:
            result["line_number"] = self.line_number
        return result


@dataclass
class RepositorySecurityAssessment:
    """Result of bounded repository content review."""

    status: str
    repository_path: str
    files_inspected: int = 0
    bytes_inspected: int = 0
    findings: list[RepositorySecurityFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    coverage_complete: bool = False
    note: str = (
        "Static heuristics identify review leads only. They do not prove a repository "
        "malicious or safe; repository code was not executed."
    )
    include_generated: bool = False
    generated_paths_excluded: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "repository_path": self.repository_path,
            "files_inspected": self.files_inspected,
            "bytes_inspected": self.bytes_inspected,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": list(self.errors),
            "limitations": list(self.limitations),
            "coverage_complete": self.coverage_complete,
            "note": self.note,
            "include_generated": self.include_generated,
            "generated_paths_excluded": self.generated_paths_excluded,
        }


def _supports_safe_walk() -> bool:
    return (
        os.name == "posix"
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.scandir in os.supports_fd
    )


def _same_file_metadata(before: os.stat_result, after: os.stat_result) -> bool:
    """Return whether two file snapshots describe unchanged relevant metadata.

    Comparing mode and ownership explicitly catches changes such as ``chmod``
    even on filesystems where two rapid updates can share a ctime timestamp.
    """
    return (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_mode == after.st_mode
        and before.st_uid == after.st_uid
        and before.st_gid == after.st_gid
        and before.st_size == after.st_size
        and getattr(before, "st_mtime_ns", None) == getattr(after, "st_mtime_ns", None)
        and getattr(before, "st_ctime_ns", None) == getattr(after, "st_ctime_ns", None)
    )


def _add_once(items: list[str], message: str) -> None:
    """Add a coverage limitation once even when many excluded paths match."""
    if message not in items:
        items.append(message)


def _line_number(data: bytes, offset: int) -> int:
    """Return a one-based source line for a byte offset."""
    return data.count(b"\n", 0, offset) + 1


def _is_generated_python_cache(path: str, is_directory: bool) -> bool:
    """Identify Python bytecode and common Python tool-cache directories."""
    name = path.rsplit("/", 1)[-1].casefold()
    if is_directory:
        return name in _PYTHON_CACHE_DIRECTORIES
    return Path(name).suffix in _PYTHON_BYTECODE_SUFFIXES


def _git_hook_config_state(data: bytes) -> tuple[bool, bool, bool]:
    """Return local custom-hook-path, include, and malformed-config flags.

    This intentionally parses only enough Git config syntax to recognize the
    settings that can redirect hook lookup. It never resolves includes or
    expands paths; those cases are surfaced as coverage limitations.
    """
    section: bytes | None = None
    custom_hooks_path = False
    has_include = False
    malformed = False
    section_pattern = re.compile(
        rb'^\[\s*([A-Za-z][A-Za-z0-9.-]*)(?:\s+[^\]]*)?\s*\]$'
    )
    for raw_line in data.splitlines():
        line = raw_line.strip()
        if not line or line.startswith((b"#", b";")):
            continue
        if line.startswith(b"["):
            match = section_pattern.fullmatch(line)
            if match is None:
                malformed = True
                section = None
            else:
                section = match.group(1).lower()
            continue
        if section is None:
            malformed = True
            continue
        key, separator, _value = line.partition(b"=")
        if not separator:
            # Git config permits valueless boolean keys. They cannot name a
            # hooksPath or include target, so they need no special handling.
            continue
        key = key.strip().lower()
        if section == b"core" and key == b"hookspath":
            custom_hooks_path = True
        elif section in {b"include", b"includeif"} and key == b"path":
            has_include = True
    return custom_hooks_path, has_include, malformed


def _finding(
    findings: list[RepositorySecurityFinding],
    seen: set[tuple[str, str, str]],
    rule_id: str,
    severity: str,
    path: str,
    evidence: str,
    explanation: str,
    line_number: int | None = None,
) -> None:
    key = (rule_id, path, evidence)
    if key not in seen:
        seen.add(key)
        findings.append(RepositorySecurityFinding(
            rule_id, severity, path, evidence, explanation, line_number,
        ))


def _analyze_file(
    path: str,
    data: bytes,
    findings: list[RepositorySecurityFinding],
    seen: set[tuple[str, str, str]],
) -> str | None:
    """Add review findings for one bounded file; return parse error if any."""
    private_key_match = _PRIVATE_KEY.search(data)
    if private_key_match:
        _finding(findings, seen, "private-key-material", "high", path,
                 "private-key header found; key material redacted",
                 "A private-key marker appears in this file. Verify whether it is a test fixture or exposed credential and rotate real secrets.",
                 _line_number(data, private_key_match.start()))
    for label, pattern in _TOKEN_PATTERNS:
        token_match = pattern.search(data)
        if token_match:
            _finding(findings, seen, "token-like-value", "high", path,
                     f"{label}; matched value redacted",
                     "A token-shaped value was found. The value is intentionally omitted from the report; verify and rotate it if genuine.",
                     _line_number(data, token_match.start()))

    url_match = _URL_DEPENDENCY.search(data)
    if url_match and Path(path).name.lower() in {
        "requirements.txt", "pyproject.toml", "pipfile", "cargo.toml", "go.mod",
    }:
        _finding(findings, seen, "external-dependency-source", "medium", path,
                 "direct URL, VCS, or editable dependency reference found",
                 "Review the source, pinning, and integrity of dependencies fetched directly from URLs or version-control systems.",
                 _line_number(data, url_match.start()))

    for rule_id, pattern in _RISKY_COMMAND_PATTERNS:
        command_match = pattern.search(data)
        if command_match:
            _finding(findings, seen, rule_id, "high", path,
                     f"static rule matched: {rule_id}",
                     "This command pattern can download or execute code, alter privileges, or make destructive changes. Review the exact context before running the repository.",
                     _line_number(data, command_match.start()))

    filename = Path(path).name.lower()
    if filename == "package.json":
        try:
            manifest = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            _finding(findings, seen, "malformed-package-manifest", "medium", path,
                     "package.json could not be parsed",
                     "The manifest is malformed or not UTF-8; lifecycle configuration could not be reviewed.")
            return f"Could not parse {path}: {type(exc).__name__}"
        if not isinstance(manifest, dict):
            _finding(findings, seen, "malformed-package-manifest", "medium", path,
                     "package.json top-level value is not an object",
                     "The manifest structure is invalid; lifecycle configuration could not be reviewed.")
            return f"Could not review {path}: top-level JSON value is not an object"

        scripts = manifest.get("scripts")
        if "scripts" in manifest and not isinstance(scripts, dict):
            _finding(findings, seen, "malformed-package-manifest", "medium", path,
                     "package.json scripts value is not an object",
                     "Lifecycle configuration has an invalid structure and could not be reviewed.")
            return f"Could not review {path}: scripts value is not an object"
        if isinstance(scripts, dict):
            if any(not isinstance(script, str) for script in scripts.values()):
                _finding(findings, seen, "malformed-package-manifest", "medium", path,
                         "package.json contains a non-string script value",
                         "One or more script values have an invalid structure; lifecycle configuration could not be fully reviewed.")
                return f"Could not review {path}: script values must be strings"
            for key in _LIFECYCLE_KEYS:
                script = scripts.get(key)
                if isinstance(script, str) and script.strip():
                    _finding(findings, seen, "package-lifecycle-script", "medium", path,
                             f"scripts.{key} is configured; command omitted",
                             "Package-manager lifecycle scripts execute during install or build workflows. Inspect this command and its dependencies before proceeding.")

    if filename == "setup.py":
        _finding(findings, seen, "python-install-script", "medium", path,
                 "setup.py is executable Python installation/build logic",
                 "Python packaging may execute setup.py during build or installation. Review it before installing or building the project.")
    elif filename in {"makefile", "dockerfile", "build.rs"}:
        _finding(findings, seen, "build-execution-surface", "low", path,
                 f"{filename} can define code executed by a build workflow",
                 "Presence is not evidence of malicious behavior. Review build commands before invoking the tool.")
    elif path.startswith(".github/workflows/") and filename.endswith((".yml", ".yaml")):
        _finding(findings, seen, "ci-workflow-execution-surface", "low", path,
                 "CI workflow can execute repository-controlled commands",
                 "Review workflow triggers, permissions, and commands before enabling CI for an untrusted repository.")

    return None


def scan_repository_security(
    repository_path: str | Path,
    *,
    include_generated: bool = False,
) -> RepositorySecurityAssessment:
    """Inspect bounded repository files using no-follow POSIX filesystem APIs.

    Regular files are considered, including ignored and untracked files,
    except Python bytecode and common cache directories excluded by default.
    Pass ``include_generated=True`` to include those paths. Oversized,
    unreadable, linked, changing, or over-limit entries make coverage
    incomplete rather than being treated as safe.
    """
    try:
        root = Path(repository_path).expanduser().absolute()
        display_path = str(root)
        root_info = root.lstat()
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            return RepositorySecurityAssessment("error", display_path, errors=[
                "Repository path must be a real directory, not a symlink."
            ])
    except (OSError, TypeError, ValueError) as exc:
        return RepositorySecurityAssessment("error", str(repository_path), errors=[
            f"Could not inspect repository path: {exc}"
        ])

    result = RepositorySecurityAssessment(
        "completed", display_path, include_generated=include_generated,
    )
    if include_generated:
        result.note += " Generated Python bytecode and cache directories were included in static review."
    else:
        result.note += (
            " Generated Python bytecode and common Python cache directories are excluded from static review "
            "by default; the separate ClamAV scan is not affected."
        )
    if not _supports_safe_walk():
        result.status = "unavailable"
        result.errors.append("Safe static review requires POSIX no-follow directory-descriptor support.")
        return result

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(root, flags)
    except OSError as exc:
        result.status = "error"
        result.errors.append(f"Could not safely open repository root: {exc}")
        return result

    started = time.monotonic()
    file_count = 0
    directory_count = 0
    findings: list[RepositorySecurityFinding] = []
    seen: set[tuple[str, str, str]] = set()
    stopped = False

    def walk(directory_fd: int, parents: tuple[str, ...]) -> None:
        nonlocal file_count, directory_count, stopped
        try:
            before_directory = os.fstat(directory_fd)
            # Bound memory before sorting. A malicious repository can contain
            # a directory with far more entries than the file-count limit.
            names: list[str] = []
            directory_limit_reached = False
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if len(names) >= MAX_DIRECTORY_ENTRIES:
                        result.limitations.append(
                            "Static review per-directory entry limit reached."
                        )
                        directory_limit_reached = True
                        break
                    names.append(entry.name)
            names.sort()
        except OSError as exc:
            result.errors.append(f"Could not read directory {'/'.join(parents) or '.'}: {exc}")
            return
        for name in names:
            if stopped:
                return
            if name == ".git":
                if parents:
                    _add_once(
                        result.limitations,
                        "Nested Git metadata and hook configuration were skipped.",
                    )
                continue
            if time.monotonic() - started >= MAX_SCAN_SECONDS:
                result.limitations.append("Static review time limit reached.")
                stopped = True
                return
            relative_parts = (*parents, name)
            relative_path = "/".join(relative_parts)
            try:
                entry_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                result.errors.append(f"Could not inspect {relative_path}: {exc}")
                continue
            if stat.S_ISDIR(entry_stat.st_mode):
                if not include_generated and _is_generated_python_cache(relative_path, is_directory=True):
                    result.generated_paths_excluded += 1
                    _add_once(
                        result.limitations,
                        "Generated Python bytecode/cache paths were excluded from static review; use --include-generated to inspect them.",
                    )
                    continue
                directory_count += 1
                if directory_count > MAX_DIRECTORIES:
                    result.limitations.append("Static review directory limit reached.")
                    stopped = True
                    return
                if len(relative_parts) > MAX_DIRECTORY_DEPTH:
                    result.limitations.append("Static review directory-depth limit reached.")
                    continue
                try:
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                    child_stat = os.fstat(child_fd)
                    if (child_stat.st_dev, child_stat.st_ino) != (entry_stat.st_dev, entry_stat.st_ino):
                        os.close(child_fd)
                        result.limitations.append("A directory changed during static review.")
                        continue
                except OSError as exc:
                    result.errors.append(f"Could not safely open directory {relative_path}: {exc}")
                    continue
                try:
                    walk(child_fd, relative_parts)
                finally:
                    os.close(child_fd)
                continue

            file_count += 1
            if file_count > MAX_FILES:
                result.limitations.append("Static review file-count limit reached.")
                stopped = True
                return
            if not stat.S_ISREG(entry_stat.st_mode):
                result.limitations.append("Symlinks and non-regular entries were skipped.")
                continue
            if (
                parents == (".git", "hooks")
                and name in {f"{hook}.sample" for hook in _GIT_HOOK_NAMES}
            ):
                continue
            if not include_generated and _is_generated_python_cache(relative_path, is_directory=False):
                result.generated_paths_excluded += 1
                _add_once(
                    result.limitations,
                    "Generated Python bytecode/cache paths were excluded from static review; use --include-generated to inspect them.",
                )
                continue
            if entry_stat.st_size < 0 or entry_stat.st_size > MAX_FILE_BYTES:
                result.limitations.append("One or more files exceeded the static review per-file size limit.")
                continue
            if result.bytes_inspected + entry_stat.st_size > MAX_TOTAL_BYTES:
                result.limitations.append("Static review total-byte limit reached.")
                stopped = True
                return
            file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
            try:
                file_fd = os.open(name, file_flags, dir_fd=directory_fd)
            except OSError as exc:
                result.errors.append(f"Could not safely open {relative_path}: {exc}")
                continue
            try:
                opened = os.fstat(file_fd)
                if not stat.S_ISREG(opened.st_mode) or not _same_file_metadata(entry_stat, opened):
                    result.limitations.append("A file changed or was replaced before static review.")
                    continue
                chunks: list[bytes] = []
                read_size = 0
                while True:
                    if time.monotonic() - started >= MAX_SCAN_SECONDS:
                        result.limitations.append("Static review time limit reached while reading a file.")
                        stopped = True
                        break
                    chunk = os.read(file_fd, min(READ_CHUNK_BYTES, MAX_FILE_BYTES - read_size + 1))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    read_size += len(chunk)
                    if read_size > MAX_FILE_BYTES or result.bytes_inspected + read_size > MAX_TOTAL_BYTES:
                        result.limitations.append("Static review byte limit reached while reading a file.")
                        stopped = True
                        break
                after = os.fstat(file_fd)
                current_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                stable = (
                    _same_file_metadata(opened, after)
                    and after.st_size == read_size
                    and (current_path.st_dev, current_path.st_ino) == (opened.st_dev, opened.st_ino)
                )
                if not stable:
                    result.limitations.append("A file changed during static review and its content was discarded.")
                    continue
                data = b"".join(chunks)
                result.files_inspected += 1
                result.bytes_inspected += len(data)
                parse_error = _analyze_file(relative_path, data, findings, seen)
                if parse_error:
                    result.errors.append(parse_error)
                if (
                    parents == (".git", "hooks")
                    and name in _GIT_HOOK_NAMES
                    and bool(opened.st_mode & 0o111)
                ):
                    _finding(
                        findings, seen, "active-git-hook", "medium", relative_path,
                        "Executable file uses a standard Git hook name",
                        "Git may execute this hook during matching Git operations. Review it before using Git with this repository; the scanner did not execute it.",
                    )
            except OSError as exc:
                result.errors.append(f"Could not read {relative_path}: {exc}")
            finally:
                os.close(file_fd)

        try:
            after_directory = os.fstat(directory_fd)
            if any(
                getattr(before_directory, field_name, None) != getattr(after_directory, field_name, None)
                for field_name in ("st_mtime_ns", "st_ctime_ns")
            ):
                result.limitations.append(f"Directory changed during static review: {'/'.join(parents) or '.'}")
        except OSError as exc:
            result.errors.append(f"Could not verify directory stability: {exc}")
        if directory_limit_reached:
            stopped = True

    try:
        opened_root = os.fstat(root_fd)
        if (opened_root.st_dev, opened_root.st_ino) != (root_info.st_dev, root_info.st_ino):
            result.status = "error"
            result.errors.append("Repository root changed before static review began.")
            return result

        # Review the default local hook directory without walking Git object
        # storage, refs, or index data. Alternate hook locations are reported
        # as a coverage limitation rather than followed outside the repository.
        git_info = None
        try:
            git_info = os.stat(".git", dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            result.limitations.append(f"Could not inspect the repository Git metadata entry: {exc}")
        if git_info is not None:
            if not stat.S_ISDIR(git_info.st_mode):
                result.limitations.append(
                    "The .git entry is not a real directory; worktree or linked Git hook configuration was not inspected."
                )
            else:
                git_fd = None
                try:
                    git_fd = os.open(".git", flags, dir_fd=root_fd)
                    opened_git = os.fstat(git_fd)
                    if (opened_git.st_dev, opened_git.st_ino) != (git_info.st_dev, git_info.st_ino):
                        result.limitations.append("Git metadata changed before its hooks could be reviewed.")
                    else:
                        config_data: bytes | None = None
                        config_missing = False
                        try:
                            config_info = os.stat("config", dir_fd=git_fd, follow_symlinks=False)
                            if not stat.S_ISREG(config_info.st_mode) or config_info.st_size > MAX_GIT_CONFIG_BYTES:
                                result.limitations.append("Git configuration is not a bounded regular file; hook configuration could not be reviewed.")
                            else:
                                config_fd = os.open(
                                    "config", os.O_RDONLY | os.O_NOFOLLOW
                                    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
                                    dir_fd=git_fd,
                                )
                                try:
                                    opened_config = os.fstat(config_fd)
                                    chunks: list[bytes] = []
                                    size = 0
                                    while size <= MAX_GIT_CONFIG_BYTES:
                                        chunk = os.read(config_fd, min(READ_CHUNK_BYTES, MAX_GIT_CONFIG_BYTES + 1 - size))
                                        if not chunk:
                                            break
                                        chunks.append(chunk)
                                        size += len(chunk)
                                    after_config = os.fstat(config_fd)
                                    current_config = os.stat("config", dir_fd=git_fd, follow_symlinks=False)
                                    if (
                                        not stat.S_ISREG(opened_config.st_mode)
                                        or not _same_file_metadata(config_info, opened_config)
                                        or size > MAX_GIT_CONFIG_BYTES
                                        or not _same_file_metadata(opened_config, after_config)
                                        or not _same_file_metadata(opened_config, current_config)
                                    ):
                                        result.limitations.append("Git configuration changed or exceeded its review limit.")
                                    else:
                                        config_data = b"".join(chunks)
                                finally:
                                    os.close(config_fd)
                        except FileNotFoundError:
                            config_missing = True
                        except OSError as exc:
                            result.limitations.append(f"Could not safely review Git configuration: {exc}")

                        if config_data is not None:
                            custom_hooks_path, has_external_config, malformed_config = (
                                _git_hook_config_state(config_data)
                            )
                            if custom_hooks_path:
                                result.limitations.append("A custom core.hooksPath is configured; that alternate hook location was not inspected.")
                            if has_external_config:
                                result.limitations.append("Git configuration includes are not resolved and may change the active hook path.")
                            if malformed_config:
                                result.limitations.append("Git configuration contains malformed or unsupported syntax; effective hook settings could not be fully reviewed.")
                        if config_missing:
                            result.limitations.append("The local Git configuration is missing; effective hook settings could not be fully reviewed.")

                        # System/global configuration and Git configuration
                        # environment overrides can also redirect hook lookup.
                        # Do not invoke Git or resolve untrusted include paths.
                        _add_once(
                            result.limitations,
                            "System, global, and environment Git configuration is not resolved; alternate hook locations may be active.",
                        )

                        hooks_info = None
                        try:
                            hooks_info = os.stat("hooks", dir_fd=git_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        if hooks_info is not None:
                            if not stat.S_ISDIR(hooks_info.st_mode):
                                result.limitations.append("The default Git hooks entry is not a real directory and was not followed.")
                            else:
                                hooks_fd = os.open("hooks", flags, dir_fd=git_fd)
                                try:
                                    opened_hooks = os.fstat(hooks_fd)
                                    if (opened_hooks.st_dev, opened_hooks.st_ino) != (hooks_info.st_dev, hooks_info.st_ino):
                                        result.limitations.append("The default Git hooks directory changed before review.")
                                    else:
                                        walk(hooks_fd, (".git", "hooks"))
                                finally:
                                    os.close(hooks_fd)
                except OSError as exc:
                    result.limitations.append(f"Could not safely inspect the default Git hooks: {exc}")
                finally:
                    if git_fd is not None:
                        os.close(git_fd)
        walk(root_fd, ())
    finally:
        os.close(root_fd)

    result.findings = sorted(findings, key=lambda item: (item.path, item.rule_id, item.evidence))
    result.errors = list(dict.fromkeys(result.errors))
    result.limitations = list(dict.fromkeys(result.limitations))
    if result.errors or result.limitations or result.generated_paths_excluded:
        result.status = "incomplete"
    elif result.findings:
        result.status = "requires_review"
        result.coverage_complete = True
    else:
        result.status = "completed"
        result.coverage_complete = True
    return result
