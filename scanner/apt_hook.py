"""Fail-closed parser and runner for APT's Pre-Install-Pkgs v3 hook."""

from __future__ import annotations

import os
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable, TextIO

from scanner.malware_scanner import MAX_PACKAGE_BYTES, MalwareAssessment, scan_deb

MAX_PROTOCOL_BYTES = 8 * 1024 * 1024
MAX_PROTOCOL_LINE_BYTES = 64 * 1024
MAX_ACTIONS = 10_000
_PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")
_CONFIG_KEY = re.compile(r"^(?:[A-Za-z0-9_.:+/-]|%[0-9A-Fa-f]{2})+$")
_MULTIARCH = {"same", "foreign", "allowed", "none", "no"}
_SPECIAL_ACTIONS = {"**CONFIGURE**", "**REMOVE**"}
_ASSESSMENT_STATUSES = {"detected", "no_detection", "unavailable", "incomplete", "error"}
_TRUSTED_SCANNER_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class AptProtocolError(ValueError):
    """Raised when APT hook input is malformed or incomplete."""


@dataclass(frozen=True)
class AptPackageAction:
    """One validated APT package action and its optional archive path."""

    package_name: str
    action: str
    archive_path: str | None
    target_version: str | None = None
    target_architecture: str | None = None
    target_multiarch: str | None = None


@dataclass(frozen=True)
class AptTransaction:
    """Validated protocol configuration and package action records."""

    configuration: tuple[tuple[str, str], ...]
    actions: tuple[AptPackageAction, ...]


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, result: os.stat_result) -> "_FileIdentity":
        return cls(
            result.st_dev, result.st_ino, result.st_size,
            getattr(result, "st_mtime_ns", int(result.st_mtime * 1e9)),
            getattr(result, "st_ctime_ns", int(result.st_ctime * 1e9)),
        )


def _line_text(raw: bytes) -> str:
    """Decode protocol bytes without losing valid filesystem path bytes."""
    return raw.decode("utf-8", errors="surrogateescape")


def _has_control(value: str) -> bool:
    return any(unicodedata.category(character) == "Cc" for character in value)


def _valid_percent_encoding(value: str) -> bool:
    index = 0
    while index < len(value):
        if value[index] == "%":
            if index + 2 >= len(value) or not re.fullmatch(
                r"[0-9A-Fa-f]{2}", value[index + 1:index + 3],
            ):
                return False
            index += 3
        else:
            index += 1
    return True


def _validate_package_action(line: str) -> AptPackageAction:
    fields = line.split(maxsplit=8)
    if len(fields) != 9:
        raise AptProtocolError("package action record must contain nine fields")
    name, old_version, old_arch, old_multiarch, direction, new_version, new_arch, new_multiarch, action = fields
    if not _PACKAGE_NAME.fullmatch(name):
        raise AptProtocolError("package action has an invalid package name")
    if direction not in {"<", ">", "="}:
        raise AptProtocolError("package action has an invalid version direction")
    for version in (old_version, new_version):
        if not version or _has_control(version):
            raise AptProtocolError("package action has an invalid version field")
    for architecture in (old_arch, new_arch):
        if not architecture or _has_control(architecture):
            raise AptProtocolError("package action has an invalid architecture field")
        if architecture != "-" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", architecture):
            raise AptProtocolError("package action has a malformed architecture")
    if old_multiarch not in _MULTIARCH or new_multiarch not in _MULTIARCH:
        raise AptProtocolError("package action has an unsupported Multi-Arch value")
    if (old_version == "-") != (old_arch == "-"):
        raise AptProtocolError("missing old version and architecture fields disagree")
    if (new_version == "-") != (new_arch == "-"):
        raise AptProtocolError("missing new version and architecture fields disagree")
    if old_version == "-" and new_version == "-":
        raise AptProtocolError("package action has neither an old nor a new version")
    if old_version == "-" and direction != "<":
        raise AptProtocolError("new package action has an inconsistent version direction")
    if new_version == "-" and direction != ">":
        raise AptProtocolError("removed package action has an inconsistent version direction")
    if old_version == "-" and old_multiarch not in {"none", "no"}:
        raise AptProtocolError("missing old version has an inconsistent Multi-Arch value")
    if new_version == "-" and new_multiarch not in {"none", "no"}:
        raise AptProtocolError("missing new version has an inconsistent Multi-Arch value")
    if not action or _has_control(action):
        raise AptProtocolError("package action has an invalid action field")
    if action in _SPECIAL_ACTIONS:
        if action == "**REMOVE**" and new_version != "-":
            raise AptProtocolError("remove action unexpectedly contains a new package version")
        if action == "**CONFIGURE**" and new_version == "-":
            raise AptProtocolError("configure action is missing its target package version")
        return AptPackageAction(
            name,
            action,
            None,
            None if new_version == "-" else new_version,
            None if new_arch == "-" else new_arch,
            None if new_version == "-" else new_multiarch,
        )
    if action.startswith("**") or not action.startswith("/"):
        raise AptProtocolError("package action is neither a known operation nor an absolute archive path")
    if new_version == "-":
        raise AptProtocolError("archive action is missing its target package version")
    archive = PurePosixPath(action)
    if ".." in archive.parts or archive.suffix != ".deb":
        raise AptProtocolError("archive path is unsafe or is not a .deb file")
    return AptPackageAction(
        name, action, action, new_version, new_arch, new_multiarch,
    )


def parse_pre_install_v3(data: bytes | str) -> AptTransaction:
    """Parse and validate the complete APT pre-install protocol v3 stream."""
    if isinstance(data, bytes):
        if len(data) > MAX_PROTOCOL_BYTES:
            raise AptProtocolError("APT protocol input exceeds the size limit")
        raw_lines = data.split(b"\n")
        if any(len(line) > MAX_PROTOCOL_LINE_BYTES for line in raw_lines):
            raise AptProtocolError("APT protocol contains an oversized record")
        if b"\r" in data or b"\x00" in data:
            raise AptProtocolError("APT protocol contains an invalid control byte")
        text = _line_text(data)
    else:
        encoded = data.encode("utf-8", errors="surrogateescape")
        if len(encoded) > MAX_PROTOCOL_BYTES:
            raise AptProtocolError("APT protocol input exceeds the size limit")
        if any(len(line.encode("utf-8", errors="surrogateescape")) > MAX_PROTOCOL_LINE_BYTES
               for line in data.split("\n")):
            raise AptProtocolError("APT protocol contains an oversized record")
        if "\r" in data or "\x00" in data:
            raise AptProtocolError("APT protocol contains an invalid control character")
        text = data

    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or lines[0] != "VERSION 3":
        raise AptProtocolError("APT hook requires the exact VERSION 3 header")
    try:
        separator = lines.index("", 1)
    except ValueError as exc:
        raise AptProtocolError("APT configuration section is missing its blank-line terminator") from exc

    configuration: list[tuple[str, str]] = []
    for line in lines[1:separator]:
        key, marker, value = line.partition("=")
        if marker != "=" or not _CONFIG_KEY.fullmatch(key):
            raise AptProtocolError("APT configuration record is malformed")
        if not _valid_percent_encoding(key) or not _valid_percent_encoding(value):
            raise AptProtocolError("APT configuration record has invalid percent encoding")
        if _has_control(value):
            raise AptProtocolError("APT configuration record contains a control character")
        configuration.append((key, value))
    native_architectures = [
        value for key, value in configuration if key == "APT::Architecture"
    ]
    if len(native_architectures) != 1 or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9-]*", native_architectures[0],
    ):
        raise AptProtocolError("APT configuration must contain one valid native architecture")

    action_lines = lines[separator + 1:]
    if not action_lines:
        raise AptProtocolError("APT transaction contains no package action records")
    if len(action_lines) > MAX_ACTIONS:
        raise AptProtocolError("APT transaction exceeds the package action limit")
    actions = tuple(_validate_package_action(line) for line in action_lines)

    archive_paths = [item.archive_path for item in actions if item.archive_path is not None]
    if len(archive_paths) != len(set(archive_paths)):
        raise AptProtocolError("APT transaction contains a duplicate archive path")
    return AptTransaction(tuple(configuration), actions)


def _read_protocol(stream: BinaryIO) -> bytes:
    """Read a bounded protocol stream through EOF, rejecting truncation by size."""
    data = stream.read(MAX_PROTOCOL_BYTES + 1)
    if len(data) > MAX_PROTOCOL_BYTES:
        raise AptProtocolError("APT protocol input exceeds the size limit")
    return data


def _safe_archive_path(raw_path: str) -> tuple[Path, _FileIdentity]:
    """Open and validate an archive without following symlinks or traversals."""
    candidate = Path(raw_path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise OSError("APT archive path must be absolute and cannot contain parent traversal")
    if candidate.suffix != ".deb":
        raise OSError("APT archive path does not have a .deb suffix")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise OSError(f"APT archive does not exist or cannot be resolved: {exc}") from exc
    if resolved != candidate:
        raise OSError("APT archive path or one of its parent directories is a symlink")

    try:
        path_info = candidate.lstat()
    except OSError as exc:
        raise OSError(f"APT archive cannot be inspected: {exc}") from exc
    if stat.S_ISLNK(path_info.st_mode):
        raise OSError("APT archive path is a symlink")
    if not stat.S_ISREG(path_info.st_mode):
        raise OSError("APT archive is not a regular file")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise OSError(f"APT archive cannot be opened safely: {exc}") from exc
    try:
        result = os.fstat(descriptor)
        if not stat.S_ISREG(result.st_mode):
            raise OSError("APT archive is not a regular file")
        if result.st_size < 0 or result.st_size > MAX_PACKAGE_BYTES:
            raise OSError("APT archive exceeds the package size limit")
        identity = _FileIdentity.from_stat(result)
        if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
            _require_root_protected_path(candidate)
        return resolved, identity
    finally:
        os.close(descriptor)


def _require_root_protected_path(path: Path) -> None:
    """Reject root-run APT inputs that an unprivileged user can replace."""
    chain = [*reversed(path.parents), path]
    for item in chain:
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise OSError("APT archive path contains a symbolic link")
        if info.st_uid != 0:
            raise OSError("APT archive path is not owned by root and could be replaced")
        writable_by_others = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        sticky_directory = stat.S_ISDIR(info.st_mode) and bool(info.st_mode & stat.S_ISVTX)
        if writable_by_others and not sticky_directory:
            raise OSError("APT archive path is writable by other users and could be replaced")
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise OSError("APT archive parent component is not a directory")


def _identity_at_path(path: Path) -> _FileIdentity:
    result = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(result.st_mode):
        raise OSError("APT archive changed to a non-regular file during scanning")
    return _FileIdentity.from_stat(result)


def _terminal_safe(value: object) -> str:
    """Escape terminal controls in package metadata and scanner messages."""
    text = str(value)
    safe: list[str] = []
    for character in text:
        if unicodedata.category(character).startswith("C"):
            safe.extend(f"\\u{ord(character):04x}")
        else:
            safe.append(character)
    return "".join(safe)


def _render_assessment(package_path: str, result: dict[str, object]) -> str:
    lines = [f"Archive: {_terminal_safe(package_path)}"]
    package = result.get("package")
    if isinstance(package, dict):
        name = _terminal_safe(package.get("name", "unknown"))
        version = _terminal_safe(package.get("version", "unknown"))
        lines.append(f"Package: {name} {version}")
    lines.extend((
        f"Status: {_terminal_safe(result.get('status', 'error'))}",
        f"Scanner: {_terminal_safe(result.get('scanner', 'unknown'))}",
    ))
    detections = result.get("detections", [])
    if isinstance(detections, list):
        for finding in detections:
            if isinstance(finding, dict):
                lines.append(
                    f"Detection: {_terminal_safe(finding.get('name', 'unknown'))} "
                    f"at {_terminal_safe(finding.get('path', 'unknown'))}"
                )
    error = result.get("error")
    if error:
        lines.append(f"Error: {_terminal_safe(error)}")
    limitations = result.get("limitations", [])
    if isinstance(limitations, list):
        lines.extend(f"Coverage limitation: {_terminal_safe(item)}" for item in limitations)
    return "\n".join(lines)


def _validated_assessment_dict(assessment: object) -> dict[str, object]:
    """Reject malformed scanner results before they can affect APT's decision."""
    serializer = getattr(assessment, "to_dict", None)
    if not callable(serializer):
        raise ValueError("scanner returned an assessment without a serializer")
    result = serializer()
    if not isinstance(result, dict):
        raise ValueError("scanner returned an assessment that is not an object")

    status = result.get("status")
    if status not in _ASSESSMENT_STATUSES:
        raise ValueError("scanner returned an unknown assessment status")
    scanner_name = result.get("scanner")
    if not isinstance(scanner_name, str) or not scanner_name.strip():
        raise ValueError("scanner returned an invalid scanner name")
    package = result.get("package")
    if status in {"detected", "no_detection"} and (
        not isinstance(package, dict)
        or any(not isinstance(package.get(key), str) or not package[key].strip()
               for key in ("name", "version"))
    ):
        raise ValueError("scanner returned a result without package identity")
    coverage_complete = result.get("coverage_complete")
    if not isinstance(coverage_complete, bool):
        raise ValueError("scanner returned an invalid coverage flag")
    detections = result.get("detections")
    if not isinstance(detections, list):
        raise ValueError("scanner returned an invalid detections list")
    for detection in detections:
        if not isinstance(detection, dict):
            raise ValueError("scanner returned a malformed detection")
        if any(
            not isinstance(detection.get(key), str) or not detection[key].strip()
            for key in ("name", "path")
        ):
            raise ValueError("scanner returned a detection without a name or path")

    error = result.get("error")
    if error is not None and not isinstance(error, str):
        raise ValueError("scanner returned a malformed error detail")
    limitations = result.get("limitations")
    if not isinstance(limitations, list) or any(
        not isinstance(item, str) for item in limitations
    ):
        raise ValueError("scanner returned malformed coverage limitations")

    if status == "no_detection":
        if not coverage_complete or detections or error or limitations:
            raise ValueError("scanner returned an inconsistent no_detection result")
    elif status == "detected":
        if not detections:
            raise ValueError("scanner returned detected status without detection evidence")
        if coverage_complete and (error or limitations):
            # Keep valid detections visible, but do not let contradictory
            # complete-coverage metadata lead to an approval prompt or allow.
            result["coverage_complete"] = False
    elif status in {"unavailable", "incomplete", "error"} and coverage_complete:
        raise ValueError(f"scanner returned {status} with complete coverage")
    return result


def _drop_to_apt_sandbox_user() -> None:
    """Irreversibly drop hook credentials before parsing untrusted archives."""
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    import pwd

    account = pwd.getpwnam("_apt")
    # setgid/setuid rather than only changing effective IDs also discards the
    # saved root IDs inherited by subprocesses such as dpkg-deb and clamscan.
    os.setgroups([account.pw_gid])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    if hasattr(os, "getresuid") and os.getresuid() != (
        account.pw_uid, account.pw_uid, account.pw_uid,
    ):
        raise OSError("could not permanently drop all root user IDs for archive scanning")
    if hasattr(os, "getresgid") and os.getresgid() != (
        account.pw_gid, account.pw_gid, account.pw_gid,
    ):
        raise OSError("could not permanently drop all root group IDs for archive scanning")


def _scan_with_trusted_path(
    scanner: Callable[[Path], MalwareAssessment], path: Path,
) -> MalwareAssessment:
    """Avoid resolving dpkg-deb or clamscan from an inherited untrusted PATH."""
    original_path = os.environ.get("PATH")
    os.environ["PATH"] = _TRUSTED_SCANNER_PATH
    try:
        return scanner(path)
    finally:
        if original_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = original_path


def _prompt_for_detection(terminal: TextIO | None = None) -> bool:
    """Require exact interactive approval for a complete scan with detections."""
    opened = None
    try:
        if terminal is None:
            opened = open("/dev/tty", "r+", encoding="utf-8", errors="replace")
            terminal = opened
        terminal.write(
            "Malware detection(s) were reported. Type exactly INSTALL to continue "
            "anyway; anything else aborts: "
        )
        terminal.flush()
        answer = terminal.readline()
        return answer.removesuffix("\n").removesuffix("\r") == "INSTALL"
    except (OSError, EOFError, KeyboardInterrupt):
        return False
    finally:
        if opened is not None:
            opened.close()


def run_apt_preinstall_hook(
    *,
    stream: BinaryIO | None = None,
    terminal: TextIO | None = None,
    scanner: Callable[[Path], MalwareAssessment] = scan_deb,
    output: TextIO | None = None,
) -> int:
    """Scan every archive in one APT v3 transaction and fail closed on gaps."""
    output_stream = output or sys.stderr
    protocol_stream = stream or getattr(sys.stdin, "buffer", None)
    if protocol_stream is None:
        print("APT hook protocol input is unavailable; transaction blocked.", file=output_stream)
        return 1
    info_fd = os.environ.get("APT_HOOK_INFO_FD")
    if info_fd is not None and info_fd != "0":
        print("Unexpected APT_HOOK_INFO_FD; transaction blocked.", file=output_stream)
        return 1

    try:
        transaction = parse_pre_install_v3(_read_protocol(protocol_stream))
    except (AptProtocolError, OSError) as exc:
        print(f"Invalid or incomplete APT protocol; transaction blocked: {_terminal_safe(exc)}", file=output_stream)
        return 1
    print("APT Pre-Install-Pkgs protocol version 3 accepted.", file=output_stream)

    archive_actions = [action for action in transaction.actions if action.archive_path is not None]
    if not archive_actions:
        print("APT transaction contains no package archives; no malware scan was needed.", file=output_stream)
        return 0

    # Validate every path while root-protection checks are still available.
    # Only after this pass does a root-run hook permanently become _apt.
    pending: list[tuple[AptPackageAction, Path | None, _FileIdentity | None, str | None]] = []
    identities: set[str] = set()
    for action in archive_actions:
        raw_path = action.archive_path
        assert raw_path is not None
        try:
            resolved, identity = _safe_archive_path(raw_path)
            resolved_name = str(resolved)
            if resolved_name in identities:
                raise OSError("duplicate archive resolves to an already-scanned file")
            identities.add(resolved_name)
            pending.append((action, resolved, identity, None))
        except (OSError, RuntimeError, KeyError, PermissionError, ValueError) as exc:
            pending.append((action, None, None, str(exc)))
        except Exception as exc:
            pending.append((
                action, None, None,
                f"Archive validation raised {type(exc).__name__}: {exc}",
            ))

    if any(path is not None for _, path, _, _ in pending):
        try:
            _drop_to_apt_sandbox_user()
        except Exception as exc:
            detail = f"Could not drop privileges for package scanning: {type(exc).__name__}: {exc}"
            pending = [
                (action, None, None, error or detail)
                for action, path, identity, error in pending
            ]

    results: list[tuple[str, dict[str, object], bool]] = []
    for action, resolved, identity, validation_error in pending:
        raw_path = action.archive_path
        assert raw_path is not None
        if validation_error is not None:
            results.append((raw_path, {
                "status": "error", "scanner": "LinuxSecMonitor APT pre-install hook",
                "package": None, "detections": [], "error": validation_error,
                "limitations": [], "coverage_complete": False,
            }, False))
            continue
        assert resolved is not None and identity is not None
        try:
            if _identity_at_path(resolved) != identity:
                raise OSError("APT archive changed after path validation")
            assessment = _scan_with_trusted_path(scanner, resolved)
            unchanged = _identity_at_path(resolved) == identity
            result = _validated_assessment_dict(assessment)
            if result.get("status") in {"detected", "no_detection"}:
                package = result["package"]
                assert isinstance(package, dict)
                actual_multiarch = package.get("multi_arch", "no")
                if actual_multiarch == "none":
                    actual_multiarch = "no"
                expected_multiarch = action.target_multiarch
                if expected_multiarch == "none":
                    expected_multiarch = "no"
                if (
                    package.get("name") != action.package_name
                    or package.get("version") != action.target_version
                    or package.get("architecture") != action.target_architecture
                    or actual_multiarch != expected_multiarch
                ):
                    expected = (
                        f"{action.package_name} {action.target_version} "
                        f"{action.target_architecture} {expected_multiarch}"
                    )
                    actual = (
                        f"{package.get('name')} {package.get('version')} "
                        f"{package.get('architecture')} {actual_multiarch}"
                    )
                    mismatch_error = (
                        "Scanned archive identity does not match APT's transaction "
                        f"record (expected {expected}; found {actual})."
                    )
                    existing_error = result.get("error")
                    result["error"] = (
                        f"{existing_error} {mismatch_error}"
                        if isinstance(existing_error, str) and existing_error.strip()
                        else mismatch_error
                    )
                    result["limitations"].append(
                        "The scanned package could not be confirmed as the package APT plans to install."
                    )
                    result["coverage_complete"] = False
                    if result["status"] == "no_detection":
                        result["status"] = "error"
            if not unchanged:
                result["error"] = "APT archive changed while it was being scanned."
                result["coverage_complete"] = False
                result["status"] = "error"
            results.append((raw_path, result, unchanged))
        except (OSError, RuntimeError, KeyError, PermissionError, ValueError) as exc:
            results.append((raw_path, {
                "status": "error", "scanner": "LinuxSecMonitor APT pre-install hook",
                "package": None, "detections": [], "error": str(exc),
                "limitations": [], "coverage_complete": False,
            }, False))
        except Exception as exc:
            # Provider exceptions are not allowed to turn a transaction clean.
            results.append((raw_path, {
                "status": "error", "scanner": "LinuxSecMonitor APT pre-install hook",
                "package": None, "detections": [],
                "error": f"Scanner raised {type(exc).__name__}: {exc}",
                "limitations": [], "coverage_complete": False,
            }, False))

    for raw_path, result, _ in results:
        print(_render_assessment(raw_path, result), file=output_stream)

    complete_no_detection = all(
        result.get("status") == "no_detection"
        and result.get("coverage_complete") is True
        and unchanged
        for _, result, unchanged in results
    )
    if complete_no_detection:
        print(
            "All transaction archives completed with no known detection. "
            "This does not guarantee that the packages are safe.",
            file=output_stream,
        )
        return 0

    if any(
        not unchanged
        or result.get("status") not in {"detected", "no_detection"}
        or result.get("coverage_complete") is not True
        for _, result, unchanged in results
    ):
        print(
            "APT transaction blocked: at least one archive had incomplete coverage, "
            "an error, or an unavailable scanner.",
            file=output_stream,
        )
        return 1

    print(
        "Malware detection found. Approval will allow APT to continue despite the "
        "reported finding(s).",
        file=output_stream,
    )
    if not _prompt_for_detection(terminal):
        print("APT transaction blocked: explicit terminal approval was not received.", file=output_stream)
        return 1
    print("Explicit INSTALL approval received; APT may continue.", file=output_stream)
    return 0
