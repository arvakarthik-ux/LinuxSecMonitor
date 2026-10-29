"""Opt-in, ownership-aware lifecycle for the LinuxSecMonitor APT hook.

All filesystem paths are injectable so lifecycle behavior can be tested under
temporary roots. The CLI uses system paths only after an explicit command and
requires effective root privileges.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

HOOK_NAME = "00linuxsecmonitor"
STATE_NAME = "apt-integration.json"
APT_CONFIG = "/usr/bin/apt-config"


class LifecycleError(RuntimeError):
    """A safe lifecycle operation could not be completed."""


def hook_contents(python: str) -> bytes:
    """Return an APT config file invoking the installed module by argv."""
    executable = Path(python)
    if not re.fullmatch(r"/[A-Za-z0-9._+/-]+", str(executable)):
        raise LifecycleError("Python executable path must be an absolute safe path")
    command = f'"{executable}" -m main --apt-preinstall-hook'
    return (
        "// Managed by LinuxSecMonitor; remove with --uninstall-apt-hook.\n"
        f'DPkg::Pre-Install-Pkgs {{ "{command}"; }};\n'
        f'DPkg::Tools::Options::{executable}::Version "3";\n'
    ).encode("utf-8")


def validate_trusted_runtime(python: str, module_paths: tuple[Path, ...]) -> None:
    """Reject interpreters/modules a non-root user could replace after setup."""
    candidates = [(Path(python), True), *((item, False) for item in module_paths)]
    for candidate, executable in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LifecycleError(f"Cannot resolve trusted runtime path {candidate}") from exc
        if not resolved.is_file():
            raise LifecycleError(f"Trusted runtime path is not a regular file: {resolved}")
        if executable and not os.access(resolved, os.X_OK):
            raise LifecycleError(f"Python interpreter is not executable: {resolved}")
        for component in (resolved, *resolved.parents):
            info = component.stat()
            if info.st_uid != 0:
                raise LifecycleError(f"Privileged hook path is not root-owned: {component}")
            if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                # Root-controlled sticky directories such as /tmp still allow
                # replacement of names and are not acceptable code parents.
                raise LifecycleError(f"Privileged hook path is writable by others: {component}")


def _ensure_directory(path: Path, mode: int = 0o755) -> None:
    if path.exists():
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise LifecycleError(f"Expected a real directory at {path}")
        return
    path.mkdir(parents=True, mode=mode)


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Publish a new file atomically without replacing a racing file."""
    _ensure_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    published_identity: tuple[int, int] | None = None
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        # A hard-link publication is atomic and fails with EEXIST, preserving
        # any file created after the caller's earlier conflict check.
        os.link(temp_path, path, follow_symlinks=False)
        published = temp_path.stat(follow_symlinks=False)
        published_identity = (published.st_dev, published.st_ino)
        temp_path.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if published_identity is not None:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == published_identity:
                    path.unlink()
            except OSError:
                pass
        try:
            os.close(descriptor)
        except OSError:
            pass
        temp_path.unlink(missing_ok=True)
        raise


def _validate_apt_config(content: bytes, directory: Path, python: str) -> None:
    """Ask APT's own parser to validate a candidate before activating it."""
    if not Path(APT_CONFIG).is_file() or not os.access(APT_CONFIG, os.X_OK):
        raise LifecycleError("apt-config is unavailable; refusing to enable an unvalidated hook")
    descriptor, temporary = tempfile.mkstemp(prefix=".linuxsecmonitor-check-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as candidate:
            candidate.write(content)
            candidate.flush()
            os.fsync(candidate.fileno())
        try:
            completed = subprocess.run(
                [APT_CONFIG, "-c", temporary, "dump"],
                capture_output=True, text=True, timeout=5, check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise LifecycleError("apt-config could not validate the candidate hook") from exc
        if completed.returncode != 0:
            raise LifecycleError("APT rejected the candidate hook configuration")
        output = completed.stdout
        version_option = f'DPkg::Tools::Options::{python}::Version "3";'
        if version_option not in output or "--apt-preinstall-hook" not in output:
            raise LifecycleError("APT did not preserve the expected protocol-v3 hook settings")
    finally:
        Path(temporary).unlink(missing_ok=True)


def validate_effective_hook_order(
    python: str, *, environment: dict[str, str] | None = None,
) -> None:
    """Require the managed hook to be the first effective pre-install command."""
    env = environment or {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    env = {key: value for key, value in env.items() if key != "APT_CONFIG"}
    if environment is not None and "APT_CONFIG" in environment:
        env["APT_CONFIG"] = environment["APT_CONFIG"]
    try:
        completed = subprocess.run(
            [APT_CONFIG, "dump"], capture_output=True, text=True,
            timeout=5, check=False, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LifecycleError("apt-config could not inspect effective hook order") from exc
    if completed.returncode != 0:
        raise LifecycleError("apt-config rejected the effective APT configuration")
    hook_lines = [
        line for line in completed.stdout.splitlines()
        if line.startswith("DPkg::Pre-Install-Pkgs:: ") and line.count('"') >= 2
    ]
    expected_command = f"{python} -m main --apt-preinstall-hook"
    if not hook_lines or expected_command not in hook_lines[0]:
        raise LifecycleError(
            "LinuxSecMonitor is not the first effective Pre-Install-Pkgs hook"
        )
    version_option = f'DPkg::Tools::Options::{python}::Version "3";'
    if version_option not in completed.stdout:
        raise LifecycleError("Effective APT configuration does not request protocol version 3")


def _read_state(state_path: Path) -> dict[str, object] | None:
    try:
        info = state_path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise LifecycleError("LinuxSecMonitor state path is not a regular file")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleError("LinuxSecMonitor lifecycle state is unreadable or invalid") from exc
    if not isinstance(state, dict) or state.get("format") != 1:
        raise LifecycleError("LinuxSecMonitor lifecycle state has an unsupported format")
    return state


def integration_status(*, apt_conf_dir: Path, state_dir: Path) -> dict[str, str]:
    hook = apt_conf_dir / HOOK_NAME
    state_path = state_dir / STATE_NAME
    state = _read_state(state_path)
    try:
        info = hook.lstat()
    except FileNotFoundError:
        status = "disabled" if state else "not_installed"
    else:
        if not stat.S_ISREG(info.st_mode):
            status = "conflict"
        elif state and state.get("hook_sha256") == _digest(hook.read_bytes()):
            status = "enabled"
        else:
            status = "conflict"
    runtime = state.get("python") if state else None
    return {
        "status": status,
        "hook_path": str(hook),
        "state_path": str(state_path),
        "python": runtime if isinstance(runtime, str) else None,
    }


def _digest(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def install_apt_hook(
    *, apt_conf_dir: Path, state_dir: Path, python: str,
    module_paths: tuple[Path, ...] = (),
    effective_order_check: Callable[[str], None] | None = None,
    writer: Callable[[Path, bytes, int], None] = _atomic_write,
) -> dict[str, str]:
    """Install one dedicated hook atomically, preserving all existing files."""
    hook = apt_conf_dir / HOOK_NAME
    state_path = state_dir / STATE_NAME
    if module_paths:
        validate_trusted_runtime(python, module_paths)
    content = hook_contents(python)
    if state_path.exists() or state_path.is_symlink():
        if not hook.exists() and not hook.is_symlink():
            raise LifecycleError(
                f"Lifecycle state already exists: {state_path}; inspect status and use enable or recovery"
            )
        existing = integration_status(apt_conf_dir=apt_conf_dir, state_dir=state_dir)
        state = _read_state(state_path)
        if (
            existing["status"] == "enabled"
            and state is not None
            and state.get("python") == str(Path(python))
            and state.get("hook_sha256") == _digest(content)
            and hook.read_bytes() == content
        ):
            _validate_apt_config(content, apt_conf_dir, python)
            if effective_order_check is not None:
                effective_order_check(python)
            return existing
        if hook.exists() or hook.is_symlink():
            raise LifecycleError(f"Refusing to overwrite existing APT configuration: {hook}")
        raise LifecycleError(
            f"Lifecycle state already exists: {state_path}; inspect status and use enable or recovery"
        )
    if hook.exists() or hook.is_symlink():
        raise LifecycleError(f"Refusing to overwrite existing APT configuration: {hook}")
    _ensure_directory(apt_conf_dir)
    _validate_apt_config(content, apt_conf_dir, python)
    state = json.dumps(
        {
            "format": 1, "hook_sha256": _digest(content),
            "hook_name": HOOK_NAME, "python": str(Path(python)),
        },
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    state_written = False
    try:
        writer(state_path, state, 0o600)
        state_written = True
        writer(hook, content, 0o644)
        if effective_order_check is not None:
            effective_order_check(python)
    except BaseException as exc:
        # Remove only a file created by this invocation with the exact bytes.
        if state_written:
            try:
                if state_path.read_bytes() == state:
                    state_path.unlink()
            except OSError:
                pass
        try:
            if hook.read_bytes() == content:
                hook.unlink()
        except OSError:
            pass
        raise LifecycleError(f"APT hook installation failed and was rolled back: {exc}") from exc
    return integration_status(apt_conf_dir=apt_conf_dir, state_dir=state_dir)


def disable_apt_hook(*, apt_conf_dir: Path, state_dir: Path) -> dict[str, str]:
    """Disable the hook while retaining its ownership record for recovery."""
    hook = apt_conf_dir / HOOK_NAME
    state_path = state_dir / STATE_NAME
    state = _read_state(state_path)
    if not hook.exists() and not hook.is_symlink():
        return integration_status(apt_conf_dir=apt_conf_dir, state_dir=state_dir)
    if state is None or hook.is_symlink() or not stat.S_ISREG(hook.lstat().st_mode):
        raise LifecycleError("Refusing to remove an APT hook not recorded as LinuxSecMonitor-owned")
    if state.get("hook_sha256") != _digest(hook.read_bytes()):
        raise LifecycleError("APT hook differs from the recorded file; preserve it and investigate")
    hook.unlink()
    return integration_status(apt_conf_dir=apt_conf_dir, state_dir=state_dir)


def uninstall_apt_hook(*, apt_conf_dir: Path, state_dir: Path) -> dict[str, str]:
    """Remove only the unchanged owned hook and its lifecycle receipt."""
    disable_apt_hook(apt_conf_dir=apt_conf_dir, state_dir=state_dir)
    state_path = state_dir / STATE_NAME
    if state_path.exists():
        state_path.unlink()
    return integration_status(apt_conf_dir=apt_conf_dir, state_dir=state_dir)


def enable_apt_hook(
    *, apt_conf_dir: Path, state_dir: Path, module_paths: tuple[Path, ...] = (),
    effective_order_check: Callable[[str], None] | None = None,
) -> dict[str, str]:
    """Restore the hook from the recorded desired configuration."""
    state_path = state_dir / STATE_NAME
    state = _read_state(state_path)
    if state is None:
        raise LifecycleError("No LinuxSecMonitor installation record; install the hook first")
    hook = apt_conf_dir / HOOK_NAME
    # The content is recoverable from the exact interpreter path stored in state.
    python = state.get("python")
    expected = state.get("hook_sha256")
    if not isinstance(python, str):
        raise LifecycleError("Lifecycle state has no recoverable Python executable")
    if module_paths:
        validate_trusted_runtime(python, module_paths)
    content = hook_contents(python)
    if expected != _digest(content):
        raise LifecycleError("Lifecycle state does not match reconstructed APT hook")
    if hook.exists() or hook.is_symlink():
        if (
            not hook.is_symlink()
            and stat.S_ISREG(hook.lstat().st_mode)
            and hook.read_bytes() == content
        ):
            _validate_apt_config(content, apt_conf_dir, python)
            if effective_order_check is not None:
                effective_order_check(python)
            return integration_status(apt_conf_dir=apt_conf_dir, state_dir=state_dir)
        raise LifecycleError("APT hook path is occupied; refusing to overwrite it")
    _validate_apt_config(content, apt_conf_dir, python)
    _atomic_write(hook, content, 0o644)
    try:
        if effective_order_check is not None:
            effective_order_check(python)
    except BaseException:
        try:
            if hook.read_bytes() == content:
                hook.unlink()
        except OSError:
            pass
        raise
    return integration_status(apt_conf_dir=apt_conf_dir, state_dir=state_dir)
