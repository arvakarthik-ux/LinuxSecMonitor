"""Read-only prerequisite and integration diagnostics."""

from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable

SYSTEM_COMMANDS = {
    "apt-get": ("/usr/bin/apt-get", ["--version"]),
    "apt-config": ("/usr/bin/apt-config", ["dump"]),
    "dpkg-query": ("/usr/bin/dpkg-query", ["--version"]),
    "dpkg-deb": ("/usr/bin/dpkg-deb", ["--version"]),
    "clamscan": ("/usr/bin/clamscan", ["--version"]),
}
SUPPORTED_DISTRIBUTIONS = {"debian", "ubuntu", "kali"}
MINIMUM_PYTHON = (3, 11)
COMMAND_TIMEOUT_SECONDS = 5
MAX_VERSION_OUTPUT_CHARS = 300


def _read_os_release(path: Path) -> dict[str, str]:
    """Read selected os-release key/value data without sourcing a shell file."""
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line or line.lstrip().startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in {"ID", "PRETTY_NAME", "VERSION_ID"}:
                values[key] = value.strip().strip("\"'")
    except (OSError, UnicodeError):
        pass
    return values


def _safe_summary(value: str) -> str:
    """Keep one bounded tool-version line and escape terminal controls."""
    first_line = value.splitlines()[0][:MAX_VERSION_OUTPUT_CHARS] if value else ""
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in first_line
    )


def collect_diagnostics(
    *,
    runner: Callable = subprocess.run,
    system_name: str | None = None,
    os_release_path: str | Path = "/etc/os-release",
    python_version: tuple[int, int] | None = None,
    command_paths: dict[str, tuple[str, list[str]]] | None = None,
) -> dict[str, object]:
    """Check platform and tool prerequisites without changing host state.

    APT configuration contents are captured only long enough to count hook
    entries. Values are intentionally never returned because they may include
    proxy credentials or other sensitive settings.
    """
    os_name = system_name or platform.system()
    version = python_version or (sys.version_info.major, sys.version_info.minor)
    release = _read_os_release(Path(os_release_path)) if os_name == "Linux" else {}
    distribution_id = release.get("ID", "").lower()
    supported_host = os_name == "Linux" and distribution_id in SUPPORTED_DISTRIBUTIONS
    commands = SYSTEM_COMMANDS if command_paths is None else command_paths
    command_results: dict[str, dict[str, object]] = {}
    apt_config_output: str | None = None

    for name, (path, arguments) in commands.items():
        if not Path(path).is_file() or not os.access(path, os.X_OK):
            command_results[name] = {"available": False, "version": None}
            continue
        try:
            completed = runner(
                [path, *arguments],
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
                check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
        except subprocess.TimeoutExpired:
            command_results[name] = {
                "available": True, "version": None, "check": "timeout",
            }
            continue
        except OSError as exc:
            command_results[name] = {
                "available": True, "version": None,
                "check": type(exc).__name__,
            }
            continue
        except Exception as exc:
            command_results[name] = {
                "available": True, "version": None,
                "check": type(exc).__name__,
            }
            continue

        output = completed.stdout or completed.stderr or ""
        ok = completed.returncode == 0
        command_results[name] = {
            "available": True,
            "version": _safe_summary(output) if ok and name != "apt-config" else None,
            "check": "ok" if ok else "failed",
        }
        if name == "apt-config" and ok:
            apt_config_output = output

    pre_install_count = pre_invoke_count = None
    if apt_config_output is not None:
        pre_install_count = sum(
            bool(re.match(r"^\s*DPkg::Pre-Install-Pkgs::", line, re.IGNORECASE))
            for line in apt_config_output.splitlines()
        )
        pre_invoke_count = sum(
            bool(re.match(r"^\s*DPkg::Pre-Invoke::", line, re.IGNORECASE))
            for line in apt_config_output.splitlines()
        )

    minimum_python = version >= MINIMUM_PYTHON
    package_inventory_ready = (
        supported_host and command_results.get("dpkg-query", {}).get("check") == "ok"
    )
    deb_scan_ready = (
        os_name == "Linux"
        and command_results.get("dpkg-deb", {}).get("check") == "ok"
        and command_results.get("clamscan", {}).get("check") == "ok"
    )
    apt_hook_prerequisites = supported_host and all(
        command_results.get(name, {}).get("check") == "ok"
        for name in ("apt-get", "apt-config", "dpkg-deb", "clamscan")
    ) and minimum_python

    limitations = [
        "ClamAV version output does not prove that signatures are current or that a real scan succeeds.",
        "APT hook counts do not prove protocol-v3 support, hook order, or maintainer-script cancellation timing.",
        "APT hook command contents are intentionally omitted from diagnostics.",
    ]
    if distribution_id == "kali":
        limitations.append("Kali vulnerability assessment is unsupported; Debian/Ubuntu records are not applied.")
    if pre_install_count is None:
        limitations.append("Effective APT hook counts are unavailable because apt-config could not be queried.")

    return {
        "status": "supported_host" if supported_host else "unsupported_host",
        "operating_system": os_name,
        "distribution_id": distribution_id or None,
        "distribution": _safe_summary(release.get("PRETTY_NAME", "")) or None,
        "distribution_version": _safe_summary(release.get("VERSION_ID", "")) or None,
        "python_version": f"{version[0]}.{version[1]}",
        "python_supported": minimum_python,
        "package_inventory_ready": package_inventory_ready,
        "deb_scan_prerequisites_available": deb_scan_ready,
        "apt_hook_prerequisites_available": apt_hook_prerequisites,
        "commands": command_results,
        "apt_pre_install_hook_count": pre_install_count,
        "apt_pre_invoke_hook_count": pre_invoke_count,
        "limitations": limitations,
        "read_only": True,
    }
