"""Read-only collection of basic operating-system and runtime details."""

from __future__ import annotations

import platform
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class SystemInfo:
    """Basic information about the host running the scanner."""

    operating_system: str
    distribution: str | None
    distribution_version: str | None
    kernel_version: str
    architecture: str
    python_version: str
    hostname: str | None

    def to_dict(self) -> dict[str, str | None]:
        """Return a JSON-serializable representation."""
        return asdict(self)


def _read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    """Read key/value fields from os-release without executing its contents."""
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"\'')
    except OSError:
        pass
    return values


def collect_system_info() -> SystemInfo:
    """Collect host details using platform APIs and optional os-release data."""
    release = _read_os_release() if platform.system() == "Linux" else {}
    distribution = release.get("PRETTY_NAME") or release.get("NAME") or release.get("ID", "").capitalize() or None
    return SystemInfo(
        operating_system=platform.system() or "Unknown",
        distribution=distribution,
        distribution_version=release.get("VERSION_ID"),
        kernel_version=platform.release() or "Unknown",
        architecture=platform.machine() or "Unknown",
        python_version=platform.python_version(),
        hostname=platform.node() or None,
    )
