"""Read-only installed package inventory for Debian-family Linux systems."""

from __future__ import annotations

import platform
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Package:
    """An installed package name and its package-manager version string."""

    name: str
    version: str


@dataclass(frozen=True)
class PackageScanResult:
    """Package scan outcome; error=None means success, including zero packages."""

    packages: list[Package]
    error: str | None = None

    @property
    def success(self) -> bool:
        """Whether enumeration completed successfully."""
        return self.error is None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable result while preserving scan status."""
        return {"success": self.success, "error": self.error,
                "packages": [asdict(package) for package in self.packages]}


def _os_release_ids(path: Path = Path("/etc/os-release")) -> set[str]:
    """Read the distro ID and ID_LIKE values without sourcing a shell file."""
    fields: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                fields[key] = value.strip().strip('"\'')
    except OSError:
        return set()
    # Use the exact distribution ID. ID_LIKE describes compatibility and must
    # not cause an otherwise unsupported distribution to be treated as Debian.
    distro_id = fields.get("ID", "").strip().lower()
    return {distro_id} if distro_id else set()


def parse_dpkg_output(output: str) -> list[Package]:
    """Parse dpkg-query's tab-separated package-name/version output."""
    packages: list[Package] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        name, separator, version = line.partition("\t")
        if separator and name.strip() and version.strip():
            packages.append(Package(name=name.strip(), version=version.strip()))
    return packages


def scan_installed_packages() -> PackageScanResult:
    """Enumerate Debian packages with dpkg-query; never changes system state."""
    if platform.system() != "Linux":
        return PackageScanResult([], "Package inventory is supported only on Debian/Ubuntu/Kali Linux.")
    distro_ids = _os_release_ids()
    supported_distributions = {"debian", "ubuntu", "kali"}
    unsupported_ids = distro_ids - supported_distributions
    if not distro_ids.intersection(supported_distributions):
        distro_name = next(iter(unsupported_ids), "unknown")
        return PackageScanResult(
            [],
            f"Unsupported distribution '{distro_name}': package inventory supports Debian, Ubuntu, and Kali.",
        )
    try:
        completed = subprocess.run(
            ["dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\n"],
            check=True, capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        return PackageScanResult([], "dpkg-query was not found; cannot scan installed packages.")
    except subprocess.TimeoutExpired:
        return PackageScanResult([], "dpkg-query timed out while reading the package database.")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip()
        return PackageScanResult([], f"dpkg-query failed{': ' + detail if detail else '.'}")
    except OSError as exc:
        return PackageScanResult([], f"Could not run dpkg-query: {exc}")
    return PackageScanResult(parse_dpkg_output(completed.stdout))
