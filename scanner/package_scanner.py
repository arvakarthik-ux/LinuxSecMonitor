"""Read-only installed package inventory for Debian-family Linux systems."""

from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Package:
    """An installed package name and its package-manager version string."""

    name: str
    version: str
    source_name: str | None = None
    source_version: str | None = None


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
                # Source fields are internal assessment metadata; keep the
                # existing public package-inventory schema unchanged.
                "packages": [
                    {"name": package.name, "version": package.version}
                    for package in self.packages
                ]}


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
    """Parse dpkg-query output, including optional source-package metadata.

    Debian Policy permits the ``Source`` field to be omitted when source and
    binary package names and versions are identical. A present source name
    without a parenthesized version likewise means the versions are identical.
    Legacy two-column rows do not prove that relationship, so leave their
    source fields unset.
    """
    packages: list[Package] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 2 or not fields[0].strip() or not fields[1].strip():
            continue
        name, version = fields[0].strip(), fields[1].strip()
        source_name = source_version = None
        if len(fields) >= 3:
            raw_source = fields[2].strip()
            if not raw_source:
                # Per Debian Policy §5.6.12, Source may be omitted only when
                # source and binary package names and versions are identical.
                source_name = name.rsplit(":", 1)[0]
                source_version = version
            else:
                source_match = re.fullmatch(r"([a-z0-9.+-]+)(?: \(([^()]+)\))?", raw_source)
                if source_match:
                    source_name = source_match.group(1)
                    # A Source version in parentheses is present when it
                    # differs; otherwise Debian Policy guarantees equality.
                    source_version = source_match.group(2) or version
        packages.append(Package(name, version, source_name, source_version))
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
            ["dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\t${Source}\\n"],
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
