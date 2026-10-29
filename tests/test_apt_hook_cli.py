"""Process-level tests for the APT hook CLI without invoking APT or dpkg."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run_hook(protocol: bytes) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "PATH": os.defpath,
        "PYTHONNOUSERSITE": "1",
        "LC_ALL": "C",
    }
    return subprocess.run(
        [sys.executable, "-B", str(PROJECT_ROOT / "main.py"), "--apt-preinstall-hook"],
        input=protocol,
        capture_output=True,
        timeout=15,
        check=False,
        cwd=PROJECT_ROOT,
        env=environment,
    )


@pytest.mark.parametrize(
    ("protocol", "expected_message"),
    [
        (
            b"VERSION 2\nAPT::Architecture=amd64\n\n",
            b"requires the exact VERSION 3 header",
        ),
        (
            b"VERSION 3\nAPT::Architecture=amd64\n\n"
            b"linuxsecmonitor-pending - - none < 0.0.1 all none **CONFIGURE**\n",
            b"no matching archive to scan",
        ),
        (
            b"VERSION 3\nAPT::Architecture=amd64\n\n"
            b"linuxsecmonitor-old 0.0.1 all none > - - none **REMOVE**\n",
            b"no matching archive to scan",
        ),
    ],
    ids=["unsupported-version", "configure-only", "remove-only"],
)
def test_hook_cli_blocks_unsupported_or_archive_less_transactions(
    protocol: bytes,
    expected_message: bytes,
) -> None:
    result = _run_hook(protocol)

    assert result.returncode == 1
    assert expected_message in result.stderr
    assert b"blocked" in result.stderr.lower()


def test_hook_cli_blocks_missing_archive_without_scanning(tmp_path: Path) -> None:
    missing_archive = tmp_path / "missing.deb"
    protocol = (
        "VERSION 3\nAPT::Architecture=amd64\n\n"
        f"linuxsecmonitor-missing - - none < 0.0.1 all none {missing_archive}\n"
    ).encode()

    result = _run_hook(protocol)

    assert result.returncode == 1
    assert b"APT Pre-Install-Pkgs protocol version 3 accepted." in result.stderr
    assert b"does not exist or cannot be resolved" in result.stderr
    assert b"APT transaction blocked" in result.stderr
