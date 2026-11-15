from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest


RC_CANDIDATES = (
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zlogin",
    ".config/fish/config.fish",
)


@pytest.fixture(scope="module", autouse=True)
def guard_primary_home_rc():
    """Verify primary-user shell RC metadata and hashes remain unchanged."""
    real_home = Path(os.environ.get("HOME") or Path.home())
    candidates = [real_home / name for name in RC_CANDIDATES]

    def snapshot() -> dict[str, tuple[int, str]]:
        state = {}
        for path in candidates:
            if path.is_file():
                stat_result = path.stat()
                state[str(path)] = (
                    stat_result.st_size,
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
        return state

    before = snapshot()
    yield
    after = snapshot()
    changed = {}
    for path in before.keys() | after.keys():
        old, new = before.get(path), after.get(path)
        if old != new:
            fields = ("size", "sha256")
            changed[path] = [
                field for field, old_value, new_value in zip(fields, old or (), new or ())
                if old_value != new_value
            ]
    assert not changed, f"primary user shell configuration metadata/hash changed: {changed}"
