"""PEP 517 build backend for LinuxSecMonitor.

The source checkout intentionally keeps ``src`` as a namespace package
(no ``src/__init__.py``): with the checkout on ``sys.path`` ahead of an
installed wheel, a regular ``src/__init__.py`` in the checkout would win
over the venv's installed copy and defeat the "installed package, not the
source checkout" requirement (gate G2).

The *installed* distribution, however, must provide a regular ``src``
package so that ``import src.wrapper`` resolves into site-packages even
when the source checkout is the current working directory. This backend
therefore injects a minimal ``src/__init__.py`` for the duration of each
build (sdist and wheel alike) and removes it again afterwards, so build
artifacts contain the file while the checkout does not retain it.

Ownership of an existing ``src/__init__.py`` is decided by content: only
the exact generated content is treated as ours and cleaned up, so a file
written by a user or another tool is never deleted.
"""

from __future__ import annotations

import os
from typing import Any, Callable

from setuptools import build_meta as _build_meta

_SRC_INIT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src", "__init__.py")
_SRC_INIT_CONTENT = (
    '"""LinuxSecMonitor package root (generated during package builds)."""\n'
)


def _inject() -> bool:
    """Ensure ``src/__init__.py`` exists for the duration of a build.

    Returns True when this call owns the file and must remove it again.
    """
    if os.path.exists(_SRC_INIT):
        try:
            with open(_SRC_INIT, encoding="utf-8") as handle:
                if handle.read() == _SRC_INIT_CONTENT:
                    return True  # leftover from an interrupted build; ours
        except OSError:
            return False
        return False  # a file we did not write: never delete it
    with open(_SRC_INIT, "w", encoding="utf-8") as handle:
        handle.write(_SRC_INIT_CONTENT)
    return True


def _release(owned: bool) -> None:
    if not owned:
        return
    try:
        os.remove(_SRC_INIT)
    except OSError:
        pass


def _build_with_injection(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    owned = _inject()
    try:
        return function(*args, **kwargs)
    finally:
        _release(owned)


def get_requires_for_build_wheel(config_settings: Any = None) -> list[str]:
    return _build_meta.get_requires_for_build_wheel(config_settings)


def get_requires_for_build_sdist(config_settings: Any = None) -> list[str]:
    return _build_meta.get_requires_for_build_sdist(config_settings)


def get_requires_for_build_editable(config_settings: Any = None) -> list[str]:
    return _build_meta.get_requires_for_build_editable(config_settings)


def prepare_metadata_for_build_wheel(metadata_directory: str, config_settings: Any = None) -> str:
    return _build_with_injection(
        _build_meta.prepare_metadata_for_build_wheel, metadata_directory, config_settings,
    )


def prepare_metadata_for_build_editable(metadata_directory: str, config_settings: Any = None) -> str:
    return _build_with_injection(
        _build_meta.prepare_metadata_for_build_editable, metadata_directory, config_settings,
    )


def build_wheel(wheel_directory: str, config_settings: Any = None, metadata_directory: str | None = None) -> str:
    return _build_with_injection(
        _build_meta.build_wheel, wheel_directory, config_settings, metadata_directory,
    )


def build_editable(wheel_directory: str, config_settings: Any = None, metadata_directory: str | None = None) -> str:
    return _build_with_injection(
        _build_meta.build_editable, wheel_directory, config_settings, metadata_directory,
    )


def build_sdist(sdist_directory: str, config_settings: Any = None) -> str:
    return _build_with_injection(_build_meta.build_sdist, sdist_directory, config_settings)
