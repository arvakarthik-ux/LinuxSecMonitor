"""C7 tests for invocation paths mediated by installed wrapper shims."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.wrapper.install import WRAPPER_TEMPLATE
from src.wrapper.path import PathManager

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    initialized = subprocess.run(
        ["git", "init", "--quiet", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert initialized.returncode == 0, initialized.stdout + initialized.stderr
    (root / "payload.py").write_text("print('harmless fixture')\n", encoding="utf-8")
    (root / "payload.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    return root


def _managed_shim(command: str, wrapper_dir: Path) -> tuple[PathManager, Path]:
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    manager = PathManager(wrapper_dir)
    shim = manager.get_wrapper_path(command)
    shim.write_text(
        WRAPPER_TEMPLATE.format(command=command, sys_executable=sys.executable),
        encoding="utf-8",
    )
    shim.chmod(0o755)
    command_path = manager.get_command_path(command)
    command_path.symlink_to(shim.name)
    assert command_path.resolve(strict=True) == shim.resolve(strict=True)
    assert manager.is_wrapped_command(command)
    return manager, command_path


def _run_managed_shim(
    command_path: Path,
    arguments: list[str],
    repository: Path,
    wrapper_dir: Path,
    tmp_path: Path,
) -> dict[str, object]:
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir(parents=True)
    result_path = tmp_path / "decision.json"
    (bootstrap / "sitecustomize.py").write_text(
        """\
import json
import os
from pathlib import Path
from src.wrapper.core import CommandWrapper


def _record_decision(self):
    decision = self.get_decision()
    Path(os.environ["LSM_C7_RESULT"]).write_text(json.dumps({
        "command": self.command_name,
        "tier": decision.tier.name,
        "is_repository": bool(
            decision.repository and decision.repository.is_repository
        ),
    }), encoding="utf-8")
    return 0


CommandWrapper.execute = _record_decision
""",
        encoding="utf-8",
    )
    environment = {
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "LSM_C7_RESULT": str(result_path),
        "PATH": os.pathsep.join(
            [str(wrapper_dir.resolve()), "/usr/local/bin", "/usr/bin", "/bin"]
        ),
        "PYTHONPATH": os.pathsep.join([str(REPO_ROOT), str(bootstrap)]),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    completed = subprocess.run(
        [str(command_path), *arguments],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(result_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("shell", ["bash", "sh", "zsh", "fish"])
def test_alternate_shells_remain_on_the_review_route(
    shell: str,
    repository: Path,
    tmp_path: Path,
):
    wrapper_dir = tmp_path / shell / "wrappers"
    _, command_path = _managed_shim(shell, wrapper_dir)
    decision = _run_managed_shim(
        command_path,
        [str(repository / "payload.sh")],
        repository,
        wrapper_dir,
        tmp_path / shell,
    )

    assert decision == {"command": shell, "tier": "TIER_2_WARN", "is_repository": True}


def test_direct_interpreter_invocation_through_managed_shim_uses_review_route(
    repository: Path,
    tmp_path: Path,
):
    wrapper_dir = tmp_path / "wrappers"
    _, command_path = _managed_shim("python3", wrapper_dir)
    decision = _run_managed_shim(
        command_path,
        [str(repository / "payload.py")],
        repository,
        wrapper_dir,
        tmp_path,
    )

    assert decision == {
        "command": "python3",
        "tier": "TIER_2_WARN",
        "is_repository": True,
    }


def test_wrapper_first_path_selects_the_managed_interpreter_shim(tmp_path: Path):
    wrapper_dir = tmp_path / "managed"
    manager, managed_interpreter = _managed_shim("python3", wrapper_dir)

    installed_path = manager.ensure_wrapper_dir_in_path("/usr/bin:/bin")
    assert installed_path.split(os.pathsep)[0] == str(wrapper_dir.resolve())
    assert Path(shutil.which("python3", path=installed_path) or "") == managed_interpreter


def test_managed_shim_alias_for_interpreter_uses_review_route(
    repository: Path,
    tmp_path: Path,
):
    wrapper_dir = tmp_path / "wrappers"
    manager, shim_path = _managed_shim("python3", wrapper_dir)
    alias_path = wrapper_dir / "python3-alias"
    alias_path.symlink_to(shim_path.name)
    assert alias_path.resolve(strict=True) == manager.get_wrapper_path("python3").resolve()

    decision = _run_managed_shim(
        alias_path,
        [str(repository / "payload.py")],
        repository,
        wrapper_dir,
        tmp_path,
    )

    assert decision == {
        "command": "python3",
        "tier": "TIER_2_WARN",
        "is_repository": True,
    }


def test_subprocess_environment_uses_wrapper_first_controlled_path(
    repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    wrapper_dir = tmp_path / "managed-wrappers"
    _managed_shim("python3", wrapper_dir)
    untrusted_dir = tmp_path / "caller-controlled"
    untrusted_dir.mkdir()
    monkeypatch.setenv("PATH", os.pathsep.join([str(untrusted_dir), "/usr/bin", "/bin"]))
    observed: dict[str, object] = {}

    from src.wrapper import core

    def capture_run(argv, **kwargs):
        observed["argv"] = argv
        observed["env"] = kwargs["env"]
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(core.subprocess, "run", capture_run)
    wrapper = core.CommandWrapper(
        "true",
        ["true"],
        cwd=repository,
        path_manager=PathManager(wrapper_dir),
    )

    assert wrapper._run_command(["true"]) == 0
    environment = observed["env"]
    assert isinstance(environment, dict)
    child_path = environment["PATH"].split(os.pathsep)
    assert child_path[0] == str(wrapper_dir.resolve())
    assert str(untrusted_dir) not in child_path
