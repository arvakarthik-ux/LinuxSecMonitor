"""C6 tests for installed-wrapper execution interception."""

from __future__ import annotations

import json
import os
import pty
import select
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("build")

if shutil.which("bash") is None or shutil.which("git") is None:
    pytest.skip("bash and git are required", allow_module_level=True)

REPO_ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 120


def _env(home: Path, path: str) -> dict[str, str]:
    return {
        "HOME": str(home),
        "PATH": path,
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }


def _run(argv, *, env: dict[str, str], cwd: Path, timeout: int = TIMEOUT):
    return subprocess.run(
        [str(part) for part in argv],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _run_with_pty(
    argv,
    *,
    env: dict[str, str],
    cwd: Path,
    before_approval=None,
):
    pid, master_fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execve(str(argv[0]), [str(part) for part in argv], env)

    output = bytearray()
    deadline = time.monotonic() + TIMEOUT
    answer_sent = False
    child_status = None
    try:
        while True:
            if not answer_sent and b"Type exactly RUN" in output:
                try:
                    if before_approval is not None:
                        before_approval()
                except BaseException:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                    raise
                os.write(master_fd, b"RUN\n")
                answer_sent = True

            if child_status is None:
                waited, child_status = os.waitpid(pid, os.WNOHANG)
                if waited == 0:
                    child_status = None

            if time.monotonic() >= deadline:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                raise AssertionError(f"installed wrapper exceeded {TIMEOUT}s: {output!r}")

            readable, _, _ = select.select([master_fd], [], [], 0.1)
            if readable:
                try:
                    chunk = os.read(master_fd, 65536)
                except OSError:
                    if child_status is not None:
                        break
                    chunk = b""
                output.extend(chunk)
            elif child_status is not None:
                break
    finally:
        os.close(master_fd)

    if not answer_sent:
        raise AssertionError(f"installed wrapper did not request approval: {output!r}")
    return subprocess.CompletedProcess(
        argv,
        os.waitstatus_to_exitcode(child_status),
        "",
        output.decode("utf-8", errors="replace"),
    )


def _read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write_scanner_bootstrap(path: Path) -> None:
    path.mkdir()
    (path / "sitecustomize.py").write_text(
        """\
import json
import os
from pathlib import Path
from src.wrapper import scanners
from src.wrapper.approval import ApprovalManager
from scanner import execution_guard


def _record(event):
    event_path = os.environ.get("LSM_C6_EVENT_LOG")
    if event_path:
        with open(event_path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(event) + "\\n")


def _scan(self, repository):
    root = Path(repository).resolve()
    _record({"event": "scan", "root": str(root)})
    result = {
        "repository": str(root),
        "repository_content_hash": scanners.repository_content_hash(root),
        "coverage_complete": True,
        "repository_changed_during_scan": False,
        "inventory": {"status": "completed", "coverage_complete": True, "errors": []},
        "malware": {
            "status": "no_detection",
            "coverage_complete": True,
            "errors": [],
            "detections": [],
        },
        "security": {
            "status": "completed",
            "coverage_complete": True,
            "errors": [],
            "findings": [],
        },
        "scanner_versions": {"c6-fixture": "1"},
    }
    _record({"event": "scan_complete", "root": str(root)})
    return result


scanners.ScannerOrchestrator.scan = _scan
_original_request_approval = ApprovalManager.request_approval


def _request_approval(self, **kwargs):
    _record({"event": "approval_request", "argv": list(kwargs["argv"])})
    return _original_request_approval(self, **kwargs)


ApprovalManager.request_approval = _request_approval
_original_confirm_execution = execution_guard.confirm_execution


def _tracked_confirm_execution(*, terminal=None, prompt=None):
    _record({"event": "clone_review_acknowledgment", "prompt": prompt})
    return _original_confirm_execution(terminal=terminal, prompt=prompt)


execution_guard.confirm_execution = _tracked_confirm_execution
""",
        encoding="utf-8",
    )


@pytest.fixture(scope="module")
def installed_wrapper(tmp_path_factory):
    root = tmp_path_factory.mktemp("c6-installed-wrapper")
    dist = root / "dist"
    dist.mkdir()
    build_home = root / "build-home"
    build_home.mkdir()
    build_env = _env(build_home, os.environ.get("PATH", "/usr/bin:/bin"))
    built = _run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--outdir",
            dist,
            REPO_ROOT,
        ],
        env=build_env,
        cwd=REPO_ROOT,
    )
    assert built.returncode == 0, built.stdout + built.stderr
    wheels = sorted(dist.glob("*.whl"))
    assert len(wheels) == 1, wheels

    venv = root / "venv"
    venv_home = root / "venv-home"
    venv_home.mkdir()
    env = _env(venv_home, os.environ.get("PATH", "/usr/bin:/bin"))
    created = _run([sys.executable, "-m", "venv", venv], env=env, cwd=root)
    assert created.returncode == 0, created.stdout + created.stderr
    python = venv / "bin" / "python"
    installed = _run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
            wheels[0],
        ],
        env=env,
        cwd=root,
    )
    assert installed.returncode == 0, installed.stdout + installed.stderr

    home = root / "home"
    home.mkdir()
    (home / ".bashrc").write_text("# C6 temporary home\n", encoding="utf-8")
    wrapper_dir = home / ".local" / "bin"
    base_path = os.pathsep.join([str(venv / "bin"), "/usr/bin", "/usr/local/bin", "/bin"])
    install = _run(
        [venv / "bin" / "linuxsecmonitor", "--wrapper-integration", "install"],
        env=_env(home, base_path),
        cwd=root,
    )
    assert install.returncode == 0, install.stdout + install.stderr

    bootstrap = root / "bootstrap"
    _write_scanner_bootstrap(bootstrap)
    event_log = root / "events.jsonl"
    wrapper_env = _env(
        home,
        os.pathsep.join([str(wrapper_dir), "/usr/bin", "/usr/local/bin", "/bin"]),
    )
    wrapper_env.update(
        PYTHONPATH=str(bootstrap),
        PYTHONDONTWRITEBYTECODE="1",
        LSM_C6_EVENT_LOG=str(event_log),
    )
    return SimpleNamespace(
        home=home,
        wrapper_dir=wrapper_dir,
        env=wrapper_env,
        event_log=event_log,
        root=root,
    )


def _make_local_repository(origin: Path, *, script: str | None = None) -> None:
    origin.mkdir()
    commands = [
        ["git", "init", "--initial-branch=main"],
        ["git", "config", "user.email", "c6@example.invalid"],
        ["git", "config", "user.name", "C6 Fixture"],
    ]
    for command in commands:
        result = _run(command, env=_env(origin, "/usr/bin:/bin"), cwd=origin)
        assert result.returncode == 0, result.stdout + result.stderr
    (origin / "README.md").write_text("local C6 fixture\n", encoding="utf-8")
    if script is not None:
        (origin / "payload.sh").write_text(script, encoding="utf-8")
    added = _run(["git", "add", "."], env=_env(origin, "/usr/bin:/bin"), cwd=origin)
    assert added.returncode == 0, added.stdout + added.stderr
    committed = _run(
        ["git", "commit", "-m", "C6 local fixture"],
        env=_env(origin, "/usr/bin:/bin"),
        cwd=origin,
    )
    assert committed.returncode == 0, committed.stdout + committed.stderr


def _append_event(path: Path, event: str) -> str:
    return (
        f"printf '%s\\n' '{{\"event\":\"{event}\"}}' "
        f">> {shlex.quote(str(path))}"
    )


def test_installed_git_clone_reviews_before_repository_script_runs(
    installed_wrapper, tmp_path,
):
    installed_wrapper.event_log.unlink(missing_ok=True)
    origin = tmp_path / "origin"
    marker = tmp_path / "repository-code-ran"
    _make_local_repository(
        origin,
        script=f"#!/bin/sh\n: > {shlex.quote(str(marker))}\n"
        + _append_event(installed_wrapper.event_log, "repository_code"),
    )
    destination = tmp_path / "clone"

    def assert_code_not_run_before_review():
        assert not marker.exists()

    cloned = _run_with_pty(
        [
            installed_wrapper.wrapper_dir / "git",
            "clone",
            origin,
            destination,
        ],
        env=installed_wrapper.env,
        cwd=tmp_path,
        before_approval=assert_code_not_run_before_review,
    )
    assert cloned.returncode == 0, cloned.stdout + cloned.stderr
    assert "Post-clone snapshot review accepted" in cloned.stderr + cloned.stdout
    assert destination.joinpath(".git").exists()
    assert not marker.exists()

    script_run = _run(
        [installed_wrapper.wrapper_dir / "bash", destination / "payload.sh"],
        env=installed_wrapper.env,
        cwd=destination,
    )
    assert script_run.returncode == 0, script_run.stdout + script_run.stderr
    assert marker.is_file()
    events = _read_events(installed_wrapper.event_log)
    event_names = [event["event"] for event in events]
    assert event_names == [
        "scan",
        "scan_complete",
        "clone_review_acknowledgment",
        "scan",
        "scan_complete",
        "repository_code",
    ], events
    assert events[0]["root"] == str(destination.resolve())
    assert str(events[2]["prompt"]).startswith(
        "Post-clone review complete. Type exactly RUN"
    )
    assert events[3]["root"] == str(destination.resolve())


def test_installed_shell_script_is_scanned_before_execution(
    installed_wrapper, tmp_path,
):
    installed_wrapper.event_log.unlink(missing_ok=True)
    repository = tmp_path / "shell-repository"
    _make_local_repository(repository)
    marker = tmp_path / "shell-script-ran"
    script = repository / "payload.sh"
    script.write_text(
        "#!/bin/sh\n"
        f": > {shlex.quote(str(marker))}\n"
        + _append_event(installed_wrapper.event_log, "shell_script"),
        encoding="utf-8",
    )

    result = _run(
        [installed_wrapper.wrapper_dir / "bash", script],
        env=installed_wrapper.env,
        cwd=repository,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.is_file()
    events = _read_events(installed_wrapper.event_log)
    assert [event["event"] for event in events] == [
        "scan",
        "scan_complete",
        "shell_script",
    ], events
    assert events[0]["root"] == str(repository.resolve())


def test_installed_build_command_is_scanned_before_execution(
    installed_wrapper, tmp_path,
):
    installed_wrapper.event_log.unlink(missing_ok=True)
    repository = tmp_path / "build-repository"
    _make_local_repository(repository)
    marker = tmp_path / "build-action-ran"
    makefile = repository / "Makefile"
    makefile.write_text(
        "install:\n"
        f"\t@{_append_event(installed_wrapper.event_log, 'build_action')}\n"
        f"\t@touch {shlex.quote(str(marker))}\n",
        encoding="utf-8",
    )

    def assert_build_not_run_before_approval():
        assert not marker.exists()

    result = _run_with_pty(
        [installed_wrapper.wrapper_dir / "make", "install"],
        env=installed_wrapper.env,
        cwd=repository,
        before_approval=assert_build_not_run_before_approval,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.is_file()
    events = _read_events(installed_wrapper.event_log)
    assert [event["event"] for event in events] == [
        "scan",
        "scan_complete",
        "approval_request",
        "build_action",
    ], events
    assert events[0]["root"] == str(repository.resolve())
    assert events[2]["argv"] == ["make", "install"]


def test_installed_dependency_install_is_scanned_before_execution(
    installed_wrapper, tmp_path,
):
    installed_wrapper.event_log.unlink(missing_ok=True)
    repository = tmp_path / "dependency-repository"
    _make_local_repository(repository)
    report = tmp_path / "pip-dry-run-report.json"
    local_wheel = next((installed_wrapper.root / "dist").glob("*.whl"))
    argv = [
        installed_wrapper.wrapper_dir / "pip",
        "install",
        "--dry-run",
        "--no-index",
        "--no-deps",
        "--disable-pip-version-check",
        "--report",
        report,
        local_wheel,
    ]

    def assert_install_not_started_before_approval():
        assert not report.exists()

    result = _run_with_pty(
        argv,
        env=installed_wrapper.env,
        cwd=repository,
        before_approval=assert_install_not_started_before_approval,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert report.is_file()
    events = _read_events(installed_wrapper.event_log)
    assert [event["event"] for event in events] == [
        "scan",
        "scan_complete",
        "approval_request",
    ], events
    assert events[0]["root"] == str(repository.resolve())
    assert events[2]["argv"][:2] == ["pip", "install"]
    assert "--dry-run" in events[2]["argv"]
