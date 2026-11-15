"""Installed-wheel integration tests for the P4.1 wrapper lifecycle (gate G4).

Every scenario runs against a wheel built from the checkout and installed
into a throwaway venv (built once for the whole module). Installer/CLI/shell
invocations use temporary HOME paths, and the primary-HOME RC guard detects
content changes. P4.5 history records an initial Fish config creation under
the real HOME and its cleanup; P4.6 interactive Fish startup explicitly uses
temporary HOME and XDG config paths.

Scenario coverage (leaf-4.1.md G4):
  a. test_imports_resolve_into_venv_site_packages
  b. test_install_touches_only_expected_user_scoped_files
  c. test_fresh_shell_resolves_git_through_installed_shim
  d. test_clone_outside_checkout_enters_wrapper_and_runs_real_git
  e. test_reinstall_is_idempotent_and_keeps_pristine_backup
  f. test_foreign_file_at_shim_path_blocks_install
  g. test_backup_matches_preinstall_rc_and_uninstall_restores_user_content
  h. test_uninstall_removes_owned_files_retains_foreign_and_restores_git
  i. test_broken_package_shim_and_cli_fail_closed
  j. test_primary_home_rc_files_untouched (autouse module guard)
"""

from __future__ import annotations

import hashlib
import json
import os
import pty
import shlex
import select
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from p4_1_home_rc_guard import guard_primary_home_rc

pytest.importorskip("build")

if shutil.which("bash") is None:
    pytest.skip("bash is required for wrapper install tests", allow_module_level=True)
if shutil.which("git") is None:
    pytest.skip("git is required for wrapper install tests", allow_module_level=True)

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKOUT = "/home/kali/LinuxSecMonitor"
TIMEOUT = 120
SYSTEM_PATH = "/usr/bin:/bin"

MARKER_START = "# >>> linuxsecmonitor wrapper >>>"
MARKER_END = "# <<< linuxsecmonitor wrapper <<<"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _env(home, path: str, shell: str = "/bin/bash") -> dict[str, str]:
    """Environment for a subprocess: temporary HOME, never the real one."""
    return {
        "HOME": str(home),
        "PATH": path,
        "SHELL": shell,
        "LANG": "C.UTF-8",
    }


def _run(
    argv,
    *,
    env: dict[str, str],
    cwd,
    timeout: int = TIMEOUT,
    start_new_session: bool = False,
) -> subprocess.CompletedProcess:
    """Run a bounded subprocess with an explicit environment."""
    return subprocess.run(
        [str(part) for part in argv],
        env=env,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        start_new_session=start_new_session,
    )


def _run_with_pty(argv, *, env: dict[str, str], cwd, answer: bytes | None,
                  timeout: int = TIMEOUT,
                  scan_gate: tuple[Path, Path, Path] | None = None,
                  ) -> subprocess.CompletedProcess:
    """Run an installed shim with a controlling terminal and bounded input."""
    pid, master_fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execve(str(argv[0]), [str(part) for part in argv], env)

    output = bytearray()
    deadline = time.monotonic() + timeout
    answer_sent = False
    child_status = None
    scan_gate_observed = False
    scan_gate_error = None
    try:
        while True:
            if scan_gate is not None and not scan_gate_observed:
                scan_started, scan_release, must_remain_absent = scan_gate
                if scan_started.exists():
                    scan_gate_observed = True
                    if must_remain_absent.exists():
                        scan_gate_error = AssertionError(
                            "Tier 1 command ran before scan completion"
                        )
                    scan_release.touch()

            if (
                not answer_sent
                and b"Type exactly RUN" in output
            ):
                os.write(master_fd, answer if answer is not None else b"\x04")
                answer_sent = True

            if child_status is None:
                waited, child_status = os.waitpid(pid, os.WNOHANG)
                if waited == 0:
                    child_status = None

            if time.monotonic() >= deadline:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                raise AssertionError(f"installed shim exceeded {timeout}s: {output!r}")

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

    returncode = os.waitstatus_to_exitcode(child_status)
    if scan_gate is not None and not scan_gate_observed:
        raise AssertionError("installed wrapper never entered the gated scan")
    if scan_gate_error is not None:
        raise scan_gate_error
    return subprocess.CompletedProcess(
        argv, returncode, "", output.decode("utf-8", errors="replace"),
    )


def _write_p42_scanner_bootstrap(directory: Path) -> Path:
    """Create a temporary sitecustomize seam for installed-process scanner results."""
    directory.mkdir()
    sitecustomize = directory / "sitecustomize.py"
    sitecustomize.write_text(
        """\
import json
import os
from pathlib import Path
from src.wrapper import scanners
from src.wrapper.approval import ApprovalManager

child_home = (
    os.environ.get("LSM_P45_TEST_CHILD_HOME")
    or os.environ.get("LSM_P46_TEST_CHILD_HOME")
)
if child_home:
    from src.wrapper import core

    _original_build_child_environment = core.build_child_environment

    def _test_child_environment(*, cwd):
        environment = _original_build_child_environment(cwd=cwd)
        environment["HOME"] = child_home
        return environment

    core.build_child_environment = _test_child_environment


def _record(event):
    log_path = os.environ.get("LSM_P43_EVENT_LOG") or os.environ.get("LSM_P42_EVENT_LOG")
    if log_path:
        with open(log_path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(event) + "\\n")


def _scan(self, repository):
    root = Path(repository).resolve()
    mode = os.environ.get("LSM_P42_SCAN_MODE", "complete")
    _record({"event": "scan", "root": str(root), "mode": mode})
    started_path = os.environ.get("LSM_P43_SCAN_STARTED")
    if started_path:
        Path(started_path).touch()
        release_path = os.environ.get("LSM_P43_SCAN_RELEASE")
        if release_path:
            import time
            deadline = time.monotonic() + 30
            while not Path(release_path).exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError("P4.3 test did not release the scanner gate")
                time.sleep(0.01)
    inventory = {"status": "completed", "coverage_complete": True, "errors": []}
    malware = {
        "status": "no_detection", "coverage_complete": True,
        "errors": [], "detections": [],
    }
    security = {"status": "completed", "coverage_complete": True, "errors": [], "findings": []}
    coverage_complete = True
    content_hash = scanners.repository_content_hash(root)
    if mode == "incomplete":
        coverage_complete = False
        inventory["coverage_complete"] = False
    elif mode == "scanner_error":
        if os.environ.get("LSM_P43_EVENT_LOG"):
            coverage_complete = False
        security.update(status="error", coverage_complete=False, errors=["fixture scanner error"])
    elif mode == "malware":
        malware.update(
            status="detected",
            detections=[{"name": "fixture-malware", "path": "fixture.txt"}],
        )
    elif mode == "integrity_mismatch":
        content_hash = "fixture-integrity-mismatch"
    elif mode == "critical_finding":
        security["findings"] = [{
            "rule_id": "fixture-critical",
            "severity": "CRITICAL",
            "path": "fixture.txt",
        }]
    elif mode == "high_finding":
        security["findings"] = [{
            "rule_id": "fixture-high",
            "severity": "HIGH",
            "path": "fixture.txt",
        }]
    result = {
        "repository": str(root),
        "repository_content_hash": content_hash,
        "coverage_complete": coverage_complete,
        "repository_changed_during_scan": False,
        "inventory": inventory,
        "malware": malware,
        "security": security,
        "scanner_versions": {"fixture": "1"},
    }
    if os.environ.get("LSM_P43_EVENT_LOG"):
        _record({"event": "scan_complete", "root": str(root), "mode": mode})
    return result


scanners.ScannerOrchestrator.scan = _scan
_original_request_approval = ApprovalManager.request_approval


def _tracked_request_approval(self, **kwargs):
    _record({"event": "approval_request", "argv": list(kwargs.get("argv", ()))})
    return _original_request_approval(self, **kwargs)


ApprovalManager.request_approval = _tracked_request_approval
""",
        encoding="utf-8",
    )
    return sitecustomize


def _read_p42_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _walk_home(home: Path) -> tuple[set[Path], set[Path]]:
    """Relative (files|symlinks, directories) under a temporary HOME."""
    files: set[Path] = set()
    dirs: set[Path] = set()
    for path in sorted(home.rglob("*")):
        rel = path.relative_to(home)
        if path.is_symlink() or path.is_file():
            files.add(rel)
        elif path.is_dir():
            dirs.add(rel)
    return files, dirs


def _bin_snapshot(wrapper_dir: Path) -> dict[str, tuple]:
    """name -> ("link", target) / ("file", sha256) for a wrapper directory."""
    snapshot: dict[str, tuple] = {}
    if not wrapper_dir.is_dir():
        return snapshot
    for entry in sorted(wrapper_dir.iterdir()):
        if entry.is_symlink():
            snapshot[entry.name] = ("link", os.readlink(entry))
        else:
            snapshot[entry.name] = ("file", _sha256(entry))
    return snapshot


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory):
    """Build wheel + sdist once, offline, with local tooling only."""
    dist = tmp_path_factory.mktemp("dist")
    build_home = tmp_path_factory.mktemp("build-home")
    proc = _run(
        [
            sys.executable, "-m", "build", "--no-isolation",
            "--outdir", str(dist), str(REPO_ROOT),
        ],
        env=_env(build_home, os.environ.get("PATH", SYSTEM_PATH)),
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, f"build failed:\n{proc.stdout}\n{proc.stderr}"
    wheels = sorted(dist.glob("*.whl"))
    assert wheels, f"no wheel produced in {dist}"
    return wheels[0]


@pytest.fixture(scope="module")
def venv(built_wheel, tmp_path_factory):
    """Throwaway venv with the wheel installed offline (no deps, no network)."""
    venv_dir = tmp_path_factory.mktemp("venv")
    venv_home = tmp_path_factory.mktemp("venv-home")
    base_path = os.environ.get("PATH", SYSTEM_PATH)
    env = _env(venv_home, base_path)

    proc = _run([sys.executable, "-m", "venv", str(venv_dir)], env=env, cwd=venv_home)
    assert proc.returncode == 0, proc.stderr

    python = venv_dir / "bin" / "python"
    proc = _run(
        [python, "-m", "pip", "install", "--no-index", "--no-deps", str(built_wheel)],
        env={**env, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
        cwd=venv_home,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

    site_packages_dirs = list((venv_dir / "lib").glob("python*/site-packages"))
    assert len(site_packages_dirs) == 1, site_packages_dirs
    return SimpleNamespace(
        venv=venv_dir,
        bin=venv_dir / "bin",
        python=python,
        cli=venv_dir / "bin" / "linuxsecmonitor",
        site_packages=site_packages_dirs[0],
        home=venv_home,
    )


@pytest.fixture(scope="module")
def installed(venv, tmp_path_factory):
    """Fresh HOME with a minimal .bashrc and exactly one install run.

    Shared by scenarios b/c/d/e/h. The install invocation is captured so
    scenario b can assert on it and later scenarios reuse the result.
    """
    home = tmp_path_factory.mktemp("home-installed")
    bashrc = home / ".bashrc"
    bashrc.write_text("# user bashrc\nexport EDITOR=vim\n", encoding="utf-8")
    wrapper_dir = home / ".local" / "bin"
    backup = home / ".bashrc.linuxsecmonitor.bak"

    proc = _run(
        [venv.cli, "--wrapper-integration", "install"],
        env=_env(home, os.pathsep.join([str(venv.bin), "/usr/bin", "/bin"])),
        cwd=home,
    )
    succeeded = proc.returncode == 0
    return SimpleNamespace(
        venv=venv,
        home=home,
        bashrc=bashrc,
        wrapper_dir=wrapper_dir,
        backup=backup,
        install=proc,
        bashrc_after_first=bashrc.read_bytes() if succeeded else b"",
        bin_after_first=_bin_snapshot(wrapper_dir) if succeeded else {},
        backup_hash_after_first=_sha256(backup) if succeeded and backup.exists() else None,
    )


class TestInstalledWheelImports:
    """Scenario a: imports resolve into the venv, not the checkout."""

    def test_imports_resolve_into_venv_site_packages(self, venv, tmp_path):
        code = (
            "import src.wrapper, src.wrapper.install, src.wrapper.core;"
            "print('|'.join([src.wrapper.__file__, "
            "src.wrapper.install.__file__, src.wrapper.core.__file__]))"
        )
        proc = _run(
            [venv.python, "-c", code],
            env=_env(tmp_path, SYSTEM_PATH),
            cwd=tmp_path,
        )
        assert proc.returncode == 0, proc.stderr
        module_files = proc.stdout.strip().split("|")
        assert len(module_files) == 3, module_files
        venv_prefix = str(venv.venv) + os.sep
        for module_file in module_files:
            assert module_file.startswith(venv_prefix), module_file
            assert CHECKOUT not in module_file, module_file
            assert str(REPO_ROOT) not in module_file, module_file


class TestInstallScopingAndFreshShell:
    """Scenarios b and c: install scoping and fresh-shell resolution."""

    def test_install_touches_only_expected_user_scoped_files(self, installed):
        proc = installed.install
        assert proc.returncode == 0, proc.stdout + proc.stderr
        home = installed.home

        files, dirs = _walk_home(home)
        assert Path(".bashrc") in files
        assert Path(".bashrc.linuxsecmonitor.bak") in files
        assert dirs <= {Path(".local"), Path(".local/bin")}, dirs

        allowed_top_level = {Path(".bashrc"), Path(".bashrc.linuxsecmonitor.bak")}
        wrapper_bin = Path(".local") / "bin"
        for rel in sorted(files):
            if rel in allowed_top_level:
                continue
            assert rel.parts[:2] == wrapper_bin.parts, rel
            entry = home / rel
            if entry.is_symlink():
                target = os.readlink(entry)
                assert Path(target).name.startswith("lsmonitor-"), (rel, target)
            else:
                assert rel.name.startswith("lsmonitor-"), rel

        # The RC file must actually have been changed to include the block.
        bashrc_text = installed.bashrc.read_text(encoding="utf-8")
        assert MARKER_START in bashrc_text
        assert MARKER_END in bashrc_text
        assert str(installed.wrapper_dir) in bashrc_text

    def test_fresh_shell_resolves_git_through_installed_shim(self, installed):
        env = _env(installed.home, SYSTEM_PATH)

        which = _run(
            ["/bin/bash", "-ic", "command -v git"],
            env=env,
            cwd=installed.home,
            timeout=30,
        )
        assert which.returncode == 0, which.stderr
        resolved = [line for line in which.stdout.splitlines() if line.strip()]
        assert resolved, which.stdout
        assert Path(resolved[-1]).parent == installed.wrapper_dir, resolved
        assert Path(resolved[-1]).name == "git"

        version = _run(
            ["/bin/bash", "-ic", "git --version"],
            env=env,
            cwd=installed.home,
            timeout=30,
        )
        assert version.returncode == 0, version.stdout + version.stderr
        assert "git version" in version.stdout, version.stdout


class TestCloneDispatchOutsideCheckout:
    """Scenario d: clone outside the checkout enters the wrapper (entry only)."""

    def test_clone_outside_checkout_enters_wrapper_and_runs_real_git(
        self, installed, tmp_path,
    ):
        origin = tmp_path / "origin"
        origin.mkdir()
        git_env = _env(tmp_path, SYSTEM_PATH)

        def git(*args):
            return _run(["git", *args], env=git_env, cwd=origin, timeout=30)

        assert git("init").returncode == 0
        assert git("config", "user.email", "wrapper-test@example.invalid").returncode == 0
        assert git("config", "user.name", "Wrapper Test").returncode == 0
        (origin / "README.md").write_text("demo origin\n", encoding="utf-8")
        assert git("add", "README.md").returncode == 0
        assert git("commit", "-m", "initial commit").returncode == 0

        destination = tmp_path / "cloned"
        shim = installed.wrapper_dir / "git"
        proc = _run(
            [shim, "clone", str(origin), str(destination)],
            env=_env(
                installed.home,
                os.pathsep.join([str(installed.wrapper_dir), "/usr/bin", "/bin"]),
            ),
            # cwd is outside /home/kali/LinuxSecMonitor (pytest tmp under /tmp).
            cwd=tmp_path,
            # CRITICAL: no controlling TTY, so P3's post-clone
            # confirm_execution fails closed immediately instead of blocking on
            # /dev/tty for up to 300s.
            start_new_session=True,
        )

        combined = proc.stdout + proc.stderr
        # Entry/dispatch evidence only: the installed wrapper was entered and
        # the real git executable ran. This is NOT verification of the P4.2
        # post-clone review behavior (P3 fail-closed acceptance is preserved).
        assert "[LinuxSecMonitor]" in combined, combined
        assert (destination / ".git").exists(), combined
        assert proc.returncode != 0, combined


class TestInstalledPostCloneReview:
    """P4.2: installed Git shim reuses the P3A.5 post-clone review path."""

    @staticmethod
    def _installed_route(
        venv, tmp_path, *, scan_mode="complete", p43=False, scan_release=None,
        shell="/bin/bash",
    ):
        home = tmp_path / "p42-home"
        home.mkdir()
        global_git_config = tmp_path / "gitconfig"
        global_git_config.write_text("", encoding="utf-8")
        base_env = _env(
            home,
            os.pathsep.join([str(home / ".local" / "bin"), "/usr/bin", "/bin"]),
            shell=shell,
        )
        if Path(shell).name == "zsh":
            base_env["ZDOTDIR"] = str(home)
        elif Path(shell).name == "fish":
            base_env["XDG_CONFIG_HOME"] = str(home / ".config")
        base_env.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=str(global_git_config),
            GIT_TERMINAL_PROMPT="0",
        )
        install = _run(
            [venv.cli, "--wrapper-integration", "install"],
            env=base_env,
            cwd=tmp_path,
        )
        assert install.returncode == 0, install.stdout + install.stderr

        bootstrap_dir = tmp_path / "p42-bootstrap"
        _write_p42_scanner_bootstrap(bootstrap_dir)
        event_log = tmp_path / "p42-events.jsonl"
        env = {
            **base_env,
            "PYTHONPATH": str(bootstrap_dir),
            "LSM_P42_EVENT_LOG": str(event_log),
            "LSM_P42_SCAN_MODE": scan_mode,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        scan_started = tmp_path / "p43-scan-started"
        if p43:
            env.update(
                LSM_P43_EVENT_LOG=str(event_log),
                LSM_P43_SCAN_STARTED=str(scan_started),
            )
            if scan_release is not None:
                env["LSM_P43_SCAN_RELEASE"] = str(scan_release)
        return SimpleNamespace(
            home=home,
            shim=home / ".local" / "bin" / "git",
            env=env,
            event_log=event_log,
            scan_started=scan_started,
        )

    @staticmethod
    def _make_local_origin(origin: Path, tmp_path: Path) -> None:
        origin.mkdir()
        git_env = _env(tmp_path, SYSTEM_PATH)
        git_env.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_TERMINAL_PROMPT="0",
        )
        commands = [
            ["git", "init", "--initial-branch=main"],
            ["git", "config", "user.email", "p42@example.invalid"],
            ["git", "config", "user.name", "P4.2 Fixture"],
        ]
        for command in commands:
            proc = _run(command, env=git_env, cwd=origin)
            assert proc.returncode == 0, proc.stdout + proc.stderr
        (origin / "fixture.txt").write_text("offline fixture\n", encoding="utf-8")
        for command in (["git", "add", "fixture.txt"], ["git", "commit", "-m", "fixture"]):
            proc = _run(command, env=git_env, cwd=origin)
            assert proc.returncode == 0, proc.stdout + proc.stderr

    @staticmethod
    def _git_events(route):
        return _read_p42_events(route.event_log)

    @pytest.mark.parametrize("explicit_destination", [True, False])
    def test_installed_shim_reviews_successful_worktree_clone(
        self, venv, tmp_path, explicit_destination,
    ):
        origin = tmp_path / "origin-seed.git"
        self._make_local_origin(origin, tmp_path)
        cwd = tmp_path / "outside-checkout"
        cwd.mkdir()
        assert str(REPO_ROOT) not in str(cwd.resolve())
        route = self._installed_route(venv, tmp_path)
        destination = cwd / (
            "explicit-worktree" if explicit_destination else "origin-seed"
        )
        argv = [route.shim, "clone", str(origin)]
        if explicit_destination:
            argv.append("explicit-worktree")

        proc = _run_with_pty(
            argv, env=route.env, cwd=cwd, answer=b"RUN\n",
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, combined
        assert (destination / ".git").is_dir(), combined
        assert (destination / "fixture.txt").read_text(encoding="utf-8") == "offline fixture\n"
        assert "Post-clone snapshot review accepted" in combined
        assert "no authorization for any later command" in combined
        assert "Type exactly RUN" in combined
        events = self._git_events(route)
        scans = [event for event in events if event["event"] == "scan"]
        assert scans == [{
            "event": "scan",
            "root": str(destination.resolve()),
            "mode": "complete",
        }]
        assert not [event for event in events if event["event"] == "approval_request"]

    @pytest.mark.parametrize(
        "answer",
        [b"run\n", b"RUN \n", b"\n", b"\x04", b"\x03"],
        ids=["lowercase", "trailing-space", "empty-line", "eof", "interrupt"],
    )
    def test_installed_review_rejects_non_exact_acknowledgment(
        self, venv, tmp_path, answer,
    ):
        origin = tmp_path / "origin-seed.git"
        self._make_local_origin(origin, tmp_path)
        cwd = tmp_path / "outside-checkout"
        cwd.mkdir()
        route = self._installed_route(venv, tmp_path)
        destination = cwd / "clone-target"

        proc = _run_with_pty(
            [route.shim, "clone", str(origin), "clone-target"],
            env=route.env,
            cwd=cwd,
            answer=answer,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode != 0, combined
        assert "Type exactly RUN" in combined
        assert "snapshot review accepted" not in combined
        assert "Clone remains on disk, unaccepted" in combined
        assert (destination / ".git").is_dir()
        assert any(event["event"] == "scan" for event in self._git_events(route))
        assert not any(
            event["event"] == "approval_request" for event in self._git_events(route)
        )

    def test_failed_installed_clone_preserves_git_status_without_review(
        self, venv, tmp_path,
    ):
        origin = tmp_path / "origin-seed.git"
        self._make_local_origin(origin, tmp_path)
        cwd = tmp_path / "outside-checkout"
        cwd.mkdir()
        occupied = cwd / "occupied"
        occupied.mkdir()
        (occupied / "keep.txt").write_text("existing\n", encoding="utf-8")
        route = self._installed_route(venv, tmp_path)
        argv = ["git", "clone", str(origin), "occupied"]
        expected = _run(argv, env=route.env, cwd=cwd)
        assert expected.returncode != 0

        proc = _run(
            [route.shim, *argv[1:]],
            env=route.env,
            cwd=cwd,
            start_new_session=True,
        )

        assert proc.returncode == expected.returncode
        assert (occupied / "keep.txt").read_text(encoding="utf-8") == "existing\n"
        assert not self._git_events(route)
        assert "Post-clone review" not in proc.stdout + proc.stderr

    @pytest.mark.parametrize(
        ("scan_mode", "blocked_text"),
        [
            ("incomplete", "repository inspection is incomplete"),
            ("scanner_error", "security scanner assessment is incomplete"),
            ("malware", "malware detected"),
            ("integrity_mismatch", "repository content changed after scanning"),
        ],
    )
    def test_installed_review_fail_closed_scan_outcomes(
        self, venv, tmp_path, scan_mode, blocked_text,
    ):
        origin = tmp_path / "origin-seed.git"
        self._make_local_origin(origin, tmp_path)
        cwd = tmp_path / "outside-checkout"
        cwd.mkdir()
        route = self._installed_route(venv, tmp_path, scan_mode=scan_mode)
        destination = cwd / "clone-target"

        proc = _run_with_pty(
            [route.shim, "clone", str(origin), "clone-target"],
            env=route.env,
            cwd=cwd,
            answer=None,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 1, combined
        assert blocked_text in combined
        assert "snapshot review accepted" not in combined
        assert "Type exactly RUN" not in combined
        assert (destination / ".git").is_dir()
        assert any(event["event"] == "scan" for event in self._git_events(route))

    def test_installed_review_without_tty_fails_closed(self, venv, tmp_path):
        origin = tmp_path / "origin-seed.git"
        self._make_local_origin(origin, tmp_path)
        cwd = tmp_path / "outside-checkout"
        cwd.mkdir()
        route = self._installed_route(venv, tmp_path)
        destination = cwd / "clone-target"

        proc = _run(
            [route.shim, "clone", str(origin), "clone-target"],
            env=route.env,
            cwd=cwd,
            start_new_session=True,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode != 0, combined
        assert "snapshot review accepted" not in combined
        assert "Clone remains on disk, unaccepted" in combined
        assert (destination / ".git").is_dir()
        assert any(event["event"] == "scan" for event in self._git_events(route))

    @pytest.mark.parametrize("clone_flag", ["--bare", "--mirror"])
    def test_installed_bare_and_mirror_clones_are_not_reviewed(
        self, venv, tmp_path, clone_flag,
    ):
        origin = tmp_path / "origin-seed.git"
        self._make_local_origin(origin, tmp_path)
        cwd = tmp_path / "outside-checkout"
        cwd.mkdir()
        route = self._installed_route(venv, tmp_path)
        destination = cwd / "bare-target"

        proc = _run_with_pty(
            [route.shim, "clone", clone_flag, str(origin), "bare-target"],
            env=route.env,
            cwd=cwd,
            answer=None,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 1, combined
        assert "no reviewable worktree" in combined
        assert "snapshot review accepted" not in combined
        assert "Type exactly RUN" not in combined
        assert destination.is_dir()
        assert not (destination / ".git").exists()
        assert (destination / "HEAD").is_file()
        assert not self._git_events(route)

    def test_clone_acknowledgment_does_not_authorize_later_tier_one_command(
        self, venv, tmp_path,
    ):
        origin = tmp_path / "origin-seed.git"
        self._make_local_origin(origin, tmp_path)
        cwd = tmp_path / "outside-checkout"
        cwd.mkdir()
        route = self._installed_route(venv, tmp_path)
        destination = cwd / "clone-target"

        clone = _run_with_pty(
            [route.shim, "clone", str(origin), "clone-target"],
            env=route.env,
            cwd=cwd,
            answer=b"RUN\n",
        )
        assert clone.returncode == 0, clone.stderr
        assert not [
            event for event in self._git_events(route)
            if event["event"] == "approval_request"
        ]

        later = _run(
            [route.shim, "checkout", "-b", "p42-later-command"],
            env=route.env,
            cwd=destination,
            start_new_session=True,
        )

        assert later.returncode == 3, later.stdout + later.stderr
        assert "Approval cancelled or unavailable" in later.stderr
        branch = _run(["git", "branch", "--show-current"], env=route.env, cwd=destination)
        assert branch.returncode == 0, branch.stdout + branch.stderr
        assert branch.stdout.strip() == "main"
        approval_events = [
            event for event in self._git_events(route)
            if event["event"] == "approval_request"
        ]
        assert approval_events == [{
            "event": "approval_request",
            "argv": ["git", "checkout", "-b", "p42-later-command"],
        }]


class TestInstalledNonGitWrapperPaths:
    """P4.3: installed non-Git shims preserve existing P3 tier behavior."""

    @staticmethod
    def _make_marker_fixture(repository: Path, marker: Path, event_log: Path) -> None:
        marker_event = shlex.quote(json.dumps({"event": "marker_action"}))
        marker_path = shlex.quote(str(marker))
        event_path = shlex.quote(str(event_log))
        (repository / "Makefile").write_text(
            ".PHONY: install\n"
            "install:\n"
            f"\t@printf '%s\\n' {marker_event} >> {event_path}\n"
            f"\t@touch {marker_path}\n",
            encoding="utf-8",
        )

    @staticmethod
    def _python_marker_fixture(repository: Path, marker: Path, event_log: Path) -> Path:
        script = repository / "fixture.py"
        script.write_text(
            "import json\n"
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed\\n', encoding='utf-8')\n"
            f"with Path({str(event_log)!r}).open('a', encoding='utf-8') as stream:\n"
            "    stream.write(json.dumps({'event': 'marker_action'}) + '\\n')\n",
            encoding="utf-8",
        )
        return script

    @staticmethod
    def _repository(path: Path, tmp_path: Path) -> None:
        TestInstalledPostCloneReview._make_local_origin(path, tmp_path)

    def test_tier1_make_install_runs_only_after_scan_and_exact_run(
        self, venv, tmp_path,
    ):
        repository = tmp_path / "make-project"
        self._repository(repository, tmp_path)
        route = TestInstalledPostCloneReview._installed_route(
            venv,
            tmp_path,
            p43=True,
            scan_release=tmp_path / "release-scan",
        )
        marker = tmp_path / "make-marker"
        self._make_marker_fixture(repository, marker, route.event_log)
        release = Path(route.env["LSM_P43_SCAN_RELEASE"])

        proc = _run_with_pty(
            [route.home / ".local" / "bin" / "make", "install"],
            env=route.env,
            cwd=repository,
            answer=b"RUN\n",
            scan_gate=(route.scan_started, release, marker),
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, combined
        assert marker.is_file(), combined
        assert "TIER 1: Scanning repository before make install" in combined
        assert "Type exactly RUN" in combined
        events = _read_p42_events(route.event_log)
        assert [event["event"] for event in events] == [
            "scan", "scan_complete", "approval_request", "marker_action",
        ]
        assert events[0]["root"] == str(repository.resolve())
        assert events[2]["argv"] == ["make", "install"]

    @pytest.mark.parametrize("answer", [b"NO\n", b"\x04"], ids=["rejected", "eof"])
    def test_tier1_make_install_rejection_does_not_run(self, venv, tmp_path, answer):
        repository = tmp_path / "make-project"
        self._repository(repository, tmp_path)
        route = TestInstalledPostCloneReview._installed_route(venv, tmp_path, p43=True)
        marker = tmp_path / "make-marker"
        self._make_marker_fixture(repository, marker, route.event_log)

        proc = _run_with_pty(
            [route.home / ".local" / "bin" / "make", "install"],
            env=route.env,
            cwd=repository,
            answer=answer,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 3, combined
        assert "Approval cancelled or unavailable" in combined
        assert not marker.exists()
        events = _read_p42_events(route.event_log)
        assert [event["event"] for event in events] == [
            "scan", "scan_complete", "approval_request",
        ]

    def test_tier1_make_install_without_repository_does_not_run(self, venv, tmp_path):
        cwd = tmp_path / "not-a-repository"
        cwd.mkdir()
        route = TestInstalledPostCloneReview._installed_route(venv, tmp_path, p43=True)
        marker = tmp_path / "make-marker"
        self._make_marker_fixture(cwd, marker, route.event_log)

        proc = _run(
            [route.home / ".local" / "bin" / "make", "install"],
            env=route.env,
            cwd=cwd,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 1, combined
        assert "no repository context" in combined
        assert not marker.exists()
        assert not _read_p42_events(route.event_log)

    def test_tier1_make_install_unavailable_tty_does_not_run(self, venv, tmp_path):
        repository = tmp_path / "make-project"
        self._repository(repository, tmp_path)
        route = TestInstalledPostCloneReview._installed_route(venv, tmp_path, p43=True)
        marker = tmp_path / "make-marker"
        self._make_marker_fixture(repository, marker, route.event_log)

        proc = _run(
            [route.home / ".local" / "bin" / "make", "install"],
            env=route.env,
            cwd=repository,
            start_new_session=True,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 3, combined
        assert "Approval cancelled or unavailable" in combined
        assert not marker.exists()
        events = _read_p42_events(route.event_log)
        assert [event["event"] for event in events] == [
            "scan", "scan_complete", "approval_request",
        ]

    @pytest.mark.parametrize(
        "scan_mode",
        ["incomplete", "scanner_error", "malware"],
    )
    def test_tier1_make_install_blocks_existing_scan_failures(
        self, venv, tmp_path, scan_mode,
    ):
        repository = tmp_path / "make-project"
        self._repository(repository, tmp_path)
        route = TestInstalledPostCloneReview._installed_route(
            venv, tmp_path, scan_mode=scan_mode, p43=True,
        )
        marker = tmp_path / "make-marker"
        self._make_marker_fixture(repository, marker, route.event_log)

        proc = _run(
            [route.home / ".local" / "bin" / "make", "install"],
            env=route.env,
            cwd=repository,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 1, combined
        assert not marker.exists()
        events = _read_p42_events(route.event_log)
        assert [event["event"] for event in events] == ["scan", "scan_complete"]
        assert "approval_request" not in [event["event"] for event in events]

    def _run_tier2_script(self, venv, tmp_path, *, scan_mode):
        repository = tmp_path / "python-project"
        self._repository(repository, tmp_path)
        route = TestInstalledPostCloneReview._installed_route(
            venv, tmp_path, scan_mode=scan_mode, p43=True,
        )
        marker = tmp_path / "python-marker"
        script = self._python_marker_fixture(repository, marker, route.event_log)
        proc = _run(
            [route.home / ".local" / "bin" / "python3", script],
            env=route.env,
            cwd=repository,
        )
        return proc, marker, route

    def test_tier2_python_script_runs_after_complete_scan(self, venv, tmp_path):
        proc, marker, route = self._run_tier2_script(
            venv, tmp_path, scan_mode="complete",
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, combined
        assert marker.read_text(encoding="utf-8") == "executed\n"
        assert "TIER 2: Scanning repository before python3" in combined
        events = _read_p42_events(route.event_log)
        assert [event["event"] for event in events] == [
            "scan", "scan_complete", "marker_action",
        ]
        assert events[0]["root"] == str((tmp_path / "python-project").resolve())
        assert "approval_request" not in [event["event"] for event in events]

    def test_tier2_python_script_allows_noncritical_finding(self, venv, tmp_path):
        proc, marker, route = self._run_tier2_script(
            venv, tmp_path, scan_mode="high_finding",
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, combined
        assert marker.is_file()
        assert [event["event"] for event in _read_p42_events(route.event_log)] == [
            "scan", "scan_complete", "marker_action",
        ]

    @pytest.mark.parametrize(
        "scan_mode",
        ["incomplete", "scanner_error", "malware", "critical_finding"],
    )
    def test_tier2_python_script_blocks_existing_block_conditions(
        self, venv, tmp_path, scan_mode,
    ):
        proc, marker, route = self._run_tier2_script(
            venv, tmp_path, scan_mode=scan_mode,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 1, combined
        assert not marker.exists()
        events = _read_p42_events(route.event_log)
        assert [event["event"] for event in events] == ["scan", "scan_complete"]
        assert "approval_request" not in [event["event"] for event in events]
        if scan_mode == "critical_finding":
            assert "critical security finding" in combined


class TestInstalledShellScriptTier2:
    """P4.4: installed Bash and sh script routes preserve P3 Tier 2 behavior."""

    @staticmethod
    def _script_fixture(repository: Path, shell: str, marker: Path, event_log: Path) -> Path:
        script = repository / f"fixture-{shell}.sh"
        marker_event = shlex.quote(json.dumps({"event": "marker_action"}))
        marker_path = shlex.quote(str(marker))
        event_path = shlex.quote(str(event_log))
        script.write_text(
            f"printf '%s\\n' {marker_event} >> {event_path}\n"
            f"printf '%s\\n' executed > {marker_path}\n",
            encoding="utf-8",
        )
        return script

    @staticmethod
    def _run_shell_script(venv, tmp_path, *, shell, scan_mode):
        repository = tmp_path / f"{shell}-project"
        TestInstalledNonGitWrapperPaths._repository(repository, tmp_path)
        route = TestInstalledPostCloneReview._installed_route(
            venv, tmp_path, scan_mode=scan_mode, p43=True,
        )
        if shell in ("zsh", "fish"):
            route.env["LSM_P45_TEST_CHILD_HOME"] = str(route.home)
        marker = tmp_path / f"{shell}-marker"
        script = TestInstalledShellScriptTier2._script_fixture(
            repository, shell, marker, route.event_log,
        )
        shell_options = {
            "zsh": ["-f"],
            "fish": ["--no-config"],
        }.get(shell, [])
        proc = _run(
            [route.home / ".local" / "bin" / shell, *shell_options, script],
            env=route.env,
            cwd=repository,
        )
        return proc, marker, route, repository

    @pytest.mark.parametrize("shell", ["bash", "sh"])
    def test_shell_script_runs_after_complete_scan_without_approval(
        self, venv, tmp_path, shell,
    ):
        proc, marker, route, repository = self._run_shell_script(
            venv, tmp_path, shell=shell, scan_mode="complete",
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, combined
        assert marker.read_text(encoding="utf-8") == "executed\n"
        assert f"TIER 2: Scanning repository before {shell}" in combined
        assert "Type exactly RUN" not in combined
        events = _read_p42_events(route.event_log)
        assert [event["event"] for event in events] == [
            "scan", "scan_complete", "marker_action",
        ]
        assert events[0]["root"] == str(repository.resolve())

    @pytest.mark.parametrize("shell", ["bash", "sh"])
    @pytest.mark.parametrize(
        ("scan_mode", "blocked_text"),
        [
            ("incomplete", "repository inspection is incomplete"),
            ("malware", "confirmed malware detected"),
            ("critical_finding", "critical security finding"),
        ],
        ids=["incomplete", "malware", "critical-finding"],
    )
    def test_shell_script_blocks_existing_block_conditions(
        self, venv, tmp_path, shell, scan_mode, blocked_text,
    ):
        proc, marker, route, repository = self._run_shell_script(
            venv, tmp_path, shell=shell, scan_mode=scan_mode,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 1, combined
        assert blocked_text in combined
        assert not marker.exists()
        events = _read_p42_events(route.event_log)
        assert [event["event"] for event in events] == ["scan", "scan_complete"]
        assert events[0]["root"] == str(repository.resolve())
        assert "Type exactly RUN" not in combined
        assert "approval_request" not in [event["event"] for event in events]


class TestInstalledZshFishScriptTier2:
    """P4.5: installed Zsh and Fish script routes preserve P3 Tier 2 behavior."""

    @pytest.mark.parametrize("shell", ["zsh", "fish"])
    def test_zsh_fish_script_runs_after_complete_scan_without_approval(
        self, venv, tmp_path, shell,
    ):
        proc, marker, route, repository = TestInstalledShellScriptTier2._run_shell_script(
            venv, tmp_path, shell=shell, scan_mode="complete",
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, combined
        assert marker.read_text(encoding="utf-8") == "executed\n"
        assert f"TIER 2: Scanning repository before {shell}" in combined
        assert "Type exactly RUN" not in combined
        events = _read_p42_events(route.event_log)
        assert [event["event"] for event in events] == [
            "scan", "scan_complete", "marker_action",
        ]
        assert events[0]["root"] == str(repository.resolve())

    @pytest.mark.parametrize("shell", ["zsh", "fish"])
    @pytest.mark.parametrize(
        ("scan_mode", "blocked_text"),
        [
            ("incomplete", "repository inspection is incomplete"),
            ("malware", "confirmed malware detected"),
            ("critical_finding", "critical security finding"),
        ],
        ids=["incomplete", "malware", "critical-finding"],
    )
    def test_zsh_fish_script_blocks_existing_block_conditions(
        self, venv, tmp_path, shell, scan_mode, blocked_text,
    ):
        proc, marker, route, repository = TestInstalledShellScriptTier2._run_shell_script(
            venv, tmp_path, shell=shell, scan_mode=scan_mode,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 1, combined
        assert blocked_text in combined
        assert not marker.exists()
        events = _read_p42_events(route.event_log)
        assert [event["event"] for event in events] == ["scan", "scan_complete"]
        assert events[0]["root"] == str(repository.resolve())
        assert "Type exactly RUN" not in combined
        assert "approval_request" not in [event["event"] for event in events]


class TestInstalledZshFishFreshShellActivation:
    """P4.6: installed shell RC integration activates in a fresh interactive shell."""

    @pytest.mark.parametrize("shell", ["zsh", "fish"])
    def test_fresh_interactive_shell_activates_installed_tier2_route(
        self, venv, tmp_path, shell,
    ):
        repository = tmp_path / f"{shell}-fresh-shell-project"
        TestInstalledNonGitWrapperPaths._repository(repository, tmp_path)
        route = TestInstalledPostCloneReview._installed_route(
            venv,
            tmp_path,
            p43=True,
            shell=f"/usr/bin/{shell}",
        )
        marker = tmp_path / f"{shell}-fresh-shell-marker"
        script = TestInstalledNonGitWrapperPaths._python_marker_fixture(
            repository, marker, route.event_log,
        )
        shim = route.home / ".local" / "bin" / "python3"

        if shell == "zsh":
            rc_file = route.home / ".zshrc"
            assert route.env["ZDOTDIR"] == str(route.home)
            assert rc_file.is_file()
            assert "export PATH=" in rc_file.read_text(encoding="utf-8")
        else:
            rc_file = route.home / ".config" / "fish" / "config.fish"
            assert route.env["XDG_CONFIG_HOME"] == str(route.home / ".config")
            assert rc_file.is_file()
            assert f"set -gx PATH {route.home / '.local' / 'bin'} $PATH" in (
                rc_file.read_text(encoding="utf-8")
            )
        assert rc_file.is_relative_to(route.home)
        assert str(shim.parent) in rc_file.read_text(encoding="utf-8")
        assert route.env["HOME"] == str(route.home)

        route.env["PATH"] = SYSTEM_PATH
        route.env["LSM_P46_TEST_CHILD_HOME"] = str(route.home)
        command = f"command -v python3; python3 {shlex.quote(str(script))}"
        proc = _run(
            [f"/usr/bin/{shell}", "-i", "-c", command],
            env=route.env,
            cwd=repository,
        )

        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, combined
        assert str(shim) in proc.stdout.splitlines(), combined
        assert marker.read_text(encoding="utf-8") == "executed\n"
        events = _read_p42_events(route.event_log)
        assert [event["event"] for event in events] == [
            "scan", "scan_complete", "marker_action",
        ]
        assert events[0]["root"] == str(repository.resolve())
        assert str(REPO_ROOT) not in str(repository.resolve())


class TestReinstallIdempotency:
    """Scenario e: a second install changes nothing and keeps the backup."""

    def test_reinstall_is_idempotent_and_keeps_pristine_backup(self, installed, venv):
        assert installed.install.returncode == 0, installed.install.stdout
        assert installed.backup_hash_after_first is not None

        second = _run(
            [venv.cli, "--wrapper-integration", "install"],
            env=_env(installed.home, os.pathsep.join([str(venv.bin), "/usr/bin", "/bin"])),
            cwd=installed.home,
        )
        assert second.returncode == 0, second.stdout + second.stderr

        assert installed.bashrc.read_bytes() == installed.bashrc_after_first
        assert _bin_snapshot(installed.wrapper_dir) == installed.bin_after_first
        assert _sha256(installed.backup) == installed.backup_hash_after_first
        # The pristine backup still holds the pre-install RC, not a marked one.
        assert MARKER_START not in installed.backup.read_text(encoding="utf-8")


class TestConflictPreflight:
    """Scenario f: a foreign file at the shim path blocks the install."""

    def test_foreign_file_at_shim_path_blocks_install(self, venv, tmp_path):
        home = tmp_path / "home-conflict"
        (home / ".local" / "bin").mkdir(parents=True)
        bashrc = home / ".bashrc"
        bashrc.write_text("# user\n", encoding="utf-8")
        foreign = home / ".local" / "bin" / "git"
        foreign.write_text("foreign", encoding="utf-8")

        proc = _run(
            [venv.cli, "--wrapper-integration", "install"],
            env=_env(home, os.pathsep.join([str(venv.bin), "/usr/bin", "/bin"])),
            cwd=tmp_path,
        )

        assert proc.returncode != 0, proc.stdout
        assert "Refusing to install" in proc.stdout + proc.stderr
        assert foreign.read_text(encoding="utf-8") == "foreign"
        assert not (home / ".bashrc.linuxsecmonitor.bak").exists()
        assert MARKER_START not in bashrc.read_text(encoding="utf-8")
        assert MARKER_END not in bashrc.read_text(encoding="utf-8")
        assert not list((home / ".local" / "bin").glob("lsmonitor-*"))

    def test_foreign_lsmonitor_named_shim_is_not_overwritten(self, venv, tmp_path):
        home = tmp_path / "home-shim-conflict"
        wrapper_dir = home / ".local" / "bin"
        wrapper_dir.mkdir(parents=True)
        bashrc = home / ".bashrc"
        bashrc.write_text("# user\n", encoding="utf-8")
        foreign = wrapper_dir / "lsmonitor-git"
        foreign.write_text(
            "#!/bin/sh\n# LinuxSecMonitor managed wrapper v1\n"
            "echo foreign shim\n",
            encoding="utf-8",
        )

        proc = _run(
            [venv.cli, "--wrapper-integration", "install"],
            env=_env(home, os.pathsep.join([str(venv.bin), "/usr/bin", "/bin"])),
            cwd=tmp_path,
        )

        assert proc.returncode != 0, proc.stdout + proc.stderr
        assert "not a verified LinuxSecMonitor shim" in proc.stdout + proc.stderr
        assert foreign.read_text(encoding="utf-8").endswith("echo foreign shim\n")
        assert not (wrapper_dir / "git").exists()
        assert bashrc.read_text(encoding="utf-8") == "# user\n"
        assert not (home / ".bashrc.linuxsecmonitor.bak").exists()


class TestBackupAndRestore:
    """Scenario g: pristine backup on install, user RC restored on uninstall."""

    def test_backup_matches_preinstall_rc_and_uninstall_restores_user_content(
        self, venv, tmp_path,
    ):
        home = tmp_path / "home-backup"
        home.mkdir()
        original = "# user profile\nexport EDITOR=vim\nalias ll='ls -l'\n"
        bashrc = home / ".bashrc"
        bashrc.write_text(original, encoding="utf-8")
        env = _env(home, os.pathsep.join([str(venv.bin), "/usr/bin", "/bin"]))

        install = _run([venv.cli, "--wrapper-integration", "install"], env=env, cwd=tmp_path)
        assert install.returncode == 0, install.stdout + install.stderr

        backup = home / ".bashrc.linuxsecmonitor.bak"
        assert backup.read_bytes() == original.encode("utf-8")

        uninstall = _run(
            [venv.cli, "--wrapper-integration", "uninstall"], env=env, cwd=tmp_path,
        )
        assert uninstall.returncode == 0, uninstall.stdout + uninstall.stderr

        final = bashrc.read_text(encoding="utf-8")
        assert MARKER_START not in final
        assert MARKER_END not in final
        assert "# user profile" in final
        assert "export EDITOR=vim" in final
        assert "alias ll='ls -l'" in final
        # The pristine backup itself is never consumed or rewritten.
        assert backup.read_bytes() == original.encode("utf-8")


class TestUninstallLifecycle:
    """Scenario h: owned files removed, foreign files retained and reported."""

    def test_uninstall_removes_owned_files_retains_foreign_and_restores_git(
        self, installed, venv,
    ):
        assert installed.install.returncode == 0, installed.install.stdout
        wrapper_dir = installed.wrapper_dir
        foreign = wrapper_dir / "custom-tool"
        foreign.write_text("keep me\n", encoding="utf-8")

        proc = _run(
            [venv.cli, "--wrapper-integration", "uninstall"],
            env=_env(installed.home, os.pathsep.join([str(venv.bin), "/usr/bin", "/bin"])),
            cwd=installed.home,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Left in place" in proc.stdout
        assert str(foreign) in proc.stdout

        # Only the foreign file survives; everything owned is gone.
        files, _dirs = _walk_home(installed.home)
        assert not any(rel.name.startswith("lsmonitor-") for rel in files), files
        assert not (wrapper_dir / "git").exists()
        assert wrapper_dir.is_dir()  # foreign file keeps the directory alive
        assert foreign.read_text(encoding="utf-8") == "keep me\n"

        bashrc_text = installed.bashrc.read_text(encoding="utf-8")
        assert MARKER_START not in bashrc_text
        assert MARKER_END not in bashrc_text

        which = _run(
            ["/bin/bash", "-ic", "command -v git"],
            env=_env(installed.home, SYSTEM_PATH),
            cwd=installed.home,
            timeout=30,
        )
        assert which.returncode == 0, which.stderr
        resolved = [line for line in which.stdout.splitlines() if line.strip()]
        assert resolved, which.stdout
        assert resolved[-1] == "/usr/bin/git", resolved

    def test_uninstall_retains_unverified_lsmonitor_named_files(self, venv, tmp_path):
        home = tmp_path / "home-uninstall-foreign"
        wrapper_dir = home / ".local" / "bin"
        wrapper_dir.mkdir(parents=True)
        foreign_shim = wrapper_dir / "lsmonitor-git"
        foreign_shim.write_text(
            "#!/bin/sh\n# LinuxSecMonitor managed wrapper v1\n"
            "echo foreign shim\n",
            encoding="utf-8",
        )
        foreign_link = wrapper_dir / "git"
        foreign_link.symlink_to("lsmonitor-git")
        bashrc = home / ".bashrc"
        bashrc.write_text("# user\n", encoding="utf-8")

        proc = _run(
            [venv.cli, "--wrapper-integration", "uninstall"],
            env=_env(home, os.pathsep.join([str(venv.bin), "/usr/bin", "/bin"])),
            cwd=tmp_path,
        )

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert foreign_shim.read_text(encoding="utf-8").endswith("echo foreign shim\n")
        assert foreign_link.is_symlink()
        assert str(foreign_shim) in proc.stdout
        assert str(foreign_link) in proc.stdout
        assert bashrc.read_text(encoding="utf-8") == "# user\n"


class TestBrokenPackageFailsClosed:
    """Scenario i: broken/missing package fails closed in shim and CLI."""

    def test_broken_package_shim_and_cli_fail_closed(self, venv, tmp_path):
        home = tmp_path / "home-broken"
        home.mkdir()
        env = _env(home, os.pathsep.join([str(venv.bin), "/usr/bin", "/bin"]))

        install = _run([venv.cli, "--wrapper-integration", "install"], env=env, cwd=tmp_path)
        assert install.returncode == 0, install.stdout + install.stderr
        shim = home / ".local" / "bin" / "git"

        src_package = venv.site_packages / "src"
        assert src_package.is_dir(), src_package
        renamed = src_package.with_name("src.disabled")
        src_package.rename(renamed)
        try:
            # Shim path: broken package -> 127 with recovery, never real git.
            proc = _run(
                [shim, "--version"],
                env=_env(home, SYSTEM_PATH),
                cwd=tmp_path,
                timeout=30,
            )
            assert proc.returncode == 127, proc.stdout + proc.stderr
            assert "Recovery:" in proc.stderr, proc.stderr
            assert "never falls back" in proc.stderr, proc.stderr
            assert "git version" not in proc.stdout + proc.stderr

            # CLI path: missing package -> exit 1 with recovery text.
            cli = _run(
                [venv.cli, "--wrapper-integration", "status"],
                env=env,
                cwd=tmp_path,
                timeout=30,
            )
            assert cli.returncode == 1, cli.stdout + cli.stderr
            assert "Recovery" in cli.stderr, cli.stderr
            assert "Traceback" not in cli.stderr, cli.stderr
        finally:
            renamed.rename(src_package)
