"""Opt-in real APT transactions; run only inside a disposable Debian/Ubuntu guest.

Run one scenario per fresh guest snapshot with
LINUXSECMONITOR_RUN_REAL_APT=1,
LINUXSECMONITOR_REAL_APT_SCENARIO=safe-approve|finding-cancel|finding-approve|incomplete-block|lifecycle,
LINUXSECMONITOR_SYSTEM_CLI=/root-owned/runtime/bin/linuxsecmonitor, and
LINUXSECMONITOR_APT_EVIDENCE_DIR=/root-owned/evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import pty
import re
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.real_apt

_APT = Path("/usr/bin/apt-get")
_APT_CONFIG = Path("/usr/bin/apt-config")
_DPKG = Path("/usr/bin/dpkg")
_DPKG_DEB = Path("/usr/bin/dpkg-deb")
_DPKG_QUERY = Path("/usr/bin/dpkg-query")
_STRACE = Path("/usr/bin/strace")
_DISPOSABLE_MARKER = Path("/run/linuxsecmonitor-disposable-apt-test")
_APT_PROMPT = b"Type exactly INSTALL to continue;"
_MAX_TERMINAL_OUTPUT = 2 * 1024 * 1024
_TRANSACTION_TIMEOUT = 180


class _AptHarnessTimeout(TimeoutError):
    def __init__(self, output: bytes):
        super().__init__(f"APT transaction exceeded {_TRANSACTION_TIMEOUT} seconds")
        self.output = output


def _enabled_for(scenario: str) -> bool:
    return (
        os.environ.get("LINUXSECMONITOR_RUN_REAL_APT") == "1"
        and os.environ.get("LINUXSECMONITOR_REAL_APT_SCENARIO") == scenario
    )


def _guest_preflight(scenario: str) -> tuple[Path, Path, dict[str, str]]:
    if os.environ.get("LINUXSECMONITOR_RUN_REAL_APT") != "1":
        pytest.skip("Real APT tests require explicit disposable-guest opt-in")
    selected = os.environ.get("LINUXSECMONITOR_REAL_APT_SCENARIO")
    if selected != scenario:
        pytest.skip(f"Run this scenario in its own fresh guest; selected scenario is {selected!r}")
    if os.name != "posix" or os.geteuid() != 0:
        pytest.fail("Real APT integration tests require root inside the disposable guest")
    if os.environ.get("APT_CONFIG"):
        pytest.fail("Unset APT_CONFIG; custom configuration can reorder or bypass the tested hook")
    try:
        marker_info = _DISPOSABLE_MARKER.lstat()
        marker_valid = (
            stat.S_ISREG(marker_info.st_mode)
            and marker_info.st_uid == 0
            and not marker_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            and _DISPOSABLE_MARKER.read_text(encoding="ascii").strip()
            == "linuxsecmonitor-disposable-apt-guest-v1"
        )
    except (OSError, UnicodeError):
        marker_valid = False
    if not marker_valid:
        pytest.fail(
            f"Missing root-owned disposable guest marker {_DISPOSABLE_MARKER}; "
            "refusing to change package state"
        )

    release = _read_os_release()
    if release.get("ID", "").lower() not in {"debian", "ubuntu"}:
        pytest.fail("Real APT integration tests support Debian/Ubuntu disposable guests only")
    required_commands = [_APT_CONFIG, _DPKG_QUERY]
    if scenario != "lifecycle":
        required_commands.extend((_APT, _DPKG, _DPKG_DEB, _DPKG_QUERY, _STRACE))
    for command in required_commands:
        if not command.is_file() or not os.access(command, os.X_OK):
            pytest.fail(f"Required guest command is unavailable: {command}")
    if scenario != "lifecycle" and not shutil.which("clamscan", path="/usr/sbin:/usr/bin:/sbin:/bin"):
        pytest.fail("ClamAV clamscan is unavailable; refusing to bypass scanning")

    cli_text = os.environ.get("LINUXSECMONITOR_SYSTEM_CLI", "")
    if not cli_text:
        pytest.fail("Set LINUXSECMONITOR_SYSTEM_CLI to the trusted installed CLI")
    cli = Path(cli_text)
    try:
        resolved_cli = cli.resolve(strict=True)
        cli_stat = resolved_cli.stat()
    except (OSError, RuntimeError):
        pytest.fail("The configured LinuxSecMonitor CLI cannot be resolved")
    if not resolved_cli.is_file() or cli_stat.st_uid != 0 or cli_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        pytest.fail("LinuxSecMonitor CLI must be a root-owned, non-group/world-writable regular file")

    evidence_text = os.environ.get("LINUXSECMONITOR_APT_EVIDENCE_DIR", "")
    if not evidence_text:
        pytest.fail("Set LINUXSECMONITOR_APT_EVIDENCE_DIR to a pre-created root-only directory")
    evidence_dir = Path(evidence_text)
    try:
        evidence_info = evidence_dir.lstat()
    except OSError:
        pytest.fail("The APT evidence directory must exist before the test starts")
    if (
        not stat.S_ISDIR(evidence_info.st_mode)
        or evidence_info.st_uid != 0
        or evidence_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        pytest.fail("The APT evidence directory must be a root-owned private directory")
    return resolved_cli, evidence_dir, release


def _read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"ID", "PRETTY_NAME", "VERSION_ID"}:
                values[key] = value.strip().strip("\"'")
    except (OSError, UnicodeError):
        pass
    return values


def _clean_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("APT_CONFIG", None)
    environment.pop("DEBIAN_FRONTEND", None)
    environment.update({"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    return environment


def _run(command: list[str], *, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, capture_output=True, text=True, timeout=timeout,
        check=False, env=_clean_environment(),
    )


def _package_state() -> dict[str, str]:
    result = _run([
        str(_DPKG_QUERY), "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n",
    ])
    if result.returncode != 0:
        raise RuntimeError(f"Could not capture dpkg package state: {result.stderr[-1000:]}")
    rows: dict[str, str] = {}
    for line in result.stdout.splitlines():
        name, separator, state = line.partition("\t")
        if separator:
            rows[name] = state
    return rows


def _apt_configuration_digest() -> str:
    root = Path("/etc/apt/apt.conf.d")
    digest = hashlib.sha256()
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path.name == "00linuxsecmonitor":
            continue
        metadata = path.lstat()
        digest.update(path.name.encode("utf-8", "surrogateescape"))
        digest.update(
            f"{stat.S_IFMT(metadata.st_mode)}:{stat.S_IMODE(metadata.st_mode)}:"
            f"{metadata.st_uid}:{metadata.st_gid}".encode("ascii")
        )
        if stat.S_ISREG(metadata.st_mode):
            digest.update(path.read_bytes())
        elif stat.S_ISLNK(metadata.st_mode):
            digest.update(os.readlink(path).encode("utf-8", "surrogateescape"))
    return digest.hexdigest()


def _preinstall_hooks() -> list[str]:
    result = _run([str(_APT_CONFIG), "dump"])
    if result.returncode != 0:
        raise RuntimeError(f"apt-config dump failed: {result.stderr[-1000:]}")
    return [
        line.split('"', 2)[1]
        for line in result.stdout.splitlines()
        if line.startswith("DPkg::Pre-Install-Pkgs:: ") and line.count('"') >= 2
    ]


def _hook_is_first(cli: Path) -> bool:
    hooks = _preinstall_hooks()
    return bool(hooks and "--apt-preinstall-hook" in hooks[0])


def _osv_hook_prerequisites() -> None:
    config = _run([str(_APT_CONFIG), "dump"])
    if config.returncode != 0:
        raise RuntimeError(f"apt-config dump failed: {config.stderr[-1000:]}")
    if any("DPkg::Pre-Invoke::" in line for line in config.stdout.splitlines()):
        raise RuntimeError("A DPkg::Pre-Invoke hook is configured; review it before this transaction test")


def _build_fixture(
    root: Path, package_name: str, *, with_finding: bool, with_incomplete_content: bool = False,
) -> tuple[Path, Path, Path]:
    package_root = root / "pkg"
    control = package_root / "DEBIAN"
    payload = package_root / "usr/share/doc" / package_name
    control.mkdir(parents=True)
    payload.mkdir(parents=True)
    (control / "control").write_text(
        f"Package: {package_name}\nVersion: 0.0.1\nArchitecture: all\n"
        "Maintainer: LinuxSecMonitor disposable test\n"
        "Description: harmless local APT integration fixture\n",
        encoding="utf-8",
    )
    (payload / "README").write_text("Harmless local integration fixture.\n", encoding="utf-8")
    postinst_marker = root / "postinst-ran"
    cron_marker = Path("/etc/cron.d") / f"linuxsecmonitor-e2e-{package_name.removeprefix('linuxsecmonitor-e2e-')}"
    if with_finding:
        script = (
            "#!/bin/sh\nset -eu\n"
            f"printf '%s\\n' 'ran' > '{postinst_marker}'\n"
            f"printf '%s\\n' '# inert LinuxSecMonitor integration marker' > '{cron_marker}'\n"
        )
        (control / "postinst").write_text(script, encoding="utf-8")
        (control / "postinst").chmod(0o755)
    if with_incomplete_content:
        # The target stays inside this package; a faulty install cannot alter
        # unrelated host data through the fixture's symlink.
        (payload / "readme-link").symlink_to("README")
    package = root / f"{package_name}_0.0.1_all.deb"
    built = _run([str(_DPKG_DEB), "--build", str(package_root), str(package)], timeout=30)
    if built.returncode != 0:
        raise RuntimeError(f"dpkg-deb fixture build failed: {built.stderr[-1000:]}")
    package.chmod(0o644)
    return package, postinst_marker, cron_marker


def _run_apt_with_decision(
    package: Path, trace: Path, decision: str | None,
) -> tuple[int, bytes, bool, bool]:
    command = [
        str(_STRACE), "-f", "-qq", "-e", "trace=execve", "-o", str(trace), "--",
        str(_APT), "-y", "--no-download", "--no-remove", "install", str(package),
    ]
    pid, terminal_fd = pty.fork()
    if pid == 0:
        os.umask(0o077)
        os.execve(command[0], command, _clean_environment())
    output = bytearray()
    decision_sent = False
    deadline = time.monotonic() + _TRANSACTION_TIMEOUT
    child_status: int | None = None
    try:
        while child_status is None:
            if time.monotonic() >= deadline:
                raise _AptHarnessTimeout(bytes(output))
            ready, _, _ = select.select([terminal_fd], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(terminal_fd, 8192)
                except OSError:
                    chunk = b""
                if chunk:
                    output.extend(chunk)
                    if len(output) > _MAX_TERMINAL_OUTPUT:
                        raise RuntimeError("APT terminal output exceeded its evidence size limit")
                    if decision is not None and not decision_sent and _APT_PROMPT in output:
                        os.write(terminal_fd, decision.encode("ascii") + b"\n")
                        decision_sent = True
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                child_status = status
        return os.waitstatus_to_exitcode(child_status), bytes(output), decision_sent, False
    except BaseException:
        try:
            os.killpg(pid, signal.SIGKILL)
        except OSError:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        raise
    finally:
        os.close(terminal_fd)


def _installed(package_name: str) -> bool:
    result = _run([str(_DPKG_QUERY), "-W", "-f=${db:Status-Abbrev}", package_name])
    return result.returncode == 0 and result.stdout.strip().startswith("ii")


def _write_evidence(evidence_dir: Path, base: str, report: dict[str, object], output: bytes, trace: Path) -> None:
    log_path = evidence_dir / f"{base}.apt.log"
    json_path = evidence_dir / f"{base}.json"
    trace_path = evidence_dir / f"{base}.execve.log"
    for target in (log_path, json_path, trace_path):
        if target.exists() or target.is_symlink():
            raise RuntimeError(f"Evidence file already exists; refusing overwrite: {target}")
    for target, data in ((log_path, output), (trace_path, trace.read_bytes())):
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
    descriptor = os.open(json_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _transaction_test(
    scenario: str, *, with_finding: bool, decision: str | None,
    with_incomplete_content: bool = False,
) -> None:
    cli, evidence_dir, release = _guest_preflight(scenario)
    if not _APT_CONFIG.is_file() or not _DPKG_DEB.is_file():
        pytest.fail("APT integration prerequisites are missing")
    _osv_hook_prerequisites()
    initial_status = _run([str(cli), "--apt-integration", "status", "--json"])
    if initial_status.returncode != 0 or json.loads(initial_status.stdout).get("status") != "not_installed":
        pytest.fail("Fresh integration test requires no prior LinuxSecMonitor lifecycle state")

    package_name = f"linuxsecmonitor-e2e-{uuid.uuid4().hex[:12]}"
    evidence_name = f"apt-{scenario}-{package_name}"
    root = Path(tempfile.mkdtemp(prefix="linuxsecmonitor-e2e-", dir="/var/tmp"))
    root.chmod(0o755)
    lifecycle: list[str] = []
    transaction_output = b""
    trace = root / "execve.raw"
    apt_exit: int | None = None
    decision_sent = False
    after_packages: dict[str, str] = {}
    marker_contents: dict[str, str | None] = {}
    cleanup_errors: list[str] = []
    timed_out = False
    package: Path | None = None
    postinst_marker = root / "postinst-ran"
    cron_marker = Path("/etc/cron.d") / f"linuxsecmonitor-e2e-{package_name.removeprefix('linuxsecmonitor-e2e-')}"
    initial_packages: dict[str, str] = {}
    initial_config = ""
    try:
        package, postinst_marker, cron_marker = _build_fixture(
            root, package_name, with_finding=with_finding,
            with_incomplete_content=with_incomplete_content,
        )
        if postinst_marker.exists() or cron_marker.exists():
            raise AssertionError("Fixture maintainer-script markers existed before the transaction")
        initial_packages = _package_state()
        initial_config = _apt_configuration_digest()
        trace_fd = os.open(
            trace,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(trace_fd)
        for action, expected in (("install", "enabled"), ("disable", "disabled"), ("enable", "enabled")):
            operation = _run([str(cli), "--apt-integration", action, "--json"])
            if operation.returncode != 0:
                raise RuntimeError(f"Lifecycle {action} failed: {operation.stderr[-1000:]}")
            observed = json.loads(operation.stdout).get("status")
            lifecycle.append(f"{action}:{observed}")
            if observed != expected:
                raise RuntimeError(f"Lifecycle {action} returned unexpected status {observed!r}")
        if not _hook_is_first(cli):
            raise RuntimeError("Installed LinuxSecMonitor hook is not first in effective APT order")

        apt_version = _run([str(_APT), "--version"]).stdout.splitlines()[0]
        try:
            apt_exit, transaction_output, decision_sent, timed_out = _run_apt_with_decision(
                package, trace, decision,
            )
        except _AptHarnessTimeout as exc:
            apt_exit, transaction_output, decision_sent, timed_out = 124, exc.output, False, True
        after_packages = _package_state()
        marker_contents = {
            "postinst": postinst_marker.read_text(encoding="utf-8").strip() if postinst_marker.is_file() else None,
            "cron": cron_marker.read_text(encoding="utf-8").strip() if cron_marker.is_file() else None,
        }
        output_text = transaction_output.decode("utf-8", "replace")
        report = {
            "scenario": scenario,
            "distribution": release.get("PRETTY_NAME", release.get("ID", "unknown")),
            "distribution_version": release.get("VERSION_ID"),
            "apt_version": apt_version,
            "package_name": package_name,
            "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
            "hook_first_before_transaction": True,
            "lifecycle_operations": lifecycle,
            "decision_sent": decision_sent,
            "apt_exit_status": apt_exit,
            "apt_timed_out": timed_out,
            "package_state_before": initial_packages.get(package_name, "absent"),
            "package_state_after": after_packages.get(package_name, "absent"),
            "package_state_changes": sorted(
                key for key in initial_packages.keys() | after_packages.keys()
                if initial_packages.get(key) != after_packages.get(key)
            ),
            "maintainer_script_markers": marker_contents,
            "hook_report_displayed": "APT Pre-Install-Pkgs protocol version 3 accepted." in output_text,
            "review_finding_displayed": "startup-persistence-write" in output_text,
            "scan_complete": "Coverage complete: yes" in output_text,
            "scan_incomplete": "Coverage complete: no" in output_text,
            "incomplete_block_displayed": "at least one archive had incomplete coverage" in output_text,
            "real_clamav_backend": "Scanner: dpkg-deb + ClamAV clamscan" in output_text,
            "no_detection_status": "Status: no_detection" in output_text,
            "approval_received": "Explicit INSTALL approval received; APT may continue." in output_text,
            "initial_package_state_digest": hashlib.sha256(
                "\n".join(f"{key}\t{value}" for key, value in sorted(initial_packages.items())).encode()
            ).hexdigest(),
            "apt_config_digest_before": initial_config,
        }
        _write_evidence(evidence_dir, evidence_name, report, transaction_output, trace)

        if with_incomplete_content:
            if decision_sent or apt_exit == 0 or not report["hook_report_displayed"]:
                raise AssertionError("APT did not fail closed on incomplete package inspection")
            if not report["scan_incomplete"] or not report["incomplete_block_displayed"]:
                raise AssertionError("APT did not visibly report incomplete scan coverage")
            if _installed(package_name) or after_packages != initial_packages:
                raise AssertionError("The incomplete scan transaction changed package state")
            if any(marker_contents.values()):
                raise AssertionError("A maintainer script ran after incomplete coverage")
            trace_text = trace.read_text(encoding="utf-8", errors="replace")
            if "dpkg-preconfigure" in trace_text or re.search(
                r'execve\("[^\"]*/dpkg", .*"(?:--unpack|--configure|--install|--remove|--purge)"',
                trace_text,
            ):
                raise AssertionError("dpkg ran after the hook rejected incomplete coverage")
        else:
            if not decision_sent or not report["hook_report_displayed"]:
                raise AssertionError("The actual APT hook did not display its v3 review prompt")
            if (
                not report["scan_complete"]
                or not report["real_clamav_backend"]
                or not report["no_detection_status"]
            ):
                raise AssertionError("APT did not report a complete real ClamAV scan")
            if "Transaction vulnerability assessment:" not in output_text:
                raise AssertionError("APT did not display the transaction vulnerability assessment")
            if with_finding and not report["review_finding_displayed"]:
                raise AssertionError("The expected maintainer-script review lead was not displayed")
        if decision == "CANCEL" and not with_incomplete_content:
            if apt_exit == 0 or _installed(package_name):
                raise AssertionError("APT did not honor cancellation")
            if any(marker_contents.values()):
                raise AssertionError("A maintainer-script marker appeared after cancellation")
            if after_packages != initial_packages:
                raise AssertionError("Package database changed during the cancelled transaction")
            if "explicit terminal approval was not received." not in output_text:
                raise AssertionError("Cancellation was not reported by the hook")
            if "dpkg-preconfigure" in trace.read_text(encoding="utf-8", errors="replace"):
                raise AssertionError("dpkg-preconfigure ran after the cancelled review")
            if re.search(
                r'execve\("[^"]*/dpkg", .*"(?:--unpack|--configure|--install|--remove|--purge)"',
                trace.read_text(encoding="utf-8", errors="replace"),
            ):
                raise AssertionError("dpkg package processing ran after cancellation")
        elif decision == "INSTALL" and not with_incomplete_content:
            if apt_exit != 0 or not _installed(package_name):
                raise AssertionError("APT did not complete the explicitly approved installation")
            installed_path = Path("/usr/share/doc") / package_name / "README"
            if not installed_path.is_file():
                raise AssertionError("Expected package payload is absent after approval")
            if with_finding and marker_contents != {
                "postinst": "ran", "cron": "# inert LinuxSecMonitor integration marker",
            }:
                raise AssertionError("Expected maintainer-script markers are absent after approval")
            if not report["approval_received"]:
                raise AssertionError("Hook did not record exact INSTALL approval")
            if not with_finding and any(marker_contents.values()):
                raise AssertionError("A package without maintainer scripts created a script marker")
            changes = report["package_state_changes"]
            if changes != [package_name]:
                raise AssertionError(f"Unexpected package database changes: {changes}")
            trace_text = trace.read_text(encoding="utf-8", errors="replace")
            hook_index = trace_text.find("--apt-preinstall-hook")
            preconfigure_index = trace_text.find("dpkg-preconfigure")
            if hook_index < 0 or (preconfigure_index >= 0 and preconfigure_index < hook_index):
                raise AssertionError("APT did not execute the managed hook before preconfigure")
            if with_finding and f"/var/lib/dpkg/info/{package_name}.postinst" not in trace_text:
                raise AssertionError("Execution trace does not show the approved postinst")
        elif not with_incomplete_content:
            raise AssertionError("Unexpected decision state for a completed APT scenario")
    finally:
        # Remove only the uniquely named test package and exact marker created
        # by this harness. Package removal is cleanup after evidence capture;
        # the tested install still travels through APT and the managed hook.
        try:
            if _installed(package_name):
                purge = _run([str(_DPKG), "--purge", package_name], timeout=30)
                if purge.returncode != 0:
                    cleanup_errors.append(f"dpkg purge failed: {purge.stderr[-500:]}")
            if cron_marker.exists() and not cron_marker.is_symlink():
                expected = b"# inert LinuxSecMonitor integration marker\n"
                if cron_marker.read_bytes() == expected and cron_marker.stat().st_uid == 0:
                    cron_marker.unlink()
                else:
                    cleanup_errors.append(f"Preserved unexpected cron marker: {cron_marker}")
            state = _run([str(cli), "--apt-integration", "status", "--json"])
            if state.returncode == 0 and json.loads(state.stdout).get("status") in {"enabled", "disabled"}:
                removed = _run([str(cli), "--apt-integration", "uninstall", "--json"])
                if removed.returncode != 0:
                    cleanup_errors.append(f"Lifecycle uninstall failed: {removed.stderr[-500:]}")
        except Exception as exc:
            cleanup_errors.append(f"Harness cleanup raised {type(exc).__name__}")
        shutil.rmtree(root, ignore_errors=False)

    if cleanup_errors:
        pytest.fail("Disposable guest cleanup requires attention: " + "; ".join(cleanup_errors))
    if _apt_configuration_digest() != initial_config:
        pytest.fail("APT drop-ins differ from the pre-test snapshot after lifecycle uninstall")
    if _package_state() != initial_packages:
        pytest.fail("dpkg package state differs from its pre-test snapshot after fixture cleanup")


@pytest.mark.skipif(not _enabled_for("safe-approve"), reason="Select safe-approve in a fresh disposable guest")
def test_real_apt_safe_package_approval():
    _transaction_test("safe-approve", with_finding=False, decision="INSTALL")


@pytest.mark.skipif(not _enabled_for("finding-cancel"), reason="Select finding-cancel in a fresh disposable guest")
def test_real_apt_finding_cancellation_prevents_package_scripts():
    _transaction_test("finding-cancel", with_finding=True, decision="CANCEL")


@pytest.mark.skipif(not _enabled_for("finding-approve"), reason="Select finding-approve in a fresh disposable guest")
def test_real_apt_finding_approval_runs_only_approved_script():
    _transaction_test("finding-approve", with_finding=True, decision="INSTALL")


@pytest.mark.skipif(not _enabled_for("incomplete-block"), reason="Select incomplete-block in a fresh guest")
def test_real_apt_incomplete_coverage_blocks_without_scripts():
    _transaction_test(
        "incomplete-block", with_finding=True, decision=None,
        with_incomplete_content=True,
    )


@pytest.mark.skipif(not _enabled_for("lifecycle"), reason="Select lifecycle in a fresh guest")
def test_real_lifecycle_recovery_and_preservation():
    cli, evidence_dir, release = _guest_preflight("lifecycle")
    apt_before = _apt_configuration_digest()
    packages_before = _package_state() if _DPKG_QUERY.exists() else {}
    status = _run([str(cli), "--apt-integration", "status", "--json"])
    if status.returncode != 0 or json.loads(status.stdout).get("status") != "not_installed":
        pytest.fail("Lifecycle test requires a fresh guest with no existing integration")

    events: list[dict[str, object]] = []
    cleanup_errors: list[str] = []
    conflict_path = Path("/etc/apt/apt.conf.d/00linuxsecmonitor")
    conflict_payload = b"// disposable lifecycle conflict fixture\n"
    conflict_identity: tuple[int, int] | None = None

    def action(name: str, expected: str) -> None:
        completed = _run([str(cli), "--apt-integration", name, "--json"])
        event: dict[str, object] = {
            "action": name, "exit_status": completed.returncode,
            "stdout": completed.stdout[-2000:], "stderr": completed.stderr[-2000:],
        }
        if completed.returncode != 0:
            raise AssertionError(f"Lifecycle {name} failed: {completed.stderr[-1000:]}")
        observed = json.loads(completed.stdout).get("status")
        event["status"] = observed
        events.append(event)
        if observed != expected:
            raise AssertionError(f"Lifecycle {name} returned {observed!r}; expected {expected!r}")

    report: dict[str, object] = {}
    try:
        conflict_fd = os.open(
            conflict_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        conflict_stat = os.fstat(conflict_fd)
        conflict_identity = (conflict_stat.st_dev, conflict_stat.st_ino)
        with os.fdopen(conflict_fd, "wb") as stream:
            stream.write(conflict_payload)
            stream.flush()
            os.fsync(stream.fileno())
        refused = _run([str(cli), "--apt-integration", "install", "--json"])
        conflict_event = {
            "action": "install-conflicting-file",
            "exit_status": refused.returncode,
            "stderr": refused.stderr[-1000:],
            "preserved": conflict_path.read_bytes() == conflict_payload,
        }
        events.append(conflict_event)
        if refused.returncode == 0 or conflict_event["preserved"] is not True:
            raise AssertionError("Install did not refuse/preserve the pre-existing hook path")
        current_conflict = conflict_path.lstat()
        if (current_conflict.st_dev, current_conflict.st_ino) != conflict_identity:
            raise AssertionError("The pre-existing hook fixture identity changed")
        conflict_path.unlink()
        conflict_identity = None

        action("install", "enabled")
        action("install", "enabled")
        hook = Path("/etc/apt/apt.conf.d/00linuxsecmonitor")
        receipt = Path("/var/lib/linuxsecmonitor/apt-integration.json")
        for path, mode in ((hook, 0o644), (receipt, 0o600)):
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
                raise AssertionError(f"Lifecycle file has unexpected type/owner: {path}")
            if stat.S_IMODE(metadata.st_mode) != mode:
                raise AssertionError(f"Lifecycle file has unexpected mode: {path}")
        action("disable", "disabled")
        action("disable", "disabled")
        # A receipt without its hook is the recoverable interrupted-setup state.
        action("enable", "enabled")
        action("enable", "enabled")
        action("disable", "disabled")
        action("enable", "enabled")
        action("uninstall", "not_installed")
        action("uninstall", "not_installed")
    except Exception as exc:
        events.append({"failure": f"{type(exc).__name__}: {exc}"})
        raise
    finally:
        if conflict_identity is not None:
            try:
                current_conflict = conflict_path.lstat()
                if (
                    (current_conflict.st_dev, current_conflict.st_ino) == conflict_identity
                    and conflict_path.read_bytes() == conflict_payload
                ):
                    conflict_path.unlink()
                else:
                    cleanup_errors.append(f"Preserved unexpected hook-path replacement: {conflict_path}")
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_errors.append(f"Could not clean the exact conflict fixture: {type(exc).__name__}")
        current = _run([str(cli), "--apt-integration", "status", "--json"])
        try:
            current_status = json.loads(current.stdout).get("status") if current.returncode == 0 else "unknown"
            if current_status in {"enabled", "disabled"}:
                removed = _run([str(cli), "--apt-integration", "uninstall", "--json"])
                if removed.returncode != 0:
                    cleanup_errors.append(f"Lifecycle cleanup failed: {removed.stderr[-1000:]}")
        except (json.JSONDecodeError, OSError) as exc:
            cleanup_errors.append(f"Lifecycle cleanup status failed: {type(exc).__name__}")
        report = {
            "scenario": "lifecycle",
            "distribution": release.get("PRETTY_NAME"),
            "distribution_version": release.get("VERSION_ID"),
            "operations": events,
            "apt_config_digest_before": apt_before,
            "apt_config_digest_after": _apt_configuration_digest(),
            "package_state_unchanged": not packages_before or _package_state() == packages_before,
            "cleanup_errors": cleanup_errors,
        }
        target = evidence_dir / f"lifecycle-{uuid.uuid4().hex}.json"
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")

    if cleanup_errors:
        pytest.fail("Lifecycle cleanup requires attention: " + "; ".join(cleanup_errors))
    if report["apt_config_digest_before"] != report["apt_config_digest_after"]:
        pytest.fail("Lifecycle left an APT configuration change")
    if not report["package_state_unchanged"]:
        pytest.fail("Lifecycle test changed the package database")
