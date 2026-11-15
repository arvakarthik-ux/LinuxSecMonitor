#!/usr/bin/env python3
"""Run one approved real-APT scenario in a fresh, isolated Kali container."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any


IMAGE_ID = "sha256:2baea3e59a5708abb354e4ecaa2589d7c97022773bc2771c0ba7241a9dd117d1"
IMAGE_TAG = "lsm-apt-guest-kali:p2-revision3-eicar-crlf-20261113-2252"
TEST_SHA256 = "51c5ad69ea58a09ccc3af1de4e85780b6823eb4973b469f486110627db2cd4e8"
IMAGE_LABELS = {
    "local.lsm.base-image-id": "sha256:3b46d05ecf5ba77c77e45bb0c6c19039faea977f1c58e217730b693274b16f06",
    "local.lsm.parent-image-id": "sha256:e7fce9086f367e7825c859d3eb93ff16198602023da0a46844ef2820af745cf9",
    "local.lsm.source-context-sha256": "70ea093c61d7223fc94837dce0ca58f142e557a26260dcdb0c3be2547594ef3e",
    "local.lsm.source-revision": "72f16ca9154ba0f88489685254c28d8a521a579e",
    "local.lsm.source-state": "authorized-dirty-working-tree",
}
SCENARIOS = {
    "G1": ("finding-cancel", "cancellation"),
    "G2": ("incomplete-block", "incomplete_coverage_blocks"),
    "G3": ("finding-approve", "finding_approval"),
    "G4": ("safe-approve", "safe_package_approval"),
    "G5": ("lifecycle", "lifecycle_recovery"),
}
EVIDENCE_DIR = Path("/var/tmp/linuxsecmonitor-apt-evidence")
TEST_IN_GUEST = Path("/opt/linuxsecmonitor-source/tests/integration/test_apt_preinstall_guest.py")
CLI_IN_GUEST = "/opt/linuxsecmonitor/bin/linuxsecmonitor"
PYTHON_IN_GUEST = "/opt/linuxsecmonitor/bin/python"


class RunnerError(RuntimeError):
    pass


def _run(
    args: list[str], *, timeout: int = 30, allow_failure: bool = False
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RunnerError(f"Command timed out after {timeout}s: {args[0]}") from exc
    if result.returncode != 0 and not allow_failure:
        details = (result.stderr or result.stdout)[-4000:]
        raise RunnerError(f"Command failed ({result.returncode}): {args!r}\n{details}")
    return result


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _docker_json(args: list[str]) -> Any:
    result = _run(["docker", *args])
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RunnerError(f"Docker returned invalid JSON for {args!r}") from exc


def _image_metadata() -> dict[str, Any]:
    images = _docker_json(["image", "inspect", IMAGE_ID])
    if not isinstance(images, list) or len(images) != 1:
        raise RunnerError("The approved Kali image did not resolve to exactly one local image")
    image = images[0]
    labels = image.get("Config", {}).get("Labels") or {}
    if image.get("Id") != IMAGE_ID:
        raise RunnerError(f"Unexpected image id: {image.get('Id')!r}")
    if IMAGE_TAG not in image.get("RepoTags", []):
        raise RunnerError(f"The approved Kali image tag {IMAGE_TAG!r} is missing")
    mismatches = {
        key: {"expected": value, "actual": labels.get(key)}
        for key, value in IMAGE_LABELS.items()
        if labels.get(key) != value
    }
    if mismatches:
        raise RunnerError(f"Approved Kali image provenance mismatch: {mismatches}")
    return {
        "id": image["Id"],
        "repo_tags": image.get("RepoTags", []),
        "labels": {key: labels.get(key) for key in IMAGE_LABELS},
        "architecture": image.get("Architecture"),
        "os": image.get("Os"),
    }


def _parse_os_release(contents: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in contents.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value.strip().strip("\"'")
    if values.get("ID", "").lower() != "kali" or values.get("VERSION_ID") != "2026.3":
        raise RunnerError(
            "The guest must report Kali Rolling 2026.3; "
            f"observed ID={values.get('ID')!r}, VERSION_ID={values.get('VERSION_ID')!r}"
        )
    return {
        key: values.get(key, "")
        for key in ("ID", "PRETTY_NAME", "VERSION_ID")
    }


def _inspect_container(name: str) -> dict[str, Any]:
    inspected = _docker_json(["inspect", name])
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise RunnerError("Container inspection did not return exactly one record")
    item = inspected[0]
    host = item.get("HostConfig") or {}
    mounts = item.get("Mounts") or []
    networks = item.get("NetworkSettings", {}).get("Networks") or {}
    network_names = sorted(networks)
    observed = {
        "id": item.get("Id"),
        "image": item.get("Image"),
        "state": item.get("State", {}).get("Status"),
        "privileged": host.get("Privileged"),
        "network_mode": host.get("NetworkMode"),
        "networks": network_names,
        "binds": host.get("Binds") or [],
        "mounts": mounts,
        "devices": host.get("Devices") or [],
    }
    if observed["image"] != IMAGE_ID:
        raise RunnerError(f"Container used an unexpected image: {observed['image']!r}")
    if observed["privileged"] is not False:
        raise RunnerError("The guest container must not be privileged")
    if observed["network_mode"] != "bridge" or network_names != ["bridge"]:
        raise RunnerError(f"Unexpected container networking: {observed!r}")
    if observed["binds"] or observed["mounts"] or observed["devices"]:
        raise RunnerError(f"Guest container has a host mount or device: {observed!r}")
    return observed


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _guest_exec(name: str, *args: str, timeout: int = 30) -> str:
    return _run(["docker", "exec", name, *args], timeout=timeout).stdout


def _validate_report(gate_id: str, report: dict[str, Any]) -> None:
    scenario, _ = SCENARIOS[gate_id]
    if report.get("scenario") != scenario:
        raise RunnerError(f"Evidence scenario mismatch: {report.get('scenario')!r}")
    if gate_id == "G5":
        if (
            not str(report.get("distribution", "")).startswith("Kali")
            or report.get("distribution_version") != "2026.3"
        ):
            raise RunnerError("Lifecycle evidence is not from Kali")
    else:
        package_name = report.get("package_name")
        if not isinstance(package_name, str) or not re.fullmatch(
            r"linuxsecmonitor-e2e-[0-9a-f]{12}", package_name
        ):
            raise RunnerError("Scenario evidence has no valid fixture package identity")
        if not isinstance(report.get("distribution_id"), str) or report[
            "distribution_id"
        ].lower() != "kali":
            raise RunnerError("Scenario evidence is not from Kali")
        if report.get("distribution_version") != "2026.3":
            raise RunnerError("Scenario evidence does not report Kali 2026.3")
    markers = report.get("maintainer_script_markers", {})
    if not isinstance(markers, dict):
        raise RunnerError("Scenario evidence has invalid maintainer-script markers")

    if gate_id == "G1":
        valid = (
            report.get("apt_exit_status") == 100
            and report.get("decision_sent") is True
            and report.get("scan_complete") is True
            and report.get("real_clamav_backend") is True
            and report.get("detected_status_displayed") is True
            and any("eicar" in name.casefold() for name in report.get("eicar_signature_names", []))
            and report.get("package_state_after") == "absent"
            and report.get("package_state_changes") == []
            and all(value is None for value in markers.values())
            and report.get("kali_vulnerability_unsupported_displayed") is True
        )
    elif gate_id == "G2":
        valid = (
            report.get("apt_exit_status") == 100
            and report.get("decision_sent") is False
            and report.get("scan_incomplete") is True
            and report.get("incomplete_block_displayed") is True
            and report.get("package_state_after") == "absent"
            and report.get("package_state_changes") == []
            and all(value is None for value in markers.values())
        )
    elif gate_id == "G3":
        package_name = report.get("package_name")
        valid = (
            report.get("apt_exit_status") == 0
            and report.get("decision_sent") is True
            and report.get("approval_received") is True
            and report.get("scan_complete") is True
            and report.get("detected_status_displayed") is True
            and any("eicar" in name.casefold() for name in report.get("eicar_signature_names", []))
            and report.get("package_state_changes") == [package_name]
            and markers
            == {"postinst": "ran", "cron": "# inert LinuxSecMonitor integration marker"}
            and report.get("kali_vulnerability_unsupported_displayed") is True
        )
    elif gate_id == "G4":
        package_name = report.get("package_name")
        valid = (
            report.get("apt_exit_status") == 0
            and report.get("decision_sent") is True
            and report.get("approval_received") is True
            and report.get("scan_complete") is True
            and report.get("real_clamav_backend") is True
            and report.get("no_detection_status") is True
            and report.get("package_state_changes") == [package_name]
            and all(value is None for value in markers.values())
            and report.get("kali_vulnerability_unsupported_displayed") is True
        )
    else:
        operations = report.get("operations")
        expected = [
            ("install", "enabled"),
            ("install", "enabled"),
            ("disable", "disabled"),
            ("disable", "disabled"),
            ("enable", "enabled"),
            ("enable", "enabled"),
            ("disable", "disabled"),
            ("enable", "enabled"),
            ("uninstall", "not_installed"),
            ("uninstall", "not_installed"),
        ]
        valid = (
            isinstance(operations, list)
            and len(operations) == len(expected) + 1
            and operations[0].get("action") == "install-conflicting-file"
            and operations[0].get("exit_status") != 0
            and operations[0].get("preserved") is True
            and [
                (event.get("action"), event.get("status"))
                for event in operations[1:]
            ] == expected
            and report.get("cleanup_errors") == []
            and report.get("apt_config_digest_before") == report.get("apt_config_digest_after")
            and report.get("package_state_unchanged") is True
        )
    if not valid:
        raise RunnerError(f"{gate_id} guest evidence did not satisfy its required outcome")


def _collect_evidence(
    name: str, gate_id: str, destination: Path
) -> tuple[dict[str, Any], list[str]]:
    guest_evidence = destination / "guest-evidence"
    guest_evidence.mkdir(mode=0o700)
    result = _run(
        ["docker", "cp", f"{name}:{EVIDENCE_DIR}/.", str(guest_evidence)],
        timeout=60,
    )
    del result
    scenario, _ = SCENARIOS[gate_id]
    reports = sorted(guest_evidence.glob("*.json"))
    if gate_id == "G5":
        reports = [path for path in reports if path.name.startswith("lifecycle-")]
        expected_artifacts = 1
    else:
        reports = [path for path in reports if path.name.startswith(f"apt-{scenario}-")]
        expected_artifacts = 3
    if len(reports) != 1:
        raise RunnerError(f"Expected one JSON report for {gate_id}, found {len(reports)}")
    report_path = reports[0]
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError(f"Could not read scenario JSON evidence: {report_path}") from exc
    if not isinstance(report, dict):
        raise RunnerError("Scenario JSON evidence must be an object")
    _validate_report(gate_id, report)
    artifact_names = sorted(path.name for path in guest_evidence.iterdir() if path.is_file())
    if len(artifact_names) != expected_artifacts:
        raise RunnerError(f"Unexpected guest evidence files for {gate_id}: {artifact_names!r}")
    if gate_id != "G5" and not (
        report_path.with_suffix(".apt.log").is_file()
        and report_path.with_suffix(".execve.log").is_file()
    ):
        raise RunnerError(f"{gate_id} is missing its APT or execve log")
    return report, artifact_names


def run_scenario(gate_id: str) -> None:
    scenario, selector = SCENARIOS[gate_id]
    repo_root = Path(__file__).resolve().parents[2]
    source_test = repo_root / "tests/integration/test_apt_preinstall_guest.py"
    if _sha256(source_test) != TEST_SHA256:
        raise RunnerError("The checked-out guest test differs from the approved image provenance")
    image = _image_metadata()
    evidence_root = Path(
        tempfile.mkdtemp(prefix=f"linuxsecmonitor-{gate_id.lower()}-", dir="/tmp")
    )
    evidence_root.chmod(0o700)
    name = f"lsm-p2-{gate_id.lower()}-{uuid.uuid4().hex[:12]}"
    created = False
    container_id = ""
    inspection: dict[str, Any] | None = None
    guest_release: dict[str, str] | None = None
    pytest_output = ""
    test_returncode: int | None = None
    report: dict[str, Any] | None = None
    artifact_names: list[str] = []
    cleanup_error: str | None = None
    test_failure: str | None = None
    evidence_failure: str | None = None
    try:
        create = _run(
            [
                "docker", "create", "--name", name, "--network", "bridge",
                "--entrypoint", "/bin/sleep", IMAGE_ID, "infinity",
            ]
        )
        container_id = create.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RunnerError("Docker returned an invalid container id")
        created = True
        _write_json(evidence_root / "image-provenance.json", image)
        _run(["docker", "start", name])
        inspection = _inspect_container(name)
        _write_json(evidence_root / "container-before.json", inspection)
        docker_socket = _guest_exec(
            name, "/bin/sh", "-c", "test ! -e /var/run/docker.sock"
        )
        del docker_socket
        release_text = _guest_exec(name, "/bin/cat", "/etc/os-release")
        guest_release = _parse_os_release(release_text)
        (evidence_root / "os-release.txt").write_text(release_text, encoding="utf-8")
        test_hash = _guest_exec(
            name, "/usr/bin/sha256sum", str(TEST_IN_GUEST)
        ).split()[0]
        if test_hash != TEST_SHA256:
            raise RunnerError(f"Guest test source hash mismatch: {test_hash}")
        _guest_exec(
            name,
            "/bin/sh",
            "-eu",
            "-c",
            "install -d -o root -g root -m 0700 /var/tmp/linuxsecmonitor-apt-evidence; "
            "printf '%s\\n' linuxsecmonitor-disposable-apt-guest-v1 "
            "> /run/linuxsecmonitor-disposable-apt-test; "
            "chown root:root /run/linuxsecmonitor-disposable-apt-test; "
            "chmod 0644 /run/linuxsecmonitor-disposable-apt-test",
        )
        try:
            pytest = _run(
                [
                    "docker", "exec", "--user", "0",
                    "--env", "LINUXSECMONITOR_RUN_REAL_APT=1",
                    "--env", f"LINUXSECMONITOR_REAL_APT_SCENARIO={scenario}",
                    "--env", f"LINUXSECMONITOR_SYSTEM_CLI={CLI_IN_GUEST}",
                    "--env", f"LINUXSECMONITOR_APT_EVIDENCE_DIR={EVIDENCE_DIR}",
                    name, PYTHON_IN_GUEST, "-m", "pytest", "-q",
                    str(TEST_IN_GUEST), "-k", selector,
                ],
                timeout=240,
                allow_failure=True,
            )
            test_returncode = pytest.returncode
            pytest_output = (pytest.stdout + pytest.stderr)[-12000:]
            if test_returncode != 0:
                test_failure = (
                    f"{gate_id} guest pytest failed with exit {test_returncode}: "
                    f"{pytest_output[-4000:]}"
                )
        except RunnerError as exc:
            test_failure = str(exc)
        pytest_log = evidence_root / "pytest-output.txt"
        pytest_log.write_text(pytest_output, encoding="utf-8")
        pytest_log.chmod(0o600)
        try:
            report, artifact_names = _collect_evidence(name, gate_id, evidence_root)
        except RunnerError as exc:
            evidence_failure = str(exc)
        inspection = _inspect_container(name)
        _write_json(evidence_root / "container-after.json", inspection)
    finally:
        if created:
            removed = _run(["docker", "rm", "--force", name], timeout=30, allow_failure=True)
            if removed.returncode != 0:
                cleanup_error = f"docker rm failed: {(removed.stderr or removed.stdout)[-1000:]}"
            else:
                remaining = _run(
                    ["docker", "ps", "--all", "--quiet", "--filter", f"name=^/{name}$"],
                    timeout=30,
                )
                if remaining.stdout.strip():
                    cleanup_error = "The scenario container still exists after removal"
        _write_json(
            evidence_root / "cleanup.json",
            {
                "container_id": container_id or None,
                "container_name": name,
                "removed": created and cleanup_error is None,
                "error": cleanup_error,
            },
        )
    if cleanup_error:
        raise RunnerError(cleanup_error)
    if test_failure:
        raise RunnerError(test_failure)
    if evidence_failure:
        raise RunnerError(evidence_failure)
    if test_returncode != 0 or report is None or not artifact_names:
        raise RunnerError("Scenario did not produce validated evidence")
    (evidence_root / "summary.json").write_text(
        json.dumps(
            {
                "gate": gate_id,
                "scenario": scenario,
                "image": image,
                "guest_release": guest_release,
                "container": inspection,
                "container_removed": True,
                "guest_artifacts": artifact_names,
                "evidence_directory": str(evidence_root),
                "outcome": "passed",
            },
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    (evidence_root / "summary.json").chmod(0o600)
    print(f"EVIDENCE_DIR={evidence_root}")
    print(f"LSM_GATE_{gate_id}_PASSED")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in SCENARIOS:
        print("usage: apt_guest_scenario_runner.py G1|G2|G3|G4|G5", file=sys.stderr)
        return 2
    try:
        run_scenario(argv[1])
    except RunnerError as exc:
        print(f"apt guest scenario runner: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
