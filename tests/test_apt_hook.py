"""Offline tests for strict APT Pre-Install-Pkgs v3 handling."""

from __future__ import annotations

from dataclasses import replace
from io import BytesIO, StringIO
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from scanner import apt_hook
from scanner.malware_scanner import MalwareAssessment, MalwareDetection, MAX_PACKAGE_BYTES


def _install_record(path: str, name: str = "demo") -> str:
    return f"{name} - - none < 1 amd64 none {path}"


def _protocol(*actions: str, config: str = "APT::Architecture=amd64") -> bytes:
    return ("VERSION 3\n" + config + "\n\n" + "\n".join(actions) + "\n").encode()


def _assessment(status: str = "no_detection", *, complete: bool | None = None) -> MalwareAssessment:
    if complete is None:
        complete = status in {"detected", "no_detection"}
    return MalwareAssessment(
        status=status,
        scanner="mock ClamAV",
        package={
            "name": "demo", "version": "1", "architecture": "amd64",
            "multi_arch": "no",
        },
        detections=(
            [MalwareDetection("Test.Signature", "payload/bin/demo")]
            if status == "detected" else []
        ),
        error="mock provider error" if status == "error" else None,
        limitations=[] if complete else ["mock incomplete coverage"],
        coverage_complete=complete,
    )


class _Terminal:
    def __init__(self, answer: str):
        self.answer = answer
        self.output = ""

    def write(self, value: str) -> int:
        self.output += value
        return len(value)

    def flush(self) -> None:
        return None

    def readline(self) -> str:
        return self.answer


def _install_path_validation(monkeypatch, *, changed=False):
    identity = apt_hook._FileIdentity(1, 2, 3, 4, 5)
    identity_checks = 0

    def validate(raw_path):
        assert raw_path.startswith("/")
        return Path("/mock") / raw_path.rsplit("/", 1)[-1], identity

    monkeypatch.setattr(apt_hook, "_safe_archive_path", validate)
    def current_identity(path):
        nonlocal identity_checks
        identity_checks += 1
        if changed and identity_checks > 1:
            return replace(identity, inode=identity.inode + 1)
        return identity

    monkeypatch.setattr(apt_hook, "_identity_at_path", current_identity)


def _run(monkeypatch, actions, *, statuses=None, answer=None, changed=False, info_fd=None):
    _install_path_validation(monkeypatch, changed=changed)
    statuses = statuses or {}
    scanned = []
    transaction = apt_hook.parse_pre_install_v3(_protocol(*actions))
    actions_by_filename = {
        Path(action.archive_path).name: action
        for action in transaction.actions
        if action.archive_path is not None
    }

    def scanner(path):
        scanned.append(path)
        result = _assessment(statuses.get(path.name, "no_detection"))
        action = actions_by_filename[path.name]
        result.package = {
            "name": action.package_name,
            "version": action.target_version or "1",
            "architecture": action.target_architecture or "amd64",
            "multi_arch": "no" if action.target_multiarch == "none" else action.target_multiarch,
        }
        return result

    monkeypatch.delenv("APT_HOOK_INFO_FD", raising=False)
    if info_fd is not None:
        monkeypatch.setenv("APT_HOOK_INFO_FD", info_fd)
    terminal = _Terminal(answer) if answer is not None else None
    output = StringIO()
    code = apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(_protocol(*actions)),
        terminal=terminal,
        scanner=scanner,
        output=output,
    )
    return code, output.getvalue(), scanned


def test_parse_v3_transaction_preserves_archive_path_spaces_and_multiarch_fields():
    transaction = apt_hook.parse_pre_install_v3(_protocol(
        _install_record("/var/cache/apt/archives/demo package.deb"),
        "libsame 1 i386 same < 2 amd64 same **CONFIGURE**",
    ))

    assert transaction.actions[0].archive_path == "/var/cache/apt/archives/demo package.deb"
    assert transaction.actions[0].target_version == "1"
    assert transaction.actions[0].target_architecture == "amd64"
    assert transaction.actions[0].target_multiarch == "none"
    assert transaction.actions[1].action == "**CONFIGURE**"
    assert transaction.actions[1].target_version == "2"
    assert transaction.actions[1].target_architecture == "amd64"
    assert transaction.actions[1].target_multiarch == "same"
    assert transaction.configuration == (("APT::Architecture", "amd64"),)


@pytest.mark.parametrize(
    "payload",
    [
        b"VERSION 2\nAPT::Architecture=amd64\n\n",
        b"VERSION 4\nAPT::Architecture=amd64\n\n" + _install_record("/x/a.deb").encode(),
        b"VERSION 3\nAPT::Architecture=amd64\n",
        b"VERSION 3\nAPT::Architecture=amd64\n\nmalformed\n",
        b"VERSION 3\nAPT::Architecture=amd64\n\ndemo - - none < 1 amd64",
        b"VERSION 3\nnot a config record\n\n" + _install_record("/x/a.deb").encode(),
        b"VERSION 3\nAPT::Architecture=%QZ\n\n" + _install_record("/x/a.deb").encode(),
        b"VERSION 3\nAPT::Architecture=amd64\r\n\r\n",
        b"VERSION 3\nAPT::Architecture=amd64\n\n\n",
        b"VERSION 3\nAPT::Architecture=amd64\n\n",
    ],
)
def test_parse_rejects_malformed_or_incomplete_protocol(payload):
    with pytest.raises(apt_hook.AptProtocolError):
        apt_hook.parse_pre_install_v3(payload)


def test_parse_rejects_duplicate_archive_paths():
    record = _install_record("/var/cache/apt/archives/demo.deb")
    with pytest.raises(apt_hook.AptProtocolError, match="duplicate"):
        apt_hook.parse_pre_install_v3(_protocol(record, record))


def test_parse_rejects_traversal_and_unknown_action():
    with pytest.raises(apt_hook.AptProtocolError, match="unsafe"):
        apt_hook.parse_pre_install_v3(_protocol(_install_record("/var/../tmp/demo.deb")))
    with pytest.raises(apt_hook.AptProtocolError, match="neither a known"):
        apt_hook.parse_pre_install_v3(_protocol(
            "demo - - none < 1 amd64 none **PURGE**",
        ))


def test_parse_accepts_configuration_and_removal_records_but_no_install_archives():
    records = [
        "confpkg - - none < 1 amd64 none **CONFIGURE**",
        "oldpkg 1 amd64 none > - - none **REMOVE**",
    ]
    transaction = apt_hook.parse_pre_install_v3(_protocol(*records))
    assert [item.action for item in transaction.actions] == ["**CONFIGURE**", "**REMOVE**"]


def test_clean_transaction_scans_every_archive_and_continues_without_prompt(monkeypatch):
    code, output, scanned = _run(
        monkeypatch,
        [_install_record("/cache/first package.deb"), _install_record("/cache/second.deb", "other")],
    )
    assert code == 0
    assert [path.name for path in scanned] == ["first package.deb", "second.deb"]
    assert output.count("Status: no_detection") == 2
    assert "protocol version 3 accepted" in output
    assert "does not guarantee" in output


def test_detection_requires_exact_terminal_approval(monkeypatch):
    code, output, scanned = _run(
        monkeypatch, [_install_record("/cache/detected.deb")],
        statuses={"detected.deb": "detected"}, answer="INSTALL\n",
    )
    assert code == 0
    assert len(scanned) == 1
    assert "Test.Signature" in output
    assert "Explicit INSTALL approval" in output


def test_mixed_clean_and_detected_archives_are_all_scanned_before_approval(monkeypatch):
    code, output, scanned = _run(
        monkeypatch,
        [_install_record("/cache/clean.deb"), _install_record("/cache/detected.deb", "other")],
        statuses={"detected.deb": "detected"},
        answer="INSTALL\n",
    )
    assert code == 0
    assert [path.name for path in scanned] == ["clean.deb", "detected.deb"]
    assert output.count("Status:") == 2
    assert "Test.Signature" in output
    assert "Explicit INSTALL approval" in output


@pytest.mark.parametrize("answer", ["install\n", "INSTALL \n", "no\n", ""])
def test_detection_cancels_for_any_nonexact_confirmation(monkeypatch, answer):
    code, output, _ = _run(
        monkeypatch, [_install_record("/cache/detected.deb")],
        statuses={"detected.deb": "detected"}, answer=answer,
    )
    assert code == 1
    assert "transaction blocked" in output


def test_detection_without_tty_is_blocked(monkeypatch):
    monkeypatch.setattr(apt_hook, "_prompt_for_detection", lambda terminal=None: False)
    code, output, _ = _run(
        monkeypatch, [_install_record("/cache/detected.deb")],
        statuses={"detected.deb": "detected"},
    )
    assert code == 1
    assert "explicit terminal approval was not received" in output


def test_prompt_fails_closed_when_no_terminal_can_be_opened(monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("no controlling terminal")

    monkeypatch.setattr(apt_hook, "open", unavailable, raising=False)
    assert apt_hook._prompt_for_detection() is False


@pytest.mark.parametrize("status", ["incomplete", "error", "unavailable"])
def test_incomplete_error_and_unavailable_results_abort(monkeypatch, status):
    code, output, _ = _run(
        monkeypatch, [_install_record("/cache/bad.deb")],
        statuses={"bad.deb": status},
    )
    assert code == 1
    assert f"Status: {status}" in output
    assert "transaction blocked" in output


def test_detection_with_incomplete_coverage_cannot_be_approved(monkeypatch):
    monkeypatch.setattr(apt_hook, "_safe_archive_path", lambda path: (
        Path("/mock/detected.deb"), apt_hook._FileIdentity(1, 2, 3, 4, 5),
    ))
    identity = apt_hook._FileIdentity(1, 2, 3, 4, 5)
    monkeypatch.setattr(apt_hook, "_identity_at_path", lambda path: identity)
    monkeypatch.setattr(apt_hook, "_prompt_for_detection", lambda terminal=None: pytest.fail("must not prompt"))
    output = StringIO()
    code = apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(_protocol(_install_record("/cache/detected.deb"))),
        scanner=lambda path: _assessment("detected", complete=False),
        output=output,
    )
    assert code == 1
    assert "transaction blocked" in output.getvalue()


def test_changed_archive_after_scan_aborts_transaction(monkeypatch):
    code, output, _ = _run(
        monkeypatch, [_install_record("/cache/changed.deb")], changed=True,
    )
    assert code == 1
    assert "changed while it was being scanned" in output
    assert "transaction blocked" in output


@pytest.mark.parametrize(
    ("actual_name", "actual_version", "actual_arch", "actual_multiarch"),
    [
        ("different-package", "1", "amd64", "no"),
        ("demo", "2", "amd64", "no"),
        ("demo", "1", "arm64", "no"),
        ("demo", "1", "amd64", "same"),
    ],
)
def test_archive_identity_mismatch_with_apt_transaction_blocks_clean_result(
    monkeypatch, actual_name, actual_version, actual_arch, actual_multiarch,
):
    _install_path_validation(monkeypatch)
    monkeypatch.delenv("APT_HOOK_INFO_FD", raising=False)
    assessment = MalwareAssessment(
        status="no_detection",
        scanner="mock ClamAV",
        package={
            "name": actual_name, "version": actual_version,
            "architecture": actual_arch, "multi_arch": actual_multiarch,
        },
        coverage_complete=True,
    )
    output = StringIO()
    code = apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(_protocol(_install_record("/cache/demo.deb"))),
        scanner=lambda path: assessment,
        output=output,
    )

    report = output.getvalue()
    assert code == 1
    assert "Status: error" in report
    assert "Scanned archive identity does not match APT's transaction record" in report
    assert "Status: no_detection" not in report
    assert "APT transaction blocked" in report


def test_archive_identity_mismatch_preserves_detection_and_blocks_without_prompt(monkeypatch):
    _install_path_validation(monkeypatch)
    monkeypatch.delenv("APT_HOOK_INFO_FD", raising=False)
    assessment = MalwareAssessment(
        status="detected",
        scanner="mock ClamAV",
        package={"name": "unexpected-package", "version": "9"},
        detections=[MalwareDetection("Test.Signature", "payload/file")],
        coverage_complete=True,
    )
    monkeypatch.setattr(
        apt_hook, "_prompt_for_detection",
        lambda terminal=None: pytest.fail("mismatched identity must block without an override prompt"),
    )
    output = StringIO()
    code = apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(_protocol(_install_record("/cache/demo.deb"))),
        scanner=lambda path: assessment,
        output=output,
    )

    report = output.getvalue()
    assert code == 1
    assert "Status: detected" in report
    assert "Test.Signature" in report
    assert "Scanned archive identity does not match APT's transaction record" in report
    assert "transaction blocked" in report


def test_scanner_uses_trusted_system_path_and_restores_caller_environment(monkeypatch):
    _install_path_validation(monkeypatch)
    monkeypatch.delenv("APT_HOOK_INFO_FD", raising=False)
    monkeypatch.setenv("PATH", "untrusted-bin")
    observed_paths = []

    def scanner(path):
        observed_paths.append(os.environ.get("PATH"))
        result = _assessment()
        result.package = {
            "name": "demo", "version": "1", "architecture": "amd64",
            "multi_arch": "no",
        }
        return result

    code = apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(_protocol(_install_record("/cache/demo.deb"))),
        scanner=scanner,
        output=StringIO(),
    )

    assert code == 0
    assert observed_paths == [apt_hook._TRUSTED_SCANNER_PATH]
    assert os.environ["PATH"] == "untrusted-bin"


def test_configuration_and_removal_only_transaction_needs_no_scanner(monkeypatch):
    actions = [
        "configpkg - - none < 1 amd64 none **CONFIGURE**",
        "oldpkg 1 amd64 none > - - none **REMOVE**",
    ]
    monkeypatch.delenv("APT_HOOK_INFO_FD", raising=False)
    output = StringIO()
    code = apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(_protocol(*actions)),
        scanner=lambda path: pytest.fail("no archive is scheduled"),
        output=output,
    )
    assert code == 0
    assert "no package archives" in output.getvalue()


def test_unexpected_info_fd_and_oversized_protocol_fail_closed(monkeypatch):
    monkeypatch.setenv("APT_HOOK_INFO_FD", "9")
    output = StringIO()
    assert apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(_protocol(_install_record("/cache/a.deb"))), output=output,
    ) == 1
    assert "Unexpected APT_HOOK_INFO_FD" in output.getvalue()

    monkeypatch.delenv("APT_HOOK_INFO_FD")
    output = StringIO()
    assert apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(b"x" * (apt_hook.MAX_PROTOCOL_BYTES + 1)), output=output,
    ) == 1
    assert "Invalid or incomplete APT protocol" in output.getvalue()


def test_safe_archive_validation_rejects_missing_oversized_directory_and_traversal(
    tmp_path, monkeypatch,
):
    missing = tmp_path / "missing.deb"
    with pytest.raises(OSError, match="does not exist"):
        apt_hook._safe_archive_path(str(missing))

    directory = tmp_path / "directory.deb"
    directory.mkdir()
    with pytest.raises(OSError, match="regular file"):
        apt_hook._safe_archive_path(str(directory))

    oversized = tmp_path / "oversized.deb"
    oversized.write_bytes(b"123456789")
    monkeypatch.setattr(apt_hook, "MAX_PACKAGE_BYTES", 8)
    with pytest.raises(OSError, match="size limit"):
        apt_hook._safe_archive_path(str(oversized))

    with pytest.raises(OSError, match="parent traversal"):
        apt_hook._safe_archive_path(str(tmp_path / ".." / "escape.deb"))


def test_safe_archive_validation_rejects_symlinks(tmp_path):
    target = tmp_path / "target.deb"
    target.write_bytes(b"harmless")
    link = tmp_path / "link.deb"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable in this test environment")
    with pytest.raises(OSError, match="symlink"):
        apt_hook._safe_archive_path(str(link))


def test_safe_archive_validation_rejects_inaccessible_file(tmp_path, monkeypatch):
    package = tmp_path / "unreadable.deb"
    package.write_bytes(b"harmless")

    def deny_open(*args, **kwargs):
        raise PermissionError("mock access denied")

    monkeypatch.setattr(apt_hook.os, "open", deny_open)
    with pytest.raises(OSError, match="cannot be opened safely"):
        apt_hook._safe_archive_path(str(package))


def test_safe_archive_validation_rejects_non_deb_and_relative_paths(tmp_path):
    text_file = tmp_path / "package.txt"
    text_file.write_text("not a package", encoding="utf-8")
    with pytest.raises(OSError, match="suffix"):
        apt_hook._safe_archive_path(str(text_file))
    with pytest.raises(OSError, match="absolute"):
        apt_hook._safe_archive_path("relative/package.deb")


def test_missing_transaction_archive_aborts_without_scanning(monkeypatch):
    monkeypatch.setattr(
        apt_hook, "_safe_archive_path",
        lambda path: (_ for _ in ()).throw(OSError("archive missing")),
    )
    output = StringIO()
    code = apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(_protocol(_install_record("/cache/missing.deb"))),
        scanner=lambda path: pytest.fail("missing archive must not be scanned"),
        output=output,
    )
    assert code == 1
    assert "archive missing" in output.getvalue()
    assert "transaction blocked" in output.getvalue()


def test_terminal_safe_escapes_ansi_and_newlines():
    assert apt_hook._terminal_safe("bad\x1b[31m\r\nname") == "bad\\u001b[31m\\u000d\\u000aname"


@pytest.mark.parametrize(
    "record",
    [
        "BadName - - none < 1 amd64 none /x/a.deb",
        "demo - amd64 none < 1 amd64 none /x/a.deb",
        "demo - - none < 1 amd64 none",
        "demo - - none ? 1 amd64 none /x/a.deb",
        "demo - - none < 1 amd64 invalid /x/a.deb",
        "demo - - none < - - none /x/a.deb",
        "demo 1 amd64 none < - - none **REMOVE**",
        "demo - - none < - - none **CONFIGURE**",
    ],
)
def test_parse_rejects_invalid_package_action_fields(record):
    with pytest.raises(apt_hook.AptProtocolError):
        apt_hook.parse_pre_install_v3(_protocol(record))


@pytest.mark.parametrize(
    "result",
    [
        None,
        [],
        {"status": "surprise", "scanner": "mock", "coverage_complete": True,
         "detections": [], "error": None, "limitations": []},
        {"status": "no_detection", "scanner": "mock", "coverage_complete": False,
         "detections": [], "error": None, "limitations": []},
        {"status": "no_detection", "scanner": "mock", "coverage_complete": True,
         "detections": [{"name": "unexpected", "path": "payload/file"}],
         "error": None, "limitations": []},
        {"status": "detected", "scanner": "mock", "coverage_complete": True,
         "detections": [], "error": None, "limitations": []},
        {"status": "detected", "scanner": "mock", "coverage_complete": True,
         "detections": [{"name": "signature"}], "error": None, "limitations": []},
        {"status": "no_detection", "scanner": "mock", "coverage_complete": True,
         "detections": [], "error": None, "limitations": ["unscanned file"]},
        {"status": "no_detection", "scanner": "mock", "coverage_complete": True,
         "detections": [], "error": None, "limitations": [], "package": None},
    ],
)
def test_malformed_scanner_results_are_reported_as_errors_and_block(monkeypatch, result):
    _install_path_validation(monkeypatch)
    monkeypatch.delenv("APT_HOOK_INFO_FD", raising=False)

    class ScannerResult:
        def to_dict(self):
            if isinstance(result, dict):
                return {"package": {"name": "demo", "version": "1"}, **result}
            return result

    output = StringIO()
    code = apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(_protocol(_install_record("/cache/result.deb"))),
        scanner=lambda path: ScannerResult(),
        output=output,
    )
    assert code == 1
    assert "Status: error" in output.getvalue()
    assert "transaction blocked" in output.getvalue()
    assert "no known detection" not in output.getvalue()


def test_detection_with_inconsistent_complete_metadata_is_preserved_but_blocked(monkeypatch):
    _install_path_validation(monkeypatch)
    monkeypatch.delenv("APT_HOOK_INFO_FD", raising=False)
    assessment = MalwareAssessment(
        status="detected",
        scanner="mock ClamAV",
        package={"name": "demo", "version": "1"},
        detections=[MalwareDetection("Test.Signature", "payload/file")],
        error="mock scanner warning",
        coverage_complete=True,
    )
    output = StringIO()
    code = apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(_protocol(_install_record("/cache/detected.deb"))),
        scanner=lambda path: assessment,
        output=output,
    )
    assert code == 1
    assert "Status: detected" in output.getvalue()
    assert "Test.Signature" in output.getvalue()
    assert "mock scanner warning" in output.getvalue()
    assert "transaction blocked" in output.getvalue()


def test_root_scanner_privileges_are_irreversibly_dropped(monkeypatch):
    user_ids = [0, 0, 0]
    group_ids = [0, 0, 0]
    calls = []
    monkeypatch.setattr(apt_hook.os, "name", "posix")
    monkeypatch.setattr(apt_hook.os, "geteuid", lambda: user_ids[1], raising=False)
    monkeypatch.setattr(apt_hook.os, "getresuid", lambda: tuple(user_ids), raising=False)
    monkeypatch.setattr(apt_hook.os, "getresgid", lambda: tuple(group_ids), raising=False)

    def setgroups(groups):
        calls.append(("setgroups", groups))

    def setgid(gid):
        calls.append(("setgid", gid))
        group_ids[:] = [gid, gid, gid]

    def setuid(uid):
        calls.append(("setuid", uid))
        user_ids[:] = [uid, uid, uid]

    monkeypatch.setattr(apt_hook.os, "setgroups", setgroups, raising=False)
    monkeypatch.setattr(apt_hook.os, "setgid", setgid, raising=False)
    monkeypatch.setattr(apt_hook.os, "setuid", setuid, raising=False)
    monkeypatch.setitem(
        sys.modules, "pwd", SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=42, pw_gid=43)),
    )

    apt_hook._drop_to_apt_sandbox_user()

    assert calls == [("setgroups", [43]), ("setgid", 43), ("setuid", 42)]
    assert user_ids == [42, 42, 42]
    assert group_ids == [43, 43, 43]


def test_privilege_drop_failure_blocks_without_scanning(monkeypatch):
    _install_path_validation(monkeypatch)
    monkeypatch.setattr(
        apt_hook, "_drop_to_apt_sandbox_user",
        lambda: (_ for _ in ()).throw(PermissionError("drop denied")),
    )
    monkeypatch.delenv("APT_HOOK_INFO_FD", raising=False)
    output = StringIO()
    code = apt_hook.run_apt_preinstall_hook(
        stream=BytesIO(_protocol(_install_record("/cache/a.deb"))),
        scanner=lambda path: pytest.fail("must not scan while still privileged"),
        output=output,
    )
    assert code == 1
    assert "Could not drop privileges" in output.getvalue()
    assert "transaction blocked" in output.getvalue()
