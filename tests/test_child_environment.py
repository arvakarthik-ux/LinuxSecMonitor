"""Deterministic tests for the child environment allowlist policy."""

from __future__ import annotations

import os
import pwd
import socket
import stat
from pathlib import Path

import pytest

from scanner import child_environment
from scanner.child_environment import (
    TRUSTED_PATH_DIRS,
    build_child_environment,
    is_dangerous_environment_key,
)


EXPECTED_BASE_KEYS = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "PWD",
    "TERM",
    "LANG",
    "TZ",
}

DANGEROUS_PARENT_VARS = [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "NODE_OPTIONS",
    "NODE_PATH",
    "RUBYOPT",
    "PERL5OPT",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASH_FUNC_x%%",
    "ZDOTDIR",
    "IFS",
    "CDPATH",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "GIT_EXTERNAL_DIFF",
    "GIT_EDITOR",
    "GIT_PAGER",
    "npm_config_script_shell",
    "NPM_CONFIG_PREFIX",
    "PIP_CONFIG_FILE",
    "PIP_INDEX_URL",
    "CARGO_HOME",
    "RUSTC_WRAPPER",
    "GOENV",
    "GOFLAGS",
    "JAVA_TOOL_OPTIONS",
    "MAVEN_OPTS",
    "GRADLE_OPTS",
    "CC",
    "CFLAGS",
    "MAKEFLAGS",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "LESSOPEN",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "GCONV_PATH",
    "NLSPATH",
    "LOCPATH",
    "HOSTALIASES",
    "XDG_CONFIG_HOME",
    "SSH_ASKPASS",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
]


@pytest.fixture
def passwd_home() -> str:
    return pwd.getpwuid(os.geteuid()).pw_dir


@pytest.fixture
def passwd_name() -> str:
    return pwd.getpwuid(os.geteuid()).pw_name


def _controlled_parent(**extra: str) -> dict[str, str]:
    base = {
        "PATH": "/tmp/evil:/usr/bin:/bin:relative/dir:.:",
        "HOME": "/home/evil-user",
        "USER": "evil user",
        "LOGNAME": "evil user",
        "SHELL": "/bin/zsh",
        "TERM": "xterm-256color",
        "TZ": "Europe/Berlin",
        "LANG": "en_US.UTF-8",
    }
    base.update(extra)
    return base


class TestDangerousVariablesExcluded:
    @pytest.mark.parametrize("key", DANGEROUS_PARENT_VARS)
    def test_dangerous_parent_variable_is_stripped(self, tmp_path, key):
        parent = _controlled_parent(**{key: "/attacker/controlled"})
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert key not in env
        assert env.get(key.upper()) != "/attacker/controlled"

    def test_result_contains_only_allowlisted_keys(self, tmp_path):
        parent = _controlled_parent(
            UNDOCUMENTED_EXTRA="whatever",
            SSH_AUTH_SOCK="relative/not-a-socket",
        )
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert set(env) == EXPECTED_BASE_KEYS

    def test_all_dangerous_family_none_retained(self, tmp_path):
        parent = _controlled_parent(**{key: "/attacker" for key in DANGEROUS_PARENT_VARS})
        env = build_child_environment(cwd=tmp_path, parent=parent)
        for key in DANGEROUS_PARENT_VARS:
            assert key not in env


class TestInputsNeverMutated:
    def test_parent_mapping_is_unchanged(self, tmp_path):
        parent = _controlled_parent(
            LD_PRELOAD="/evil.so",
            PYTHONPATH="/evil/py",
            GIT_CONFIG_GLOBAL="/evil/gitconfig",
            BASH_ENV="/evil/bashenv",
        )
        snapshot = dict(parent)
        build_child_environment(cwd=tmp_path, parent=parent)
        assert parent == snapshot

    def test_os_environ_is_unchanged_by_default_parent(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("LD_PRELOAD", "/evil.so")
        monkeypatch.setenv("PYTHONPATH", "/evil/py")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/evil/gitconfig")
        monkeypatch.setenv("BASH_ENV", "/evil/bashenv")
        before = dict(os.environ)
        build_child_environment(cwd=tmp_path)
        assert dict(os.environ) == before


class TestIdentityVariables:
    def test_home_is_passwd_home_not_parent_redirection(
        self, tmp_path, passwd_home
    ):
        parent = _controlled_parent(HOME="/tmp/attacker/home")
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert env["HOME"] == passwd_home

    def test_user_logname_are_passwd_account(self, tmp_path, passwd_name):
        env = build_child_environment(cwd=tmp_path, parent=_controlled_parent())
        assert env["USER"] == passwd_name
        assert env["LOGNAME"] == passwd_name

    def test_identity_fallback_without_passwd_entry(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(child_environment, "_passwd_account", lambda: None)
        env = build_child_environment(
            cwd=tmp_path, parent=_controlled_parent(USER="good_user", LOGNAME="good_user")
        )
        assert env["USER"] == "good_user"
        assert env["LOGNAME"] == "good_user"

    def test_unsanitizable_parent_user_falls_back_to_unknown(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(child_environment, "_passwd_account", lambda: None)
        env = build_child_environment(
            cwd=tmp_path,
            parent=_controlled_parent(USER="evil user", LOGNAME="$(reboot)"),
        )
        assert env["USER"] == "unknown"
        assert env["LOGNAME"] == "unknown"

    def test_missing_parent_user_falls_back_to_unknown(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(child_environment, "_passwd_account", lambda: None)
        env = build_child_environment(
            cwd=tmp_path,
            parent={"PATH": "/usr/bin", "HOME": "/home"},
        )
        assert env["USER"] == "unknown"
        assert env["LOGNAME"] == "unknown"

    def test_home_fallback_chain_without_passwd_entry(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(child_environment, "_passwd_account", lambda: None)
        env = build_child_environment(
            cwd=tmp_path, parent=_controlled_parent(HOME="/abs/fallback")
        )
        assert env["HOME"] == "/abs/fallback"
        relative_env = build_child_environment(
            cwd=tmp_path, parent=_controlled_parent(HOME="relative/home")
        )
        assert relative_env["HOME"] == "/"

    def test_shell_is_fixed_non_interactive(self, tmp_path):
        env = build_child_environment(cwd=tmp_path, parent=_controlled_parent())
        assert env["SHELL"] == "/bin/sh"

    def test_pwd_matches_requested_cwd(self, tmp_path):
        env = build_child_environment(cwd=tmp_path, parent=_controlled_parent())
        assert env["PWD"] == os.path.abspath(os.fspath(tmp_path))


class TestConditionalValues:
    def test_invalid_term_becomes_dumb(self, tmp_path):
        parent = _controlled_parent(TERM="xterm$()")
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert env["TERM"] == "dumb"

    def test_valid_term_is_retained(self, tmp_path):
        parent = _controlled_parent(TERM="screen-256color")
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert env["TERM"] == "screen-256color"

    def test_abs_tmpdir_retained(self, tmp_path):
        parent = _controlled_parent(TMPDIR="/tmp/workdir")
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert env["TMPDIR"] == "/tmp/workdir"

    def test_relative_tmpdir_omitted(self, tmp_path):
        parent = _controlled_parent(TMPDIR="relative/tmp")
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert "TMPDIR" not in env

    def test_invalid_tz_becomes_utc(self, tmp_path):
        parent = _controlled_parent(TZ="Evil Zone\npayload")
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert env["TZ"] == "UTC"

    def test_valid_tz_retained(self, tmp_path):
        parent = _controlled_parent(TZ="UTC+2")
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert env["TZ"] == "UTC+2"

    def test_invalid_lang_becomes_c_utf8(self, tmp_path):
        parent = _controlled_parent(LANG="C\ninjected")
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert env["LANG"] == "C.UTF-8"

    def test_valid_lc_all_is_retained_not_overridden(self, tmp_path):
        parent = _controlled_parent(LC_ALL="de_DE.UTF-8", LANG="en_US.UTF-8")
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert env["LC_ALL"] == "de_DE.UTF-8"
        assert env["LANG"] == "en_US.UTF-8"

    def test_invalid_lc_variable_omitted(self, tmp_path):
        parent = _controlled_parent(LC_CTYPE="bad value")
        env = build_child_environment(cwd=tmp_path, parent=parent)
        assert "LC_CTYPE" not in env

    def test_proxy_and_xdg_never_retained(self, tmp_path):
        parent = _controlled_parent(
            http_proxy="http://evil:3128",
            HTTPS_PROXY="http://evil:3128",
            XDG_CONFIG_HOME="/evil/xdg",
        )
        env = build_child_environment(cwd=tmp_path, parent=parent)
        for key in ("http_proxy", "HTTP_PROXY", "HTTPS_PROXY", "XDG_CONFIG_HOME"):
            assert key not in env


class TestTrustedPath:
    def test_parent_path_entries_never_reappear(self, tmp_path):
        parent = _controlled_parent()  # PATH includes /tmp/evil, relative, "."
        env = build_child_environment(cwd=tmp_path, parent=parent)
        entries = env["PATH"].split(":")
        assert "/tmp/evil" not in entries
        assert "relative/dir" not in entries
        assert "." not in entries
        assert "" not in entries

    def test_each_path_entry_is_absolute_root_owned_readonly(self, tmp_path):
        env = build_child_environment(cwd=tmp_path, parent=_controlled_parent())
        assert env["PATH"]
        for entry in env["PATH"].split(":"):
            assert os.path.isabs(entry)
            assert os.path.exists(entry)
            stat_result = os.stat(entry)
            assert stat_result.st_uid == 0
            assert not stat_result.st_mode & 0o022
            assert os.access(entry, os.X_OK)

    def test_path_entries_come_from_trusted_constant(self, tmp_path):
        env = build_child_environment(cwd=tmp_path, parent=_controlled_parent())
        for entry in env["PATH"].split(":"):
            assert entry in TRUSTED_PATH_DIRS

    def test_tmp_directory_is_not_trusted(self, tmp_path):
        # A group/other-writable directory is never trusted, whoever owns it.
        # chmod first so the assertion holds even when tests run as root (a
        # root-owned default tmp_path would otherwise fail on ownership, not
        # on mode); the 0o700 restore preserves the original isolation.
        os.chmod(tmp_path, 0o777)
        try:
            result = child_environment._is_trusted_directory(str(tmp_path))
            assert result is False
        finally:
            os.chmod(tmp_path, 0o700)

    def test_policy_fails_closed_without_any_trusted_directory(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            child_environment, "_is_trusted_directory", lambda directory: False
        )
        with pytest.raises(RuntimeError):
            build_child_environment(cwd=tmp_path, parent=_controlled_parent())


@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="AF_UNIX unavailable on this platform"
)
class TestSshAuthSock:
    def _make_agent_socket(self, tmp_path: Path) -> socket.socket:
        sock_path = tmp_path / "agent.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(1)
        return server

    def test_private_owned_socket_is_retained(self, tmp_path):
        server = self._make_agent_socket(tmp_path)
        try:
            sock_path = tmp_path / "agent.sock"
            os.chmod(sock_path, 0o600)
            env = build_child_environment(
                cwd=tmp_path, parent=_controlled_parent(SSH_AUTH_SOCK=str(sock_path))
            )
            assert env["SSH_AUTH_SOCK"] == str(sock_path)
        finally:
            server.close()
            (tmp_path / "agent.sock").unlink(missing_ok=True)

    def test_group_other_accessible_socket_is_omitted(self, tmp_path):
        server = self._make_agent_socket(tmp_path)
        try:
            sock_path = tmp_path / "agent.sock"
            os.chmod(sock_path, 0o666)
            env = build_child_environment(
                cwd=tmp_path, parent=_controlled_parent(SSH_AUTH_SOCK=str(sock_path))
            )
            assert "SSH_AUTH_SOCK" not in env
        finally:
            server.close()
            (tmp_path / "agent.sock").unlink(missing_ok=True)

    def test_nonexistent_socket_path_is_omitted(self, tmp_path):
        env = build_child_environment(
            cwd=tmp_path,
            parent=_controlled_parent(SSH_AUTH_SOCK=str(tmp_path / "nope.sock")),
        )
        assert "SSH_AUTH_SOCK" not in env

    def test_non_socket_file_is_omitted(self, tmp_path):
        plain = tmp_path / "plain.sock"
        plain.write_text("")
        os.chmod(plain, 0o600)
        env = build_child_environment(
            cwd=tmp_path, parent=_controlled_parent(SSH_AUTH_SOCK=str(plain))
        )
        assert "SSH_AUTH_SOCK" not in env


class TestTripwire:
    def test_dangerous_key_detector(self):
        assert is_dangerous_environment_key("LD_PRELOAD") is True
        assert is_dangerous_environment_key("git_config_global") is True
        assert is_dangerous_environment_key("NPM_CONFIG_PREFIX") is True
        assert is_dangerous_environment_key("HTTP_PROXY") is True
        assert is_dangerous_environment_key("PATH") is False
        assert is_dangerous_environment_key("HOME") is False
        assert is_dangerous_environment_key("SSH_AUTH_SOCK") is False
        assert is_dangerous_environment_key("LC_ALL") is False
        assert is_dangerous_environment_key("LANGUAGE") is False

    def test_expanded_tripwire_representatives_are_dangerous(self):
        for representative in (
            "JAVA_HOME",           # JAVA prefix
            "JAVA_TOOL_OPTIONS",   # JAVA prefix
            "JDK_JAVA_OPTIONS",    # JDK_ prefix
            "RUSTFLAGS",           # RUST prefix
            "RUSTC_WRAPPER",
            "DOTNET_CLI_HOME",     # DOTNET_ prefix
            "UV_CACHE_DIR",        # UV_ prefix
            "POETRY_VIRTUALENVS_PATH",  # POETRY_ prefix
            "CMAKE_TOOLCHAIN_FILE",     # CMAKE_ prefix
            "CCACHE_DIR",          # CCACHE_ prefix
            "PKG_CONFIG_PATH",     # PKG_CONFIG prefix
            "DOCKER_HOST",         # DOCKER_ prefix
            "BUILDKIT_HOST",
            "GNUPGHOME",
            "GPG_AGENT_INFO",
            "SSH_AGENT_PID",       # SSH_AGENT prefix
            "CURL_HOME",           # CURL_ prefix
            "XDG_RUNTIME_DIR",     # XDG_ prefix and explicit name
            "DBUS_SESSION_BUS_ADDRESS",
            "MALLOC_ARENA_MAX",    # MALLOC_ prefix
            "GLIBC_TUNABLES",      # GLIBC_ prefix
            "HISTFILE",            # HIST prefix
            "MANPAGER",
            "BROWSER",
            "SYSTEMD_PAGER",
            "TERMINFO",
            "TERMINFO_DIRS",
            "MAKELEVEL",
            "MFLAGS",
            "RANLIB",
            "STRIP",
            "OBJCOPY",
            "NM",
            "AR",
            "AS",
            "LD",
            "PS1",
            "PS2",
            "PS3",
            "TMOUT",
            "FCEDIT",
            "EXECSHELL",
            "WAYLAND_DISPLAY",
        ):
            assert is_dangerous_environment_key(representative) is True, representative

    def test_allowlisted_keys_are_never_dangerous(self):
        allowlisted = [
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "SHELL",
            "PWD",
            "TERM",
            "TMPDIR",
            "TZ",
            "LANG",
            "LANGUAGE",
            "SSH_AUTH_SOCK",
            "LC_ALL",
            "LC_CTYPE",
            "LC_NUMERIC",
            "LC_TIME",
            "LC_COLLATE",
            "LC_MONETARY",
            "LC_MESSAGES",
            "LC_PAPER",
            "LC_NAME",
            "LC_ADDRESS",
            "LC_TELEPHONE",
            "LC_MEASUREMENT",
            "LC_IDENTIFICATION",
        ]
        for key in allowlisted:
            assert is_dangerous_environment_key(key) is False, key
            assert is_dangerous_environment_key(key.lower()) is False, key

    def test_tripwire_policy_failure_raises_runtime_error(
        self, tmp_path, monkeypatch
    ):
        # Force the tripwire to treat a benign allowlisted key as dangerous:
        # the policy must fail closed instead of shipping it.
        monkeypatch.setattr(
            child_environment,
            "is_dangerous_environment_key",
            lambda key: key == "HOME",
        )
        with pytest.raises(RuntimeError):
            build_child_environment(cwd=tmp_path, parent=_controlled_parent())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
