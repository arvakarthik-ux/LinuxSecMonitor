"""Explicit allowlist environment policy for child processes.

This module is the single reusable environment policy used by the two real
child-process launch sites in LinuxSecMonitor:

1. ``scanner.execution_guard.run_reviewed_command`` (``--safe-run`` gated
   execution after repository review).
2. ``src.wrapper.core.CommandWrapper._run_command`` (the wrapper framework's
   automatic repository protection).

Why an allowlist?

Both launch sites spawn a reviewed command after user approval. Historically,
``run_reviewed_command`` passed no ``env=`` at all, so the child inherited the
full parent environment, and ``_run_command`` used a small allowlist that
copied several variables unvalidated (``HOME``, ``USER``, ``SHELL``, ``TERM``)
and could re-inject hostile runtime overrides (``NODE_PATH``,
``RUSTC_WRAPPER``, ``MAVEN_OPTS``, ``GRADLE_OPTS``, ...). A child process that
inherits a hostile environment can be hijacked without running a single byte of
repository code, for example through:

* dynamic-linker injection (``LD_PRELOAD``, ``LD_LIBRARY_PATH``, ``LD_AUDIT``),
* interpreter startup hooks (``PYTHONPATH``, ``PYTHONSTARTUP``,
  ``BASH_ENV``, ``ENV``, ``ZDOTDIR``, ``RUBYOPT``, ``PERL5OPT``,
  ``NODE_OPTIONS``, ``JAVA_TOOL_OPTIONS``),
* tool configuration redirection (``GIT_CONFIG_GLOBAL``, ``GIT_SSH_COMMAND``,
  ``PIP_CONFIG_FILE``, ``CARGO_HOME``, ``GOENV``, ``MAVEN_OPTS``,
  ``GRADLE_OPTS``, ``NPM_CONFIG_PREFIX``), which silently changes what the
  "same" command does,
* proxy and CA overrides (``HTTP_PROXY``, ``HTTPS_PROXY``,
  ``SSL_CERT_FILE``, ``REQUESTS_CA_BUNDLE``), which redirect network traffic
  and TLS trust for any command that reaches the network.

A whitelist is the only robust model here: instead of enumerating every
variable that could ever become dangerous, we retain a fixed set of variables
that reviewed child commands legitimately need, each one validated, and strip
everything else. This policy is not used for the APT hook (which builds its
own restricted environment after dropping to the ``_apt`` user) and is not a
sandbox: a determined child can still act outside it. It removes the class of
environment-injection attacks that would otherwise be inherited silently.

Retained variables and why:

``PATH``
    Validated trusted system directories from ``TRUSTED_PATH_DIRS`` only
    (never the parent PATH). Each directory must be absolute, exist, be a
    directory (following symlinks), be owned by root, not be group- or
    other-writable, and be executable-searchable for the current user. If no
    directory validates, construction fails closed with ``RuntimeError``.
    Package-manager and build tools resolve helper binaries through PATH; a
    parent-controlled PATH with writable/attacker-owned entries would let
    repository-local code shadow system tools.

``HOME``
    Normalized to the *current account's* passwd home
    (``pwd.getpwuid(os.geteuid()).pw_dir``) when that path is absolute;
    otherwise a valid absolute parent ``HOME`` is used as a portable fallback;
    otherwise ``/``. Git, pip, npm, and other package managers read
    configuration from ``$HOME`` (``.gitconfig``, ``.pip/pip.conf`` ...), so
    an env-redirected HOME pointing at repository-controlled or temporary
    storage would let the reviewed command load silently replaced
    configuration. Resolving HOME to the passwd entry anchors it to the
    account rather than to whatever the parent put in the environment.

``USER`` / ``LOGNAME``
    The passwd account name for the effective UID, so identity-based tooling
    cannot be spoofed; fallback to a strictly sanitized token from the parent
    (alphanumeric plus ``._-``, max 64 bytes); otherwise ``"unknown"``.

``SHELL``
    Fixed to ``/bin/sh``. Child commands are non-interactive; inheriting the
    parent's interactive shell would leak shell-specific startup hooks
    (``.bashrc``, ``.zshrc``) into unrelated tools that consult ``$SHELL``
    (editors, pagers, ``git var GIT_SHELL`` style lookups).

``PWD``
    Absolute path of the requested working directory. Some tools consult
    ``$PWD`` instead of ``getcwd()``; it must match the ``cwd`` actually
    passed to the child, never the parent's stale working directory.

``TERM``
    Parent value only when it matches ``^[A-Za-z0-9._+-]{1,64}$``; otherwise
    ``"dumb"``. Terminal capability strings can contain terminal-escape
    sequences that confuse or exploit pagers and editors; the strict pattern
    allows every real terminal name (``xterm-256color``, ``tmux-256color``)
    but never arbitrary escape payloads.

``TMPDIR``
    Parent value only when it is absolute and NUL-free; otherwise omitted, in
    which case tools fall back to ``/tmp``. A relative or hostile TMPDIR can
    redirect lock files, socket targets and temporary artifacts onto paths
    the child does not control or into repository-local storage.

``TZ``
    Parent value only when it matches ``^[A-Za-z0-9_+:/.-]{1,128}$``
    (e.g. ``Europe/Berlin``, ``UTC+2``); otherwise ``"UTC"``. Timezone data is
    bounded to characters that appear in real zone names and offsets, so a
    hostile TZ cannot smuggle payload text into date library parsing.

``LANG`` / ``LC_*`` / ``LANGUAGE``
    Locale compatibility. ``LANG`` is retained when it matches
    ``^[A-Za-z0-9_.@-]{1,64}$`` (e.g. ``en_US.UTF-8``), else ``"C.UTF-8"``.
    ``LC_ALL``, ``LC_CTYPE``, ``LC_NUMERIC``, ``LC_TIME``, ``LC_COLLATE``,
    ``LC_MONETARY``, ``LC_MESSAGES``, ``LC_PAPER``, ``LC_NAME``,
    ``LC_ADDRESS``, ``LC_TELEPHONE``, ``LC_MEASUREMENT``,
    ``LC_IDENTIFICATION`` and ``LANGUAGE`` are retained only when they match
    ``^[A-Za-z0-9_.@:-]{1,128}$`` and are omitted otherwise. ``LC_ALL`` is
    deliberately NOT forced on top of the parent's locale: forcing it would
    silently override legitimate locale choices and change collation and
    number formatting for reviewed commands; the pattern rejects value forms
    that could alter program behaviour beyond locale selection.

``SSH_AUTH_SOCK``
    Retained only when the value is an absolute path to an existing Unix
    domain socket that is owned by the current effective UID and not
    group/other accessible (no ``0o077`` bits). Ordinary git-over-SSH
    operation legitimately needs the agent; the strict validation prevents
    pointing the child at an attacker-controlled socket (credential capture)
    or a path whose contents are readable by others. Residual TOCTOU: the
    socket is validated at environment-build time and could be replaced
    before the child opens it; the ownership/permission requirements bound
    that window to an attacker who can already write into the agent socket
    location as the same user.

Deliberately NOT retained: proxy configuration (``HTTP_PROXY``,
``HTTPS_PROXY``, ``ALL_PROXY``, ``NO_PROXY`` and lowercase variants),
virtual-environment and conda state (``VIRTUAL_ENV``, ``CONDA_PREFIX``),
XDG configuration redirection (``XDG_*``), display/session variables
(``DISPLAY``, ``DBUS_*``, ``XAUTHORITY``), CI and environmental markers
(``CI``, ``NODE_ENV``), editor and pager hooks (``EDITOR``, ``VISUAL``,
``PAGER``, ``LESSOPEN``), and every runtime-override variable named in the
dangerous lists below. Anything not named in this policy is dropped; a future
"dangerous" variable needs no update here to be excluded.

After construction, a final tripwire assertion verifies that no retained key
matches the documented dangerous prefixes or names; a violation raises
``RuntimeError`` so a policy bug fails closed instead of silently shipping a
hostile variable to the child.

Residual limits
---------------

This policy is environment hardening, not a security boundary:

(a) Configuration files under the trusted ``HOME`` (``~/.gitconfig``,
    ``~/.npmrc``, ``~/.pip/pip.conf`` and similar) are NOT sanitized.
    Environment filtering cannot neutralize hostile entries in those
    files, and a compromised account home affects every reviewed child.
(b) The known trusted-executable replacement race (leaf-3A.4 gate 5) is NOT
    addressed by this policy; the window between trusting a resolved
    executable and spawning it is handled (or not) elsewhere.
(c) PATH directory ownership/mode validation happens at environment-build
    time; replacing a validated directory afterwards requires root or
    equivalent file ownership, but the build-time snapshot itself is not
    continuously verified while the child runs.
(d) The child inherits this filtered environment but still reads its own
    configuration files (per-user config under HOME, project-local config
    in the repository) which this policy does not inspect.
(e) This is defense-in-depth only. It is not a sandbox and does not cover
    privilege-escalation paths such as ``sudo`` or other environment-reset
    mechanisms that rebuild the child environment by different rules.
"""

from __future__ import annotations

import os
import re
import stat
from types import MappingProxyType
from typing import Mapping

__all__ = [
    "TRUSTED_PATH_DIRS",
    "DANGEROUS_ENV_PREFIXES",
    "DANGEROUS_ENV_NAMES",
    "build_child_environment",
]


# Fixed trusted system directories for the child PATH. The parent PATH is
# never consulted: any user-writable or temporary directory in it could host
# trojan executables that shadow system tools inside the reviewed command.
TRUSTED_PATH_DIRS: tuple[str, ...] = (
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/local/sbin",
    "/usr/sbin",
    "/sbin",
)

# Documented tripwire lists. These are NOT the primary filter (the allowlist
# is); they exist so that allowlisted keys can be asserted free of known
# injection vectors after the policy is built. Keys are matched
# case-insensitively: a key is dangerous when its uppercase form equals an
# entry of DANGEROUS_ENV_NAMES or starts with an entry of
# DANGEROUS_ENV_PREFIXES.
#
# Prefixes cover whole variable families commonly used for code-injection or
# configuration redirection. Every prefix below is disjoint from the
# allowlisted key set (PATH, HOME, USER, LOGNAME, SHELL, PWD, TERM, TMPDIR,
# TZ, LANG, LC_*, LANGUAGE, SSH_AUTH_SOCK) by construction.
DANGEROUS_ENV_PREFIXES: frozenset[str] = frozenset({
    "LD_",           # LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, LD_DEBUG...
    "GIT_",          # GIT_CONFIG_GLOBAL, GIT_SSH_COMMAND, GIT_DIR, GIT_ASKPASS...
    "PYTHON",        # PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT...
    "NODE_",         # NODE_OPTIONS, NODE_PATH, NODE_EXTRA_CA_CERTS...
    "NPM_CONFIG_",   # NPM_CONFIG_PREFIX, npm_config_script_shell...
    "YARN_",         # YARN_* lifecycle/config hooks
    "PNPM_",         # PNPM_* lifecycle/config hooks
    "PERL",          # PERL5OPT, PERL5LIB, PERLLIB, PERL5DB...
    "RUBY",          # RUBYOPT, RUBYLIB, RUBYPATH...
    "BASH_",         # BASH_ENV, BASHOPTS, BASH_FUNC_x%%...
    "ZSH_",          # ZSH_ENV_FILE, ZSH_CUSTOM...
    "CARGO_",        # CARGO_HOME, CARGO_TARGET_DIR...
    "RUST",          # RUSTFLAGS, RUSTDOCFLAGS, RUSTC_WRAPPER, RUSTUP_*...
    "JAVA",          # JAVA_HOME, JAVA_TOOL_OPTIONS, JAVACMD, JAVA_OPTIONS... (covers JVM options list below)
    "JDK_",          # JDK_JAVA_OPTIONS, JDK_* launcher overrides
    "MAVEN_",        # MAVEN_OPTS, MAVEN_HOME...
    "GRADLE_",       # GRADLE_OPTS, GRADLE_HOME...
    "GEM_",          # GEM_HOME, GEM_PATH...
    "BUNDLE_",       # BUNDLE_GEMFILE, BUNDLE_BIN...
    "GO",            # GOENV, GOFLAGS, GOPATH, GOCACHE, GODEBUG...
    "PIP_",          # PIP_CONFIG_FILE, PIP_INDEX_URL...
    "PIPENV_",       # PIPENV_* pipenv runtime overrides
    "POETRY_",       # POETRY_* poetry runtime overrides
    "UV_",           # UV_* uv tool overrides
    "HATCH_",        # HATCH_* hatch tool overrides
    "DOTNET_",       # DOTNET_* .NET toolchain overrides
    "CONDA_",        # CONDA_PREFIX and conda runtime overrides
    "CMAKE_",        # CMAKE_* build configuration redirection
    "MAKEFLAGS",     # make jobserver/flags injection
    "CCACHE_",       # CCACHE_* compiler-cache redirection
    "DISTCC_",       # DISTCC_* distributed build redirection
    "PKG_CONFIG",    # PKG_CONFIG_PATH, PKG_CONFIG_LIBDIR, PKG_CONFIG_SYSROOT_DIR
    "DOCKER_",       # DOCKER_HOST, DOCKER_CONFIG...
    "BUILDKIT_",     # BUILDKIT_* build-hook redirection
    "GPG_",          # GPG_HOME, GPG_* agent/config redirection
    "SSH_ASKPASS",   # SSH_ASKPASS, SSH_ASKPASS_REQUIRE, SSH_ASKPASS_FEED
    "SSH_AGENT",     # SSH_AGENT_PID and other SSH_AGENT_* variables
    "CURL_",         # CURL_HOME and curl config redirection
    "LESS",          # LESSOPEN, LESSCLOSE, LESSSECURE...
    "HIST",          # HISTCONTROL, HISTFILE, HISTSIZE, HISTTIMEFORMAT...
    "MALLOC_",       # MALLOC_ARENA_MAX, MALLOC_CONF...
    "GLIBC_",        # GLIBC_TUNABLES and related loader tunables
    "XDG_",          # XDG_CONFIG_HOME, XDG_RUNTIME_DIR...
    "DBUS_",         # DBUS_SESSION_BUS_ADDRESS...
    "OPENSSL_",      # OPENSSL_CONF...
    "KRB5",          # KRB5CCNAME, KRB5_CONFIG...
    "WGET",          # WGETRC...
})

DANGEROUS_ENV_NAMES: frozenset[str] = frozenset({
    # Interpreter start-up hooks without a covering prefix.
    "ENV",
    "IFS",
    "ZDOTDIR",
    "SHELLOPTS",
    "BASHOPTS",
    "CDPATH",
    "GLOBIGNORE",
    "PROMPT_COMMAND",
    # Interactive-shell prompt/pager hooks (never needed non-interactively).
    "PS1",
    "PS2",
    "PS3",
    "PS4",
    "TMOUT",
    "POSIXLY_CORRECT",
    # Compilers / build systems.
    "CC",
    "CXX",
    "CFLAGS",
    "CXXFLAGS",
    "LDFLAGS",
    "MAKEFLAGS",
    "MAKELEVEL",
    "MFLAGS",
    # Toolchain binaries the build can repoint at attacker-controlled programs.
    "LD",
    "AR",
    "AS",
    "RANLIB",
    "STRIP",
    "OBJCOPY",
    "NM",
    # JVM toolchain (prefix JAVA covers the JAVA_* option variables;
    # _JAVA_OPTIONS does not start with JAVA so it is listed explicitly).
    "_JAVA_OPTIONS",
    "CLASSPATH",
    "NODE_ENV",
    # Editors / pagers that can execute helper programs.
    "EDITOR",
    "VISUAL",
    "PAGER",
    "MANPAGER",
    "SYSTEMD_PAGER",
    "BROWSER",
    "LESSOPEN",
    "LESSCLOSE",
    "LESSECHO",
    "FCEDIT",
    "EXECSHELL",
    # Terminal capability database redirection.
    "TERMINFO",
    "TERMINFO_DIRS",
    # Network / TLS trust redirection.
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "FTP_PROXY",
    "SOCKS_SERVER",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HOSTALIASES",
    "RES_OPTIONS",
    "LOCALDOMAIN",
    # Locale redirection.
    "GCONV_PATH",
    "NLSPATH",
    "LOCPATH",
    "CHARSETALIASDIR",
    # Session / display bridges (XDG_/DBUS_ prefixes cover most; these are
    # kept as explicit documentation of the referral/user-agent style hooks).
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "SSH_AGENT_PID",
    # Secrets / agent redirection without a covering prefix.
    "GNUPGHOME",
    "GPG_AGENT_INFO",
    "XDG_RUNTIME_DIR",  # documented specifically: credential/socket staging dir
    # Environment redirection of well-known tool state.
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "GIT_CONFIG_COUNT",  # redundant with GIT_ prefix; kept as documentation
})

# Locales retained conditionally (besides LANG / LANGUAGE).
_LOCALE_LC_KEYS: tuple[str, ...] = (
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
)

_TERM_RE = re.compile(r"[A-Za-z0-9._+-]{1,64}")
_TZ_RE = re.compile(r"[A-Za-z0-9_+:/.-]{1,128}")
_LANG_RE = re.compile(r"[A-Za-z0-9_.@-]{1,64}")
_LC_RE = re.compile(r"[A-Za-z0-9_.@:-]{1,128}")
_USER_TOKEN_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")


def _read_only_parent(parent: Mapping[str, str] | None) -> Mapping[str, str]:
    """Return a read-only view of the parent mapping (never mutated)."""
    if parent is None:
        return MappingProxyType(os.environ)
    return MappingProxyType(parent)


def _effective_uid() -> int | None:
    """Current effective UID, or None on platforms without POSIX UIDs."""
    try:
        return os.geteuid()
    except AttributeError:  # non-POSIX platform
        return None


def _passwd_account() -> tuple[str, str] | None:
    """Return (account_name, home_directory) for the effective UID.

    Returns None when the passwd database is unavailable (non-POSIX
    platform), the uid has no passwd entry, or the lookup fails. Callers
    fall back to documented non-privileged behaviour.
    """
    uid = _effective_uid()
    if uid is None:
        return None
    try:
        import pwd
    except ImportError:  # non-POSIX platform
        return None
    try:
        entry = pwd.getpwuid(uid)
    except (KeyError, OSError):
        return None
    return entry.pw_name, entry.pw_dir


def _is_trusted_directory(directory: str) -> bool:
    """Validate one candidate PATH directory for the child environment.

    A directory is trusted only when it is absolute, exists, is a real
    directory (symlinks are followed for the stat), is owned by root, is not
    group- or other-writable, and is searchable (X_OK) by the current user.
    """
    try:
        if not directory or "\x00" in directory:
            return False
        if not os.path.isabs(directory):
            return False
        stat_result = os.stat(directory)  # follows symlinks by design
        if not stat.S_ISDIR(stat_result.st_mode):
            return False
        if stat_result.st_uid != 0:
            return False
        if stat_result.st_mode & 0o022:  # group/other writable
            return False
        if not os.access(directory, os.X_OK):
            return False
    except OSError:
        return False
    return True


def build_child_environment(
    *,
    cwd: str | os.PathLike[str],
    parent: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the explicit allowlist environment for a spawned child command.

    Args:
        cwd: Working directory the child will run in; its absolute form
            becomes the child ``PWD``.
        parent: Parent environment to source optional values from. Defaults
            to a read-only view of ``os.environ``. The mapping is never
            mutated and ``os.environ`` is never written to.

    Returns:
        A new dictionary containing only the documented, validated
        allowlist variables. Raises ``RuntimeError`` when the policy cannot
        be satisfied (no trusted PATH directory, tripwire violation).

    Raises:
        RuntimeError: If no trusted PATH directory validates or the final
            tripwire detects a dangerous key in the built environment.
    """
    parent_env = _read_only_parent(parent)
    result: dict[str, str] = {}

    # PATH: trusted system directories only (fail closed if none validate).
    result["PATH"] = _trusted_path_or_raise()

    # HOME: anchor to the account's passwd home; env redirection of HOME is
    # a known configuration-hijack vector for Git and package managers.
    result["HOME"] = _policy_home(parent_env)

    # USER / LOGNAME: passwd identity, sanitized fallback, "unknown".
    account_name = _policy_user(parent_env)
    result["USER"] = account_name
    result["LOGNAME"] = account_name

    # SHELL: fixed non-interactive shell; never inherit the parent's shell
    # (startup-hook leakage into tools that consult $SHELL).
    result["SHELL"] = "/bin/sh"

    # PWD: absolute form of the requested working directory.
    result["PWD"] = os.path.abspath(os.fspath(cwd))

    # TERM: strict pattern only; escape-payload-looking values -> "dumb".
    result["TERM"] = _policy_term(parent_env)

    # TMPDIR: absolute, NUL-free only; otherwise omit (tools use /tmp).
    tmpdir = _policy_tmpdir(parent_env)
    if tmpdir is not None:
        result["TMPDIR"] = tmpdir

    # TZ: strict pattern only; anything else -> "UTC".
    result["TZ"] = _policy_tz(parent_env)

    # Locale compatibility: LANG validated (else "C.UTF-8"), LC_* and
    # LANGUAGE retained only when they match the locale pattern; LC_ALL is
    # never forced over a valid parent value.
    locale_values = _policy_locale(parent_env)
    result.update(locale_values)

    # SSH_AUTH_SOCK: validated agent socket for ordinary git-over-SSH.
    ssh_auth_sock = _policy_ssh_auth_sock(parent_env)
    if ssh_auth_sock is not None:
        result["SSH_AUTH_SOCK"] = ssh_auth_sock

    # Final tripwire: no retained key may match a documented dangerous
    # name/prefix. A violation is a policy bug: fail closed.
    for key in result:
        if is_dangerous_environment_key(key):
            raise RuntimeError(
                "child environment policy rejected dangerous key"
            )
    return result


def is_dangerous_environment_key(key: str) -> bool:
    """Return True when the key matches the documented dangerous lists."""
    if not isinstance(key, str) or not key or "\x00" in key:
        return True
    normalized = key.upper()
    if normalized in DANGEROUS_ENV_NAMES:
        return True
    return any(
        normalized.startswith(prefix) for prefix in DANGEROUS_ENV_PREFIXES
    )


def _trusted_path_or_raise() -> str:
    """Join validated trusted PATH directories; fail closed if none."""
    entries: list[str] = []
    seen_resolved: set[str] = set()
    for directory in TRUSTED_PATH_DIRS:
        if not _is_trusted_directory(directory):
            continue
        resolved = os.path.realpath(directory)
        if resolved in seen_resolved:
            continue  # deduplicate aliasing (e.g. /bin -> /usr/bin)
        seen_resolved.add(resolved)
        entries.append(directory)
    if not entries:
        raise RuntimeError(
            "child environment policy found no trusted PATH directory"
        )
    return ":".join(entries)


def _policy_home(parent_env: Mapping[str, str]) -> str:
    """HOME is the passwd home of the current account when absolute.

    Fallback: a valid absolute parent HOME; final fallback "/". Never trust
    a relative or hostile redirected HOME because package-manager config
    resolution depends on it.
    """
    account = _passwd_account()
    if account is not None:
        home = account[1]
        if isinstance(home, str) and home and os.path.isabs(home) and "\x00" not in home:
            return home
    parent_home = parent_env.get("HOME", "")
    if (
        isinstance(parent_home, str)
        and parent_home
        and os.path.isabs(parent_home)
        and "\x00" not in parent_home
    ):
        return parent_home
    return "/"


def _policy_user(parent_env: Mapping[str, str]) -> str:
    """User identity: passwd name; sanitized parent token; "unknown"."""
    account = _passwd_account()
    if account is not None:
        return account[0]
    parent_user = parent_env.get("USER", "")
    if isinstance(parent_user, str) and _USER_TOKEN_RE.fullmatch(parent_user):
        return parent_user
    return "unknown"


def _policy_term(parent_env: Mapping[str, str]) -> str:
    """TERM: strict terminal-name pattern only, else "dumb"."""
    value = parent_env.get("TERM", "")
    if isinstance(value, str) and _TERM_RE.fullmatch(value):
        return value
    return "dumb"


def _policy_tmpdir(parent_env: Mapping[str, str]) -> str | None:
    """TMPDIR only when absolute and NUL-free; otherwise omitted."""
    value = parent_env.get("TMPDIR", "")
    if (
        isinstance(value, str)
        and value
        and os.path.isabs(value)
        and "\x00" not in value
    ):
        return value
    return None


def _policy_tz(parent_env: Mapping[str, str]) -> str:
    """TZ: strict zone-name/offset pattern only, else "UTC"."""
    value = parent_env.get("TZ", "")
    if isinstance(value, str) and _TZ_RE.fullmatch(value):
        return value
    return "UTC"


def _policy_locale(parent_env: Mapping[str, str]) -> dict[str, str]:
    """LANG plus conditionally retained LC_* / LANGUAGE variables.

    LANG falls back to "C.UTF-8" so the child always has an explicit
    encoding choice; LC_* and LANGUAGE are dropped when invalid rather than
    replaced, and LC_ALL is never forced over a valid parent value to
    preserve legitimate locale configuration.
    """
    values: dict[str, str] = {}
    lang = parent_env.get("LANG", "")
    if isinstance(lang, str) and _LANG_RE.fullmatch(lang):
        values["LANG"] = lang
    else:
        values["LANG"] = "C.UTF-8"
    for key in (*_LOCALE_LC_KEYS, "LANGUAGE"):
        value = parent_env.get(key, "")
        if isinstance(value, str) and _LC_RE.fullmatch(value):
            values[key] = value
    return values


def _policy_ssh_auth_sock(parent_env: Mapping[str, str]) -> str | None:
    """Validated SSH agent socket path or None.

    Requirements: absolute path, existing socket (S_ISSOCK), owned by the
    current effective UID, no group/other access bits. Validated at build
    time; a residual TOCTOU window remains (documented in the module
    docstring) and is bounded by the ownership/permission requirements.
    """
    value = parent_env.get("SSH_AUTH_SOCK", "")
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    if not os.path.isabs(value):
        return None
    uid = _effective_uid()
    if uid is None:  # cannot verify ownership: fail closed
        return None
    try:
        stat_result = os.stat(value)
    except OSError:
        return None
    if not stat.S_ISSOCK(stat_result.st_mode):
        return None
    if stat_result.st_uid != uid:
        return None
    if stat_result.st_mode & 0o077:
        return None
    return value
