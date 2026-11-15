"""Pure parsing of ``git clone`` invocations for post-clone review (3A.5).

This module is deliberately side-effect free: it inspects the argument vector
of a ``git clone`` command and determines the repository source, the
destination worktree directory, and whether the clone is bare/mirror (which
produces no reviewable worktree). It implements Git 2.53 option semantics per
the 3A.5 explorer findings.

The parser fails closed: when the destination cannot be determined without
ambiguity it returns an error instead of guessing. A wrong guess after a
successful clone would let the wrapper claim a review of content it cannot
locate, so errors are always surfaced to the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class CloneInvocation:
    """Parsed ``git clone`` invocation.

    ``error`` is non-None only when the invocation could not be parsed or the
    destination could not be determined without guessing; callers must treat
    an error as "post-clone review impossible" (fail closed).
    """

    repository: str
    destination: Path | None
    bare: bool
    mirror: bool
    error: str | None


# Long options that always consume a value: attached via '=' or the next argv
# token. Short aliases map to their long names (values may be attached, e.g.
# -bmain, -j2).
VALUE_LONG: frozenset[str] = frozenset({
    "branch",          # -b
    "revision",
    "upload-pack",     # -u
    "depth",
    "shallow-since",
    "shallow-exclude",
    "origin",          # -o
    "template",
    "reference",
    "reference-if-able",
    "separate-git-dir",
    "ref-format",
    "config",          # -c
    "server-option",
    "filter",
    "bundle-uri",
    "jobs",            # -j
})
VALUE_SHORT: dict[str, str] = {
    "b": "branch",
    "u": "upload-pack",
    "o": "origin",
    "c": "config",
    "j": "jobs",
}

# Long options that take an optional value which is only ever attached via
# '='; a bare occurrence is a boolean flag.
OPTIONAL_VALUE_LONG: frozenset[str] = frozenset({
    "recurse-submodules",
    "recursive",
})

# Boolean options: they never consume the next argv token.
BOOL_SHORT_CHARS: frozenset[str] = frozenset("nlsqv46")
BOOL_LONG: frozenset[str] = frozenset({
    "bare",
    "mirror",
    "no-checkout",
    "checkout",
    "progress",
    "reject-shallow",
    "no-hardlinks",
    "hardlinks",
    "dissociate",
    "single-branch",
    "no-single-branch",
    "tags",
    "no-tags",
    "shallow-submodules",
    "also-filter-submodules",
    "remote-submodules",
    "sparse",
    "quiet",
    "verbose",
    "local",
    "shared",
    "ipv4",            # long alias of -4
    "ipv6",            # long alias of -6
})

KNOWN_LONG: frozenset[str] = BOOL_LONG | OPTIONAL_VALUE_LONG | VALUE_LONG


def _error(message: str) -> CloneInvocation:
    return CloneInvocation(repository="", destination=None, bare=False,
                           mirror=False, error=message)


def _default_destination_name(repository: str) -> str | None:
    """Derive the destination directory name from a repository source.

    Mirrors human-readable Git behavior: trim trailing slashes, take the last
    component after '/' or after a ':' (scp-like syntax), then strip one
    trailing '.git'. Returns None when the result would be empty, '.', '..',
    or otherwise undeterminable.
    """
    if not repository:
        return None
    cleaned = repository.rstrip("/")
    if not cleaned:
        return None
    start = max(cleaned.rfind("/"), cleaned.rfind(":")) + 1
    name = cleaned[start:]
    if name.endswith(".git"):
        name = name[:-4]
    if not name or name in {".", ".."}:
        return None
    return name


def _resolve_destination(base: Path, destination_arg: str) -> Path | None:
    """Resolve a destination argument relative to ``base`` without expanding ``~``."""
    try:
        return (base / destination_arg).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None


def parse_clone_invocation(argv: Sequence[str], cwd: str | Path) -> CloneInvocation:
    """Parse a full ``git clone`` argv against ``cwd``.

    Args:
        argv: The complete argument vector, e.g. ``("git", "clone", "--bare", url)``.
        cwd: Working directory the command runs in; relative destinations and
            derived destinations resolve against this directory.

    Returns:
        A :class:`CloneInvocation`. On any parse or resolution failure the
        result carries ``error`` and no destination.
    """
    argv = tuple(argv)
    if len(argv) < 3:
        return _error("git clone requires a repository argument")
    if Path(argv[0]).name.lower() != "git":
        return _error("not a git invocation")
    if argv[1] != "clone":
        return _error("not a git clone invocation")

    tokens = list(argv[2:])
    positionals: list[str] = []
    bare = False
    mirror = False
    index = 0

    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            positionals.extend(tokens[index + 1:])
            break
        if token.startswith("--"):
            name, sep, attached = token[2:].partition("=")
            if name in OPTIONAL_VALUE_LONG:
                # Value only when attached via '='; never consumes the next token.
                index += 1
                continue
            if name in VALUE_LONG:
                if not sep:
                    if index + 1 >= len(tokens):
                        return _error(f"git clone option {token} requires a value")
                    index += 2
                else:
                    index += 1
                continue
            if name in BOOL_LONG:
                if sep:
                    return _error(f"git clone option {token} does not take a value")
                if name == "bare":
                    bare = True
                elif name == "mirror":
                    mirror = True
                index += 1
                continue
            if not sep and name.startswith("no-") and name[3:] in KNOWN_LONG:
                # --no-X negations are booleans and never consume a token.
                if name == "no-bare":
                    bare = False
                elif name == "no-mirror":
                    mirror = False
                index += 1
                continue
            return _error(f"unknown git clone option {token}")
        if token.startswith("-") and len(token) > 1:
            cluster = token[1:]
            position = 0
            consumed_value = False
            while position < len(cluster):
                char = cluster[position]
                if char in BOOL_SHORT_CHARS:
                    position += 1
                    continue
                if char in VALUE_SHORT:
                    rest = cluster[position + 1:]
                    if rest:
                        # Attached value (e.g. -bmain, -j2) never consumes argv.
                        pass
                    elif index + 1 < len(tokens):
                        # Detached value: next token belongs to this option.
                        index += 1
                    else:
                        return _error(f"git clone option -{char} requires a value")
                    consumed_value = True
                    break
                return _error(f"unknown git clone option {token}")
            _ = consumed_value
            index += 1
            continue
        positionals.append(token)
        index += 1

    if len(positionals) < 1:
        return _error("git clone requires a repository argument")
    if len(positionals) > 2:
        return _error("git clone accepts at most two positional arguments")

    repository = positionals[0]
    if not repository:
        return _error("git clone repository argument is empty")

    if len(positionals) == 2:
        # The explicit destination wins and is used exactly as given.
        if not positionals[1]:
            return _error("git clone explicit destination is empty")
        destination_arg = positionals[1]
    else:
        name = _default_destination_name(repository)
        if name is None:
            return _error(
                "cannot determine git clone destination directory name"
            )
        destination_arg = name

    destination = _resolve_destination(Path(cwd), destination_arg)
    if destination is None:
        return _error("git clone destination path is not usable")

    return CloneInvocation(
        repository=repository,
        destination=destination,
        bare=bare,
        mirror=mirror,
        error=None,
    )
