"""Resource extraction. M1. Trusted — this is the security-critical parsing.

A resolver turns a tool call's arguments into the resource string that the
scope check compares against a capability token's pattern. It is the one place
where a mistake is invisible: the crypto still verifies, the rules still fire,
and the token scoped to ``workspace/**`` quietly admits ``/etc/passwd``.

Resolvers are code, not configuration, for exactly this reason. Resolving
``..`` and extracting a host from ``http://allowed.com@evil.com/`` is parsing,
and a mini-language for security-critical parsing evaluated out of a mutable
store would be strictly worse than a reviewed function.

**A resolver may refuse.** Unparseable arguments are a denial, never a resource
equal to the raw string.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

__all__ = ["RESOLVERS", "ResolutionError", "Root", "resolve"]


class ResolutionError(Exception):
    """The arguments do not name a resource this resolver can vouch for."""

    reason = "unresolvable"


class Root:
    """A named filesystem root. Resources render as ``<name>/<relative path>``.

    Naming the root keeps ledger entries and token patterns readable
    (``workspace/reports/**``) while the absolute location stays deployment
    configuration.
    """

    def __init__(self, name: str, path: str | os.PathLike):
        if not name or "/" in name:
            raise ValueError("root name must be non-empty and contain no '/'")
        self.name = name
        # realpath once: the root itself may sit behind a symlink
        self.path = os.path.realpath(os.fspath(path))


def _field(args: Mapping[str, Any], config: Mapping[str, Any]) -> str:
    name = config.get("field")
    if not isinstance(name, str):
        raise ResolutionError("resolver_config has no 'field'")
    value = args.get(name)
    if not isinstance(value, str):
        raise ResolutionError(f"argument {name!r} is missing or not a string")
    if "\x00" in value:
        raise ResolutionError("argument contains a null byte")
    return value


def path_under_root(
    args: Mapping[str, Any], config: Mapping[str, Any], *, root: Root
) -> str:
    """Resolve a path argument and confine it to `root`.

    Traversal is the classic way a scope check is defeated: the raw string
    ``workspace/reports/../../../etc/passwd`` matches ``workspace/**`` by
    prefix while resolving somewhere else entirely. So the path is resolved
    first and the result is what gets compared.

    ``realpath`` is used rather than lexical normalisation alone, because a
    symlink inside the root pointing outside it survives every lexical check.

    Known limit: this is a check, and the MCP server opens the file afterwards.
    A symlink created in between would not be caught here (TOCTOU). Closing
    that needs the server itself to be confined — which is what container
    isolation is for, and is post-v0.
    """
    raw = _field(args, config)
    if raw.startswith("~"):
        raise ResolutionError("home-relative paths are not resolvable here")
    candidate = os.path.realpath(os.path.join(root.path, raw))
    if candidate != root.path and not candidate.startswith(root.path + os.sep):
        raise ResolutionError(f"path escapes the {root.name!r} root")
    relative = os.path.relpath(candidate, root.path)
    if relative == ".":
        return root.name
    return f"{root.name}/{relative.replace(os.sep, '/')}"


def url_host(args: Mapping[str, Any], config: Mapping[str, Any]) -> str:
    """Extract the host from a URL argument.

    Substring matching on a URL is defeated trivially — ``allowed.com`` appears
    in both ``http://allowed.com@evil.com/`` (host: evil.com) and
    ``http://evil.com#@allowed.com`` (host: evil.com). Only a real parse gives
    the host the request will actually reach.

    Hosts are normalised to IDNA/punycode so that visually identical Unicode
    homographs cannot compare unequal to their ASCII form.
    """
    raw = _field(args, config)
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise ResolutionError(f"unparseable URL: {exc}") from None
    if parts.scheme not in ("http", "https"):
        raise ResolutionError(f"unsupported scheme: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise ResolutionError("URL has no host")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        raise ResolutionError("host is not a valid domain name") from None
    return host


def literal_field(args: Mapping[str, Any], config: Mapping[str, Any]) -> str:
    """Return an argument verbatim, with no interpretation.

    Only safe with capabilities scoped to exact literal matches, since nothing
    here normalises anything. It exists so a tool with an opaque identifier
    (a queue name, a record id) is bindable without inventing a resolver.
    """
    return _field(args, config)


RESOLVERS: dict[str, Callable[..., str]] = {
    "path_under_root": path_under_root,
    "url_host": url_host,
    "literal_field": literal_field,
}


def resolve(
    name: str,
    args: Mapping[str, Any],
    config: Mapping[str, Any],
    *,
    roots: Mapping[str, Root] | None = None,
) -> str:
    """Dispatch to a named resolver. An unknown resolver is a refusal."""
    fn = RESOLVERS.get(name)
    if fn is None:
        raise ResolutionError(f"unknown resolver: {name!r}")
    if name == "path_under_root":
        root_name = config.get("root")
        root = (roots or {}).get(root_name) if isinstance(root_name, str) else None
        if root is None:
            raise ResolutionError(f"no configured root named {root_name!r}")
        return fn(args, config, root=root)
    return fn(args, config)
