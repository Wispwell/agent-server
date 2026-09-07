"""Tests for resource extraction — the security-critical parsing.

Most of these are attacks. A resolver bug is invisible everywhere else in the
system: signatures still verify, rules still fire, and the boundary is gone.
"""

from __future__ import annotations

import os

import pytest

from agentserver.tools.resolvers import (
    ResolutionError,
    Root,
    literal_field,
    path_under_root,
    resolve,
    url_host,
)


@pytest.fixture
def root(tmp_path):
    (tmp_path / "workspace" / "reports").mkdir(parents=True)
    (tmp_path / "workspace" / "reports" / "q3.md").write_text("ok")
    (tmp_path / "outside.txt").write_text("secret")
    return Root("workspace", tmp_path / "workspace")


CFG = {"field": "path", "root": "workspace"}


# --------------------------------------------------------------------------
# path traversal — the classic way a scope check is defeated
# --------------------------------------------------------------------------


def test_a_normal_path_resolves_to_a_named_resource(root):
    assert path_under_root({"path": "reports/q3.md"}, CFG, root=root) == "workspace/reports/q3.md"


def test_redundant_segments_are_normalised(root):
    assert path_under_root({"path": "./reports/./q3.md"}, CFG, root=root) == "workspace/reports/q3.md"
    assert path_under_root({"path": "reports/../reports/q3.md"}, CFG, root=root) == "workspace/reports/q3.md"


@pytest.mark.parametrize(
    "attack",
    [
        "../outside.txt",
        "reports/../../outside.txt",
        "../../../../../../etc/passwd",
        "reports/../../../etc/passwd",
    ],
)
def test_traversal_out_of_the_root_is_refused(root, attack):
    """The raw string matches `workspace/**` by prefix. The resolved path does not."""
    with pytest.raises(ResolutionError, match="escapes"):
        path_under_root({"path": attack}, CFG, root=root)


def test_an_absolute_path_cannot_smuggle_past_the_root(root):
    """os.path.join discards the root when given an absolute path — the
    containment check, not the join, is what catches this."""
    with pytest.raises(ResolutionError, match="escapes"):
        path_under_root({"path": "/etc/passwd"}, CFG, root=root)


def test_a_symlink_pointing_outside_the_root_is_refused(root, tmp_path):
    """Lexical normalisation alone would accept this: the path contains no `..`."""
    os.symlink(tmp_path / "outside.txt", tmp_path / "workspace" / "escape.txt")
    with pytest.raises(ResolutionError, match="escapes"):
        path_under_root({"path": "escape.txt"}, CFG, root=root)


def test_a_symlink_staying_inside_the_root_is_fine(root, tmp_path):
    os.symlink(tmp_path / "workspace" / "reports" / "q3.md",
               tmp_path / "workspace" / "link.md")
    assert path_under_root({"path": "link.md"}, CFG, root=root) == "workspace/reports/q3.md"


def test_home_relative_paths_are_refused(root):
    with pytest.raises(ResolutionError, match="home-relative"):
        path_under_root({"path": "~/.ssh/id_ed25519"}, CFG, root=root)


def test_the_root_itself_resolves_to_the_root_name(root):
    assert path_under_root({"path": "."}, CFG, root=root) == "workspace"


# --------------------------------------------------------------------------
# URL host confusion
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/a/b", "example.com"),
        ("https://EXAMPLE.com/", "example.com"),
        ("https://example.com:8443/x", "example.com"),
        # userinfo: the host is what comes AFTER the '@'
        ("http://allowed.com@evil.com/", "evil.com"),
        ("http://user:pass@evil.com/", "evil.com"),
        # fragment: everything after '#' is not part of the authority
        ("http://evil.com#@allowed.com", "evil.com"),
        ("http://evil.com/?x=allowed.com", "evil.com"),
    ],
)
def test_host_extraction_survives_url_confusion(url, expected):
    """Substring matching on the URL text accepts every one of these."""
    assert url_host({"url": url}, {"field": "url"}) == expected


def test_unicode_homographs_normalise_to_punycode():
    """'а' here is Cyrillic U+0430, not Latin 'a'. It must not compare equal."""
    homograph = "http://аllowed.com/"
    got = url_host({"url": homograph}, {"field": "url"})
    assert got != "allowed.com"
    assert got.startswith("xn--")


@pytest.mark.parametrize(
    "url",
    ["ftp://example.com/x", "file:///etc/passwd", "javascript:alert(1)",
     "http:///nohost", "notaurl", ""],
)
def test_non_http_or_hostless_urls_are_refused(url):
    with pytest.raises(ResolutionError):
        url_host({"url": url}, {"field": "url"})


# --------------------------------------------------------------------------
# argument handling
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [{}, {"path": None}, {"path": 42}, {"path": ["x"]}])
def test_a_missing_or_non_string_argument_is_refused(root, bad):
    with pytest.raises(ResolutionError):
        path_under_root(bad, CFG, root=root)


def test_null_bytes_are_refused(root):
    with pytest.raises(ResolutionError, match="null byte"):
        path_under_root({"path": "reports/q3.md\x00.png"}, CFG, root=root)


def test_a_resolver_config_without_a_field_is_refused(root):
    with pytest.raises(ResolutionError, match="field"):
        path_under_root({"path": "x"}, {"root": "workspace"}, root=root)


def test_literal_field_interprets_nothing():
    assert literal_field({"q": "a/../b"}, {"field": "q"}) == "a/../b"
    with pytest.raises(ResolutionError):
        literal_field({"q": 1}, {"field": "q"})


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------


def test_dispatch_routes_and_supplies_the_root(root):
    assert resolve("path_under_root", {"path": "reports/q3.md"}, CFG,
                   roots={"workspace": root}) == "workspace/reports/q3.md"
    assert resolve("url_host", {"url": "https://a.com/"}, {"field": "url"}) == "a.com"


def test_an_unknown_resolver_is_a_refusal():
    with pytest.raises(ResolutionError, match="unknown resolver"):
        resolve("eval_python", {"x": "1"}, {"field": "x"})


def test_an_unconfigured_root_is_a_refusal(root):
    with pytest.raises(ResolutionError, match="no configured root"):
        resolve("path_under_root", {"path": "x"}, {"field": "path", "root": "nope"},
                roots={"workspace": root})


def test_root_names_may_not_contain_separators(tmp_path):
    with pytest.raises(ValueError):
        Root("a/b", tmp_path)
