"""Unit tests for access control: path normalization, allow-list, token parsing."""

import pytest

from access import (
    ALLOWED_PREFIXES,
    extract_bearer_token,
    is_allowed,
    is_plugin_token,
    normalize_path,
)

# ── normalize_path ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/spend/logs", "/spend/logs"),
        ("/key/info", "/key/info"),
        # Trailing slash is PRESERVED so upstream directory redirects
        # (e.g. /ui → /ui/) keep working instead of looping forever.
        ("/key/info/", "/key/info/"),
        ("/ui/", "/ui/"),
        ("/ui", "/ui"),
        ("/health/liveliness", "/health/liveliness"),
        ("/", "/"),
        ("/a", "/a"),
    ],
)
def test_normalize_path_valid(path, expected):
    assert normalize_path(path) == expected


@pytest.mark.parametrize(
    "path",
    [
        "/key/info/../generate",  # literal traversal
        "/spend/logs/../key/generate",
        "/key/%2E%2E/generate",  # percent-encoded traversal
        "/key/%2e%2e/generate",
        "/%2E%2E/etc/passwd",
        "/key\\info",  # backslash
        "/key\x00info",  # NUL byte
        "//../etc",  # leading double slash + traversal
    ],
)
def test_normalize_path_rejects_traversal(path):
    assert normalize_path(path) is None


def test_normalize_path_collapses_interior_slashes():
    # Interior // is collapsed (matches what httpx will dispatch upstream),
    # but a single trailing slash is preserved.
    assert normalize_path("//key//info") == "/key/info"
    assert normalize_path("//key//info//") == "/key/info/"


def test_normalize_path_preserves_trailing_slash():
    """Regression: stripping the trailing slash caused /ui → /ui/ redirect
    loops because the gateway kept rewriting /ui/ back to /ui."""
    assert normalize_path("/ui/") == "/ui/"
    assert normalize_path("/ui") == "/ui"
    assert normalize_path("/spend/logs/") == "/spend/logs/"


def test_normalize_path_empty():
    assert normalize_path("") is None


# ── is_allowed ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        "/spend",
        "/spend/logs",
        "/spend/keys",
        "/global/spend",
        "/key/info",
        "/key/info/abc",
        "/key/info/",  # trailing slash tolerated by is_allowed even though preserved
        "/model/info",
        "/health",
        "/health/liveliness",
        "/health/",
    ],
)
def test_is_allowed_true(path):
    assert is_allowed(normalize_path(path))


@pytest.mark.parametrize(
    "path",
    [
        "/key/generate",
        "/key/infoleak",  # must NOT match "/key/info" via startswith-on-string
        "/model/new",
        "/team/list",
        "/v1/chat/completions",
        "/spendx",  # sibling prefix, must not match
        "/",
    ],
)
def test_is_allowed_false(path):
    norm = normalize_path(path)
    assert norm is not None
    assert not is_allowed(norm)


def test_allowed_prefixes_are_stable():
    # Document the operational contract; bump in tests when adding a path.
    assert "/spend" in ALLOWED_PREFIXES
    assert "/key/info" in ALLOWED_PREFIXES
    assert "/key/generate" not in ALLOWED_PREFIXES


# ── extract_bearer_token ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "header",
    [
        "Bearer abc123",
        "bearer abc123",
        "BEARER abc123",
        "BeArEr abc123",
        "Bearer   abc123",  # extra spaces stripped
    ],
)
def test_extract_bearer_token_success(header):
    assert extract_bearer_token(header) == "abc123"


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "abc123",
        "Basic dXNlcjpwYXNz",
        "Bearer",  # no token
        "Bearer ",  # empty token
        "Token abc123",
    ],
)
def test_extract_bearer_token_failure(header):
    assert extract_bearer_token(header) is None


# ── is_plugin_token (constant-time compare) ────────────────────────────────


def test_is_plugin_token_match():
    keys = frozenset({"plugin_one", "plugin_two"})
    assert is_plugin_token("plugin_one", keys) is True
    assert is_plugin_token("plugin_two", keys) is True


def test_is_plugin_token_no_match():
    keys = frozenset({"plugin_one"})
    assert is_plugin_token("plugin_other", keys) is False


def test_is_plugin_token_empty_set_denies():
    assert is_plugin_token("anything", frozenset()) is False


def test_is_plugin_token_none_denies():
    assert is_plugin_token(None, frozenset({"x"})) is False


def test_is_plugin_token_empty_string_denies():
    assert is_plugin_token("", frozenset({"x"})) is False
