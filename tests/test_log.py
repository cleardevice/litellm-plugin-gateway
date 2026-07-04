"""Unit tests for log redaction and level handling."""

import json

import pytest

import config
from log import (
    body_full,
    body_preview,
    log_request,
    mask_key,
    sanitize_body,
    sanitize_headers,
)

# ── mask_key ───────────────────────────────────────────────────────────────


def test_mask_key_short_fully_redacted():
    # Short values must not leak length beyond the cap.
    assert mask_key("abcd") == "****"
    assert mask_key("12345678") == "********"


def test_mask_key_long_shows_ends():
    out = mask_key("sk-abcdef-1234567890")
    assert out.startswith("sk-")
    assert out.endswith("***890")
    assert "abcdef" not in out
    assert "1234567" not in out


def test_mask_key_empty():
    assert mask_key("") == ""


# ── sanitize_headers ───────────────────────────────────────────────────────


def test_sanitize_headers_authorization_bearer():
    out = sanitize_headers({"Authorization": "Bearer sk-secret-1234567"})
    assert out["Authorization"] == "Bearer sk-***567"
    assert "sk-secret-1234567" not in out["Authorization"]


def test_sanitize_headers_authorization_basic():
    out = sanitize_headers({"Authorization": "Basic dXNlcjpwYXNz"})
    assert "dXNlcjpwYXNz" not in out["Authorization"]
    assert out["Authorization"].startswith("Basic ")


def test_sanitize_headers_authorization_unknown_scheme():
    out = sanitize_headers({"Authorization": "Digest abcdef1234567890"})
    assert "abcdef" not in out["Authorization"]


def test_sanitize_headers_sensitive_names():
    raw = {
        "X-API-Key": "sk-secret-1234567890",
        "X-Auth-Token": "tok-secret-1234567890",
        "Cookie": "session=abc1234567",
        "Set-Cookie": "sess=xyz12345678",
        "X-Password": "pwpwpw1234567890",
        "Innocent": "keep-me",
    }
    out = sanitize_headers(raw)
    assert "sk-secret" not in out["X-API-Key"]
    assert "tok-secret" not in out["X-Auth-Token"]
    assert "abc1234567" not in out["Cookie"]
    assert "xyz12345678" not in out["Set-Cookie"]
    assert "pwpwpw" not in out["X-Password"]
    assert out["Innocent"] == "keep-me"


# ── sanitize_body ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "field",
    [
        "api_key",
        "api-key",
        "apikey",
        "key",
        "token",
        "password",
        "passwd",
        "secret",
        "authorization",
        "access_token",
        "refresh_token",
    ],
)
def test_sanitize_body_masks_known_json_keys(field):
    secret = "sk-leaked-1234567890"
    body = f'{{"{field}":"{secret}"}}'.encode()
    out = sanitize_body(body).decode()
    assert secret not in out
    # Masked form should retain first/last 3 chars of a long value.
    assert "sk-" in out  # first 3 preserved


@pytest.mark.parametrize("field", ["api_key", "KEY", "ApiKey", "Access_Token"])
def test_sanitize_body_case_insensitive(field):
    secret = "sk-leaked-1234567890"
    body = f'{{"{field}":"{secret}"}}'.encode()
    assert secret not in sanitize_body(body).decode()


def test_sanitize_body_bearer_phrase():
    body = b"grant_type=refresh_token&access_token=Bearer sk-leaked-1234567890"
    out = sanitize_body(body).decode()
    assert "sk-leaked" not in out


def test_sanitize_body_basic_phrase():
    body = b"auth=Basic dXNlcjpwYXNzOjEyMzQ="
    out = sanitize_body(body).decode()
    assert "dXNlcjpwYXNzOjEyMzQ=" not in out


def test_sanitize_body_preserves_non_secret_json():
    body = b'{"model":"gpt-4","temperature":0.7,"messages":[{"role":"user","content":"hi"}]}'
    assert sanitize_body(body) == body


def test_sanitize_body_binary_passthrough():
    # Bytes that aren't valid UTF-8 should pass through unchanged.
    body = b"\xff\xfe\x00binary"
    assert sanitize_body(body) == body


# ── body_preview / body_full ───────────────────────────────────────────────


def test_body_preview_truncates():
    body = b"x" * 500
    out = body_preview(body, max_bytes=10)
    assert out.endswith("...")
    assert len(out) <= 13


def test_body_full_truncates_with_marker():
    body = b'{"key":"sk-abcdefghij1234567890"}'
    out = body_full(body, max_bytes=10)
    assert "truncated" in out


def test_body_empty():
    assert body_preview(b"") == "(empty)"
    assert body_full(b"") == "(empty)"


# ── log level handling (regression for os.environ bypass) ──────────────────


def test_log_level_from_settings(capsys, monkeypatch):
    """settings.valid_log_level must drive log output, not os.environ."""
    monkeypatch.setattr(config.settings, "log_level", "minimal")
    monkeypatch.setenv("LOG_LEVEL", "body")  # must be IGNORED now
    log_request(
        rid="test1",
        rtype="normal",
        method="GET",
        path="/spend/logs",
        status=200,
        latency_ms=10.0,
        req_headers={"Authorization": "Bearer x"},
        req_body=b'{"key":"sk-leaked-1234567890"}',
    )
    line = json.loads(capsys.readouterr().out)
    # Minimal level → only base fields, no body.
    assert "req_body" not in line
    assert line["rid"] == "test1"


def test_log_level_body_includes_body(capsys, monkeypatch):
    monkeypatch.setattr(config.settings, "log_level", "body")
    log_request(
        rid="test2",
        rtype="normal",
        method="GET",
        path="/spend/logs",
        status=200,
        latency_ms=10.0,
        req_body=b'{"key":"sk-leaked-1234567890"}',
    )
    line = json.loads(capsys.readouterr().out)
    assert "req_body" in line
    assert "sk-leaked" not in line["req_body"]


def test_log_level_invalid_falls_back_to_headers(capsys, monkeypatch):
    monkeypatch.setattr(config.settings, "log_level", "nonsense")
    log_request(
        rid="test3",
        rtype="normal",
        method="GET",
        path="/spend/logs",
        status=200,
        latency_ms=1.0,
        req_headers={"x-api-key": "sk-leaked-1234567890"},
    )
    line = json.loads(capsys.readouterr().out)
    assert "req_headers" in line  # headers-level fallback
    assert "req_body" not in line
    assert "sk-leaked" not in json.dumps(line)


def test_quiet_path_silenced_at_minimal(capsys, monkeypatch):
    monkeypatch.setattr(config.settings, "log_level", "minimal")
    log_request(
        rid="quiet",
        rtype="normal",
        method="GET",
        path="/health/liveliness",
        status=200,
        latency_ms=1.0,
    )
    captured = capsys.readouterr().out
    assert captured == ""


def test_error_field_included_when_provided(capsys, monkeypatch):
    monkeypatch.setattr(config.settings, "log_level", "minimal")
    log_request(
        rid="e1",
        rtype="normal",
        method="GET",
        path="/x",
        status=502,
        latency_ms=1.0,
        error="ConnectError: boom",
    )
    line = json.loads(capsys.readouterr().out)
    assert line.get("error") == "ConnectError: boom"
