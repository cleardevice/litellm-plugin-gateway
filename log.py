"""Structured JSON request logging with secret redaction.

All log lines are single-line JSON so they can be ingested by any log
shipper without parsing. Sensitive material is masked *before* serialization:

* ``Authorization`` header values (Bearer / Basic).
* Any header whose name contains ``key``, ``token``, ``secret`` or ``password``.
* In bodies: ``"api_key"``, ``"api-key"``, ``"key"``, ``"password"``,
  ``"secret"``, ``"token"``, ``Authorization: Basic ...`` and
  ``Bearer <tok>`` substrings (matched case-insensitively).

Masking is best-effort but conservative: when in doubt we redact more rather
than less. The masking passes run on both request and response bodies so that
endpoints like ``/key/generate`` cannot leak freshly minted keys into logs.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from config import settings

# Header names (lowercased) whose values are secret. Anything containing one
# of these substrings is masked in full.
_SENSITIVE_HEADER_HINTS = ("key", "token", "secret", "password", "auth", "cookie")

# JSON keys (case-insensitive) whose string values should be masked when
# found inside a request/response body.
_SENSITIVE_BODY_KEYS = (
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
)


def mask_key(key: str) -> str:
    """Mask a secret, preserving enough to identify which secret it was.

    Short values are fully redacted so as not to leak length information.
    """
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return key[:3] + "***" + key[-3:]


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl == "authorization":
            # Preserve scheme prefix so logs remain readable.
            if v.lower().startswith("bearer "):
                sanitized[k] = "Bearer " + mask_key(v[7:].strip())
            elif v.lower().startswith("basic "):
                sanitized[k] = "Basic " + mask_key(v[6:].strip())
            else:
                sanitized[k] = mask_key(v)
        elif any(hint in kl for hint in _SENSITIVE_HEADER_HINTS):
            sanitized[k] = mask_key(v)
        else:
            sanitized[k] = v
    return sanitized


# Pre-compiled redaction patterns for bodies. Each replaces the captured
# secret with its masked form. Order matters slightly: we mask Bearer / Basic
# phrases first, then JSON-style key/value pairs.
_BEARER_RE = re.compile(r"(?i)\bBearer\s+(\S+)")
_BASIC_RE = re.compile(r"(?i)\bBasic\s+([A-Za-z0-9._~+/=-]+)")
# Match "key":"value" pairs for any of the sensitive keys. The value may not
# contain an unescaped double quote.
_JSON_KEY_RE = re.compile(
    r'(?i)("(?:' + "|".join(re.escape(k) for k in _SENSITIVE_BODY_KEYS) + r')"\s*:\s*")([^"]*)(")'
)


def _mask_bearer(m: re.Match[str]) -> str:
    return "Bearer " + mask_key(m.group(1))


def _mask_basic(m: re.Match[str]) -> str:
    return "Basic " + mask_key(m.group(1))


def _mask_json_value(m: re.Match[str]) -> str:
    return m.group(1) + mask_key(m.group(2)) + m.group(3)


def sanitize_body(body: bytes) -> bytes:
    """Best-effort redaction of secrets inside an arbitrary body.

    Operates on a UTF-8 (lossy) decode so it works for JSON, form-encoded and
    plain-text payloads. Anything we cannot decode is returned unchanged —
    binary content is unlikely to contain the patterns above.
    """
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return body
    text = _BEARER_RE.sub(_mask_bearer, text)
    text = _BASIC_RE.sub(_mask_basic, text)
    text = _JSON_KEY_RE.sub(_mask_json_value, text)
    return text.encode("utf-8")


def body_preview(body: bytes, max_bytes: int = 200) -> str:
    if not body:
        return "(empty)"
    sanitized = sanitize_body(body)
    if len(sanitized) > max_bytes:
        return sanitized[:max_bytes].decode("utf-8", errors="replace") + "..."
    return sanitized.decode("utf-8", errors="replace")


def body_full(body: bytes, max_bytes: int = 4096) -> str:
    if not body:
        return "(empty)"
    sanitized = sanitize_body(body)
    if len(sanitized) > max_bytes:
        return (
            sanitized[:max_bytes].decode("utf-8", errors="replace")
            + f"  [truncated {max_bytes}/{len(sanitized)}]"
        )
    return sanitized.decode("utf-8", errors="replace")


def _ts() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_request(
    *,
    rid: str,
    rtype: str,
    method: str,
    path: str,
    status: int,
    latency_ms: float,
    req_headers: dict[str, str] | None = None,
    req_body: bytes | None = None,
    res_headers: dict[str, str] | None = None,
    res_body: bytes | None = None,
    is_streaming: bool = False,
    error: str | None = None,
) -> None:
    """Emit a single JSON log line for a proxied request.

    ``error`` is the upstream exception text (if any) — included here for
    operators but never returned to the client (see ``main._error_response``).
    """
    level = settings.valid_log_level

    # Health probes are silenced at the minimal level to keep logs readable.
    if level == "minimal" and path in settings.quiet_path_set:
        return

    if level == "minimal":
        _log_line(rid, rtype, method, path, status, latency_ms, error)
    elif level == "headers":
        _log_headers(
            rid,
            rtype,
            method,
            path,
            status,
            latency_ms,
            req_headers,
            req_body,
            res_headers,
            is_streaming,
            error,
        )
    elif level == "body":
        _log_body(
            rid,
            rtype,
            method,
            path,
            status,
            latency_ms,
            req_headers,
            req_body,
            res_headers,
            res_body,
            is_streaming,
            error,
        )


def log_forbidden(rid: str, rtype: str, method: str, path: str) -> None:
    """Emit a 403-style line. Kept for callers that want to log denials
    explicitly without going through ``log_request``."""
    print(
        json.dumps(
            {
                "ts": _ts(),
                "rid": rid,
                "type": rtype,
                "method": method,
                "path": path,
                "status": 403,
                "error": "forbidden",
            }
        )
    )


def _base_entry(
    rid: str,
    rtype: str,
    method: str,
    path: str,
    status: int,
    latency_ms: float,
    error: str | None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "ts": _ts(),
        "rid": rid,
        "type": rtype,
        "method": method,
        "path": path,
        "status": status,
        "latency_ms": round(latency_ms, 2),
    }
    if error:
        entry["error"] = error
    return entry


def _log_line(
    rid: str,
    rtype: str,
    method: str,
    path: str,
    status: int,
    latency_ms: float,
    error: str | None = None,
) -> None:
    print(json.dumps(_base_entry(rid, rtype, method, path, status, latency_ms, error)))


def _log_headers(
    rid: str,
    rtype: str,
    method: str,
    path: str,
    status: int,
    latency_ms: float,
    req_headers: dict[str, str] | None,
    req_body: bytes | None,
    res_headers: dict[str, str] | None,
    is_streaming: bool,
    error: str | None = None,
) -> None:
    entry = _base_entry(rid, rtype, method, path, status, latency_ms, error)
    if req_headers:
        entry["req_headers"] = sanitize_headers(req_headers)
    if req_body:
        entry["req_body_preview"] = body_preview(req_body)
    if res_headers:
        entry["res_headers"] = sanitize_headers(res_headers)
    if is_streaming:
        entry["streaming"] = True
    print(json.dumps(entry, ensure_ascii=False))


def _log_body(
    rid: str,
    rtype: str,
    method: str,
    path: str,
    status: int,
    latency_ms: float,
    req_headers: dict[str, str] | None,
    req_body: bytes | None,
    res_headers: dict[str, str] | None,
    res_body: bytes | None,
    is_streaming: bool,
    error: str | None = None,
) -> None:
    entry = _base_entry(rid, rtype, method, path, status, latency_ms, error)
    if req_headers:
        entry["req_headers"] = sanitize_headers(req_headers)
    if req_body:
        entry["req_body"] = body_full(req_body)
    if res_headers:
        entry["res_headers"] = sanitize_headers(res_headers)
    if is_streaming:
        entry["streaming"] = True
        entry["res_body"] = "(streaming)"
    elif res_body:
        entry["res_body"] = body_full(res_body)
    print(json.dumps(entry, ensure_ascii=False))
