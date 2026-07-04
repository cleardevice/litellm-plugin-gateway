"""Integration tests for the proxy handler.

The handler talks to a mock httpx client stored on ``app.state.client`` by
the lifespan handler. The ``mock_litellm`` fixture swaps that client for an
``AsyncMock`` for the duration of each test.
"""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient

MASTER_KEY = "sk-master-secret-key-12345"
PLUGIN_KEY = "plugin_opencode_costs"
NORMAL_KEY = "sk-normal-user-key"


@pytest.fixture
def mock_litellm():
    """Replace app.state.client with an AsyncMock for one test."""
    from main import app

    mock_client = AsyncMock()
    real = getattr(app.state, "client", None)
    app.state.client = mock_client
    yield mock_client
    app.state.client = real


@pytest.fixture
def client():
    from main import app

    with TestClient(app) as c:
        yield c


def _mock_buffered_response(status=200, body=b'{"ok": true}', headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.content = body
    resp.headers = headers or {"content-type": "application/json"}
    return resp


async def _aiter_chunks(chunks):
    for c in chunks:
        yield c


def _mock_stream_response(status=200, chunks=None, headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {"content-type": "text/event-stream"}
    resp.aiter_bytes = MagicMock(return_value=_aiter_chunks(chunks or [b"data: hello\n\n"]))
    resp.aclose = AsyncMock()
    return resp


# ── Plugin key: allowed endpoints ──────────────────────────────────────────


def test_plugin_key_spend_logs(client, mock_litellm):
    """Plugin key GET /spend/logs → 200, Authorization rewritten to MASTER_KEY."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response(body=b'[{"spend": 1.5}]'))
    resp = client.get("/spend/logs", headers={"Authorization": f"Bearer {PLUGIN_KEY}"})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {MASTER_KEY}"


def test_plugin_key_spend_keys(client, mock_litellm):
    """Plugin key GET /spend/keys → 200, Authorization rewritten."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/spend/keys", headers={"Authorization": f"Bearer {PLUGIN_KEY}"})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {MASTER_KEY}"


def test_plugin_key_key_info(client, mock_litellm):
    """Plugin key GET /key/info → 200, Authorization rewritten."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/key/info", headers={"Authorization": f"Bearer {PLUGIN_KEY}"})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {MASTER_KEY}"


def test_plugin_key_model_info(client, mock_litellm):
    """Plugin key GET /model/info → 200, Authorization rewritten."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/model/info", headers={"Authorization": f"Bearer {PLUGIN_KEY}"})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {MASTER_KEY}"


def test_plugin_key_health(client, mock_litellm):
    """Plugin key GET /health/liveliness → 200, Authorization rewritten."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response(body=b'{"status": "ok"}'))
    resp = client.get("/health/liveliness", headers={"Authorization": f"Bearer {PLUGIN_KEY}"})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {MASTER_KEY}"


# ── Plugin key: non-allowed endpoints (pass-through, key NOT rewritten) ────


def test_plugin_passthrough_key_generate(client, mock_litellm):
    """Plugin key GET /key/generate → pass-through, Authorization unchanged."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/key/generate", headers={"Authorization": f"Bearer {PLUGIN_KEY}"})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {PLUGIN_KEY}"


def test_plugin_passthrough_post_key(client, mock_litellm):
    """Plugin key POST /key/generate → pass-through, Authorization unchanged."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.post("/key/generate", headers={"Authorization": f"Bearer {PLUGIN_KEY}"}, json={})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {PLUGIN_KEY}"


def test_plugin_passthrough_model_new(client, mock_litellm):
    """Plugin key POST /model/new → pass-through, Authorization unchanged."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.post("/model/new", headers={"Authorization": f"Bearer {PLUGIN_KEY}"}, json={})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {PLUGIN_KEY}"


def test_plugin_passthrough_team_list(client, mock_litellm):
    """Plugin key GET /team/list → pass-through, Authorization unchanged."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/team/list", headers={"Authorization": f"Bearer {PLUGIN_KEY}"})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {PLUGIN_KEY}"


# ── Normal key + no auth: pass-through ─────────────────────────────────────


def test_normal_key_passthrough(client, mock_litellm):
    """Normal key → pass-through, Authorization NOT modified."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/spend/logs", headers={"Authorization": f"Bearer {NORMAL_KEY}"})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {NORMAL_KEY}"


def test_normal_key_admin_passthrough(client, mock_litellm):
    """Normal key can access admin endpoints (no restriction)."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.post("/key/generate", headers={"Authorization": f"Bearer {NORMAL_KEY}"}, json={})
    assert resp.status_code == 200


def test_no_auth_passthrough(client, mock_litellm):
    """No Authorization → pass-through unchanged."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/spend/logs")
    assert resp.status_code == 200


# ── SSE Streaming ──────────────────────────────────────────────────────────


def test_sse_streaming(client, mock_litellm):
    """SSE streaming → chunks pass through transparently."""
    chunks = [b"data: chunk1\n\n", b"data: chunk2\n\n", b"data: [DONE]\n\n"]
    upstream = _mock_stream_response(chunks=chunks)
    mock_litellm.build_request = MagicMock(return_value=MagicMock())
    mock_litellm.send = AsyncMock(return_value=upstream)

    resp = client.post(
        "/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {NORMAL_KEY}",
            "Accept": "text/event-stream",
        },
        json={"model": "gpt-4", "stream": True},
    )

    assert resp.status_code == 200
    body = resp.content
    assert b"data: chunk1" in body
    assert b"data: chunk2" in body
    assert b"[DONE]" in body


def test_sse_streaming_key_rewrite(client, mock_litellm):
    """SSE streaming with plugin key on allowed endpoint → key rewritten."""
    chunks = [b"data: ok\n\n"]
    upstream = _mock_stream_response(chunks=chunks)
    mock_litellm.build_request = MagicMock(return_value=MagicMock())
    mock_litellm.send = AsyncMock(return_value=upstream)

    resp = client.get(
        "/spend/logs",
        headers={
            "Authorization": f"Bearer {PLUGIN_KEY}",
            "Accept": "text/event-stream",
        },
    )

    assert resp.status_code == 200
    sent_headers = mock_litellm.build_request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {MASTER_KEY}"


# ── Key masking in logs ────────────────────────────────────────────────────


def test_key_masking_in_logs(client, mock_litellm, capsys, monkeypatch):
    """MASTER_KEY must never appear in log output."""
    import config

    monkeypatch.setattr(config.settings, "log_level", "body")
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())

    client.get("/spend/logs", headers={"Authorization": f"Bearer {PLUGIN_KEY}"})

    captured = capsys.readouterr()
    assert MASTER_KEY not in captured.out
    assert MASTER_KEY not in captured.err


def test_response_body_key_masked_in_logs(client, mock_litellm, capsys, monkeypatch):
    """A freshly-minted key returned by /key/generate must be masked in logs."""
    import config

    monkeypatch.setattr(config.settings, "log_level", "body")
    secret_value = "sk-freshly-leaked-12345"
    mock_litellm.request = AsyncMock(
        return_value=_mock_buffered_response(body=f'{{"key":"{secret_value}"}}'.encode())
    )

    client.post("/key/generate", json={})

    captured = capsys.readouterr()
    assert secret_value not in captured.out


# ── Query string ───────────────────────────────────────────────────────────


def test_query_string_forwarded(client, mock_litellm):
    """Query parameters are forwarded to LiteLLM."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    client.get(
        "/spend/logs?api_key=testkey&start_date=2026-07-01&end_date=2026-07-03",
        headers={"Authorization": f"Bearer {PLUGIN_KEY}"},
    )
    sent_url = str(mock_litellm.request.call_args[1]["url"])
    assert "start_date=2026-07-01" in sent_url
    assert "end_date=2026-07-03" in sent_url


# ── Path traversal (regression for the master-key elevation bug) ───────────


def test_path_traversal_percent_encoded_rejected(client, mock_litellm):
    """Plugin key + /key/info/%2E%2E/generate → 400, MASTER_KEY never sent."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())

    resp = client.get(
        "/key/info/%2E%2E/generate",
        headers={"Authorization": f"Bearer {PLUGIN_KEY}"},
    )

    assert resp.status_code == 400
    mock_litellm.request.assert_not_called()


def test_path_traversal_normalized_not_elevated(client, mock_litellm):
    """If the client sends an already-resolved /key/generate path with a plugin
    token, the request goes through but the Authorization is NOT rewritten —
    the allow-list decision is made on the literal path actually sent."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())

    resp = client.get("/key/generate", headers={"Authorization": f"Bearer {PLUGIN_KEY}"})

    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {PLUGIN_KEY}"


# ── Trailing-slash preservation (regression for /ui redirect loop) ─────────


def test_trailing_slash_forwarded_to_upstream(client, mock_litellm):
    """A trailing slash must be preserved on the path forwarded upstream.

    Regression: ``posixpath.normpath`` stripped trailing slashes, so a request
    to ``/ui/`` was forwarded as ``/ui``. LiteLLM's FastAPI then issued a
    307 directory redirect back to ``/ui/``, which the gateway again stripped,
    producing an infinite redirect loop. The path sent upstream MUST match
    what the client asked for.
    """
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    client.get("/ui/")
    sent_url = str(mock_litellm.request.call_args[1]["url"])
    assert sent_url.endswith("/ui/"), f"trailing slash lost in {sent_url}"
    assert not sent_url.endswith("/ui") or sent_url.endswith("/ui/")


def test_no_trailing_slash_not_added(client, mock_litellm):
    """Conversely, a path without trailing slash must not gain one."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    client.get("/ui")
    sent_url = str(mock_litellm.request.call_args[1]["url"])
    assert sent_url.endswith("/ui")
    assert not sent_url.endswith("/ui/")


# ── Body size limit ────────────────────────────────────────────────────────


def test_oversize_body_rejected(client, mock_litellm, monkeypatch):
    """A body larger than MAX_BODY_BYTES is rejected with 413 upstream-untouched."""
    import config

    monkeypatch.setattr(config.settings, "max_body_bytes", 128)
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())

    big = b"x" * 1024
    resp = client.post(
        "/v1/chat/completions",
        content=big,
        headers={"Authorization": f"Bearer {NORMAL_KEY}", "Content-Type": "application/json"},
    )

    assert resp.status_code == 413
    mock_litellm.request.assert_not_called()


# ── Error responses ────────────────────────────────────────────────────────


def test_error_response_no_exception_leak(client, mock_litellm):
    """A ConnectError must not leak internal hostnames to the client."""
    mock_litellm.request = AsyncMock(
        side_effect=httpx.ConnectError("connect to litellm.internal:4000 timed out")
    )

    resp = client.get("/spend/logs", headers={"Authorization": f"Bearer {NORMAL_KEY}"})

    assert resp.status_code == 502
    body = resp.text
    assert "litellm.internal" not in body
    assert "timed out" not in body
    assert resp.json()["error"] == "upstream unreachable"
    assert "rid" in resp.json()


def test_error_response_timeout(client, mock_litellm):
    mock_litellm.request = AsyncMock(side_effect=httpx.ReadTimeout("read timed out"))
    resp = client.get("/spend/logs", headers={"Authorization": f"Bearer {NORMAL_KEY}"})
    assert resp.status_code == 504
    assert resp.json()["error"] == "upstream timeout"


# ── Case-insensitive Bearer ────────────────────────────────────────────────


def test_bearer_lowercase_recognized(client, mock_litellm):
    """'bearer xxx' (RFC-7235 case-insensitive scheme) is treated as plugin."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/spend/logs", headers={"Authorization": f"bearer {PLUGIN_KEY}"})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {MASTER_KEY}"


def test_bearer_uppercase_recognized(client, mock_litellm):
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/spend/logs", headers={"Authorization": f"BEARER {PLUGIN_KEY}"})
    assert resp.status_code == 200
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers["authorization"] == f"Bearer {MASTER_KEY}"


# ── Request-ID correlation ─────────────────────────────────────────────────


def test_rid_in_response_header(client, mock_litellm):
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/spend/logs")
    assert "x-request-id" in resp.headers
    rid = resp.headers["x-request-id"]
    assert len(rid) == 16  # secrets.token_hex(8) → 16 chars
    assert all(c in "0123456789abcdef" for c in rid)


def test_rid_echoed_from_valid_client_header(client, mock_litellm):
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/spend/logs", headers={"X-Request-ID": "my-req-123"})
    assert resp.headers["x-request-id"] == "my-req-123"


def test_rid_rejected_when_malformed(client, mock_litellm):
    """Control chars / spaces in client X-Request-ID → fresh rid minted."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    resp = client.get("/spend/logs", headers={"X-Request-ID": "bad value!"})
    rid = resp.headers["x-request-id"]
    assert rid != "bad value!"
    assert len(rid) == 16


# ── Host preservation / forwarded headers (redirect-target fix) ────────────


def test_original_host_forwarded_to_upstream(client, mock_litellm):
    """The client-facing Host must reach LiteLLM so it builds redirects that
    point back through the gateway rather than at the internal hostname."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())

    client.get("/ui", headers={"Host": "gateway.example:4010"})

    sent_headers = mock_litellm.request.call_args[1]["headers"]
    # The original client-facing host is preserved verbatim — NOT rewritten
    # to the upstream's internal hostname (litellm:4000).
    assert sent_headers.get("host") == "gateway.example:4010"
    assert sent_headers.get("host") != "litellm:4000"
    # Forwarded chain is populated for upstreams that prefer those.
    assert sent_headers.get("x-forwarded-host") == "gateway.example:4010"
    assert sent_headers.get("x-forwarded-port") == "4010"


def test_forwarded_proto_default_http(client, mock_litellm):
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    client.get("/spend/logs")
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    assert sent_headers.get("x-forwarded-proto") == "http"


def test_forwarded_chain_appends_existing_xff(client, mock_litellm):
    """A pre-existing X-Forwarded-For is preserved and extended, not replaced."""
    mock_litellm.request = AsyncMock(return_value=_mock_buffered_response())
    client.get(
        "/spend/logs",
        headers={"X-Forwarded-For": "203.0.113.5"},
    )
    sent_headers = mock_litellm.request.call_args[1]["headers"]
    xff = sent_headers.get("x-forwarded-for", "")
    assert "203.0.113.5" in xff
    # Our hop is appended at the end.
    assert xff.startswith("203.0.113.5, ")


# ── Docs / OpenAPI pass-through ────────────────────────────────────────────


@pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/redoc"])
def test_docs_routes_proxied_not_intercepted(client, mock_litellm, path):
    """/openapi.json, /docs, /redoc must reach LiteLLM rather than being
    served by the gateway's own FastAPI docs routes (otherwise LiteLLM's
    Swagger renders the gateway's empty catch-all spec)."""
    mock_litellm.request = AsyncMock(
        return_value=_mock_buffered_response(body=b'{"swagger":"upstream"}')
    )
    resp = client.get(path)
    assert resp.status_code == 200
    assert resp.content == b'{"swagger":"upstream"}'
    # Confirm it really went to the upstream, not to a built-in route.
    mock_litellm.request.assert_called_once()
    sent_url = str(mock_litellm.request.call_args[1]["url"])
    assert sent_url.endswith(path)
