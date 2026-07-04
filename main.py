"""LiteLLM reverse-proxy gateway.

Auth model:

* Requests carrying a *plugin* token (configured via ``PLUGIN_KEYS``) and
  hitting an allow-listed path are forwarded to LiteLLM with their
  ``Authorization`` rewritten to ``MASTER_KEY``.
* All other requests are passed through unchanged — LiteLLM's own auth
  decides whether they succeed.

Path-safety: the request path is normalized (see :mod:`access`) and the
*same* normalized form is used both for the allow-list check and for
constructing the upstream URL. This closes the previous ``/key/info/../x``
bypass.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from access import extract_bearer_token, is_allowed, is_plugin_token, normalize_path
from config import settings
from log import log_request

# Hop-by-hop headers (RFC 7230 §6.1) plus headers the httpx client must
# recompute itself. Stripped from both outbound and inbound traffic.
#
# Note: ``Host`` is intentionally NOT stripped. It is an end-to-end header
# (not hop-by-hop per RFC), and forwarding the *original* client-facing Host
# is what lets the upstream build correct self-referential URLs. Otherwise
# LiteLLM would redirect browsers to its internal hostname (e.g.
# ``http://litellm:4000/ui/``) bypassing the gateway.
HOP_HEADERS: frozenset[str] = frozenset(
    {
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "upgrade",
        "trailer",
        "trailers",
        "proxy-authorization",
        "proxy-authenticate",
    }
)

TIMEOUT = 600.0
MAX_RID_LEN = 128
# Per-character alphabet for client-supplied X-Request-ID values. Anything
# outside this set causes us to ignore the header and mint a fresh id.
_RID_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def _new_rid() -> str:
    """64 bits of entropy — collision-safe at any realistic request rate."""
    return secrets.token_hex(8)


def _coerce_rid(raw: str | None) -> str:
    """Accept a client-supplied X-Request-ID if it is short and boring.

    We do not trust the client with formatting that could confuse log
    parsers or inject control characters. Reject anything weird.
    """
    if not raw:
        return _new_rid()
    if len(raw) > MAX_RID_LEN:
        return _new_rid()
    if not all(c in _RID_ALPHABET for c in raw):
        return _new_rid()
    return raw


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create one shared httpx client for the whole process.

    Reusing connections gives us keep-alive and proper pooling; per-request
    clients were paying a TCP+TLS handshake on every call.
    """
    # Fail fast on misconfiguration before we accept traffic.
    settings.assert_configured()

    app.state.client = httpx.AsyncClient(
        timeout=httpx.Timeout(TIMEOUT),
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
    )
    try:
        yield
    finally:
        await app.state.client.aclose()


app = FastAPI(
    title="litellm-plugin-gateway",
    lifespan=lifespan,
    # This service is a transparent proxy, not an API surface of its own.
    # Disable FastAPI's built-in docs/openapi routes so that /docs, /redoc
    # and /openapi.json fall through to the catch-all and are proxied to
    # LiteLLM — otherwise the gateway would serve its own (empty) OpenAPI
    # spec and LiteLLM's Swagger UI would render our catch-all handler
    # instead of LiteLLM's real endpoints.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def handler(request: Request) -> Response:
    rid = _coerce_rid(request.headers.get("x-request-id"))
    auth = request.headers.get("authorization", "")
    token = extract_bearer_token(auth)

    if token is not None and is_plugin_token(token, settings.plugin_key_set):
        rtype = "plugin"
    else:
        rtype = "normal"

    # Normalize once, use everywhere. raw_path is the undecoded bytes the
    # client actually sent — protects against uvicorn-level surprises.
    raw_path = request.scope.get("raw_path", b"")
    if isinstance(raw_path, bytes):
        raw_path_str = raw_path.decode("latin-1", errors="replace")
    else:
        raw_path_str = str(raw_path)

    path = normalize_path(raw_path_str)
    if path is None:
        return _error_response(rid, rtype, request, 400, "invalid path", 0.0)

    query = request.url.query
    url = f"{settings.litellm_url.rstrip('/')}{path}"
    if query:
        url = f"{url}?{query}"

    body = await _read_limited_body(request, settings.max_body_bytes)
    if body is None:
        return _error_response(rid, rtype, request, 413, "request body too large", 0.0)

    proxy_headers = _build_proxy_headers(request)

    if rtype == "plugin" and is_allowed(path):
        proxy_headers["authorization"] = f"Bearer {settings.master_key}"

    accept = proxy_headers.get("accept", "").lower()
    content_type = proxy_headers.get("content-type", "").lower()
    is_streaming = "text/event-stream" in accept or "text/event-stream" in content_type

    start = time.time()
    client: httpx.AsyncClient = request.app.state.client

    try:
        if is_streaming:
            return await _proxy_stream(
                client, request, url, proxy_headers, body, start, rid, rtype, path
            )
        return await _proxy_buffered(
            client, request, url, proxy_headers, body, start, rid, rtype, path
        )
    except httpx.TimeoutException:
        latency = round((time.time() - start) * 1000, 2)
        log_request(
            rid=rid,
            rtype=rtype,
            method=request.method,
            path=path,
            status=504,
            latency_ms=latency,
            error="upstream timeout",
        )
        return _error_response(rid, rtype, request, 504, "upstream timeout", latency)
    except httpx.ConnectError:
        latency = round((time.time() - start) * 1000, 2)
        log_request(
            rid=rid,
            rtype=rtype,
            method=request.method,
            path=path,
            status=502,
            latency_ms=latency,
            error="upstream unreachable",
        )
        return _error_response(rid, rtype, request, 502, "upstream unreachable", latency)
    except Exception as exc:
        latency = round((time.time() - start) * 1000, 2)
        # Full exception text goes ONLY to logs; the client gets a stable
        # message tagged with rid so support can correlate.
        log_request(
            rid=rid,
            rtype=rtype,
            method=request.method,
            path=path,
            status=502,
            latency_ms=latency,
            error=f"{type(exc).__name__}: {exc}",
        )
        return _error_response(rid, rtype, request, 502, "proxy error", latency)


def _build_proxy_headers(request: Request) -> dict[str, str]:
    """Filter hop-by-hop headers and add forwarding metadata.

    The original ``Host`` is deliberately preserved so the upstream sees the
    client-facing address and can build redirects / self-referential URLs
    pointing back through the gateway rather than at the internal upstream
    hostname.
    """
    proxy_headers: dict[str, str] = {
        k: v for k, v in request.headers.items() if k.lower() not in HOP_HEADERS
    }

    # X-Forwarded-* chain. We honour any pre-existing values so this gateway
    # composes correctly when itself behind another L7 proxy.
    client_host = request.client.host if request.client else ""
    _append_forwarded(proxy_headers, "x-forwarded-for", client_host)

    host = request.headers.get("host", "")
    if host:
        _append_forwarded(proxy_headers, "x-forwarded-host", host)

    # Scheme: prefer a pre-existing X-Forwarded-Proto (we may be behind TLS
    # termination), otherwise fall back to the connection scheme.
    if "x-forwarded-proto" not in proxy_headers:
        scheme = request.url.scheme or "http"
        proxy_headers["x-forwarded-proto"] = scheme

    # Port: derive from the Host header if present (covers non-default ports
    # the client used to reach us).
    if host and ":" in host and "x-forwarded-port" not in proxy_headers:
        proxy_headers["x-forwarded-port"] = host.rsplit(":", 1)[-1]

    return proxy_headers


def _append_forwarded(headers: dict[str, str], name: str, value: str) -> None:
    """Append ``value`` to a forwarded-header chain, preserving earlier hops."""
    existing = headers.get(name)
    headers[name] = f"{existing}, {value}" if existing else value


async def _read_limited_body(request: Request, max_bytes: int) -> bytes | None:
    """Read the request body, capped at ``max_bytes``.

    Returns ``None`` if the declared or actual size exceeds the cap. The
    streaming read means we never buffer more than ``max_bytes + chunk_size``
    even for chunked-transfer requests with no ``Content-Length``.
    """
    cl = request.headers.get("content-length")
    if cl is not None and cl.strip().isdigit() and int(cl) > max_bytes:
        return None

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _error_response(
    rid: str, rtype: str, request: Request, status: int, message: str, latency_ms: float
) -> JSONResponse:
    # Errors still get a minimal audit line so operators see the 4xx/5xx
    # without having to enable verbose logging.
    log_request(
        rid=rid,
        rtype=rtype,
        method=request.method,
        path=request.url.path,
        status=status,
        latency_ms=latency_ms,
        error=message,
    )
    return JSONResponse(
        status_code=status,
        content={"error": message, "rid": rid},
        headers={"x-request-id": rid},
    )


async def _proxy_buffered(
    client: httpx.AsyncClient,
    request: Request,
    url: str,
    headers: dict[str, str],
    body: bytes,
    start: float,
    rid: str,
    rtype: str,
    path: str,
) -> Response:
    response = await client.request(
        method=request.method,
        url=url,
        headers=headers,
        content=body,
    )
    latency = round((time.time() - start) * 1000, 2)
    res_headers = {
        k: v
        for k, v in response.headers.items()
        if k.lower() not in HOP_HEADERS and k.lower() != "content-encoding"
    }
    res_headers["x-request-id"] = rid

    # Drop the body from logs if upstream returned something huge — we still
    # forward it to the client in full, just don't retain it in memory/log.
    res_body_for_log: bytes | None
    if len(response.content) > settings.max_response_bytes:
        res_body_for_log = None
    else:
        res_body_for_log = response.content

    log_request(
        rid=rid,
        rtype=rtype,
        method=request.method,
        path=path,
        status=response.status_code,
        latency_ms=latency,
        req_headers=headers,
        req_body=body,
        res_headers=res_headers,
        res_body=res_body_for_log,
    )
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=res_headers,
    )


async def _proxy_stream(
    client: httpx.AsyncClient,
    request: Request,
    url: str,
    headers: dict[str, str],
    body: bytes,
    start: float,
    rid: str,
    rtype: str,
    path: str,
) -> StreamingResponse:
    req = client.build_request(
        method=request.method,
        url=url,
        headers=headers,
        content=body,
    )
    upstream = await client.send(req, stream=True)
    res_headers = {
        k: v
        for k, v in upstream.headers.items()
        if k.lower() not in HOP_HEADERS and k.lower() != "content-encoding"
    }
    res_headers["x-request-id"] = rid
    latency = round((time.time() - start) * 1000, 2)
    log_request(
        rid=rid,
        rtype=rtype,
        method=request.method,
        path=path,
        status=upstream.status_code,
        latency_ms=latency,
        req_headers=headers,
        req_body=body,
        res_headers=res_headers,
        is_streaming=True,
    )

    async def stream_chunks() -> AsyncIterator[bytes]:
        try:
            async for chunk in upstream.aiter_bytes():
                yield chunk
        finally:
            await upstream.aclose()

    return StreamingResponse(
        stream_chunks(),
        status_code=upstream.status_code,
        headers=res_headers,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=settings.port)
