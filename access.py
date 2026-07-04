"""Access control: bearer-token parsing, path allow-listing for plugin keys.

Security invariants enforced here:

* ``is_allowed`` decides based on the **normalized** path that will actually
  be sent upstream. Callers must pass the *same* normalized path they intend
  to forward to LiteLLM, so the check and the dispatched request cannot
  disagree (this is what previously enabled ``/key/info/../generate`` to be
  allowed while httpx routed the request to ``/key/generate``).
* Any path containing ``..`` segments, backslashes, NUL bytes, or other
  traversal artifacts is hard-denied regardless of normalization outcome.
* Token comparison is constant-time via ``hmac.compare_digest`` to avoid
  timing oracles on key prefixes.
"""

from __future__ import annotations

import hmac
from collections.abc import Collection
from urllib.parse import unquote

ALLOWED_PREFIXES: tuple[str, ...] = (
    "/spend",
    "/global/spend",
    "/key/info",
    "/model/info",
    "/health",
)


def extract_bearer_token(auth_header: str | None) -> str | None:
    """Extract a bearer token from an ``Authorization`` header.

    RFC 7235 specifies the auth scheme as case-insensitive; we therefore
    accept ``bearer``, ``Bearer``, ``BEARER``, etc. Returns ``None`` when
    the header is absent or does not use the Bearer scheme.
    """
    if not auth_header:
        return None
    # Match the 7-character "Bearer " prefix case-insensitively but preserve
    # the original-case token after it.
    if len(auth_header) < 7 or auth_header[:7].lower() != "bearer ":
        return None
    token = auth_header[7:].strip()
    return token or None


def normalize_path(path: str) -> str | None:
    """Return a safe, normalized form of ``path``.

    Returns ``None`` if the path contains traversal artifacts that we refuse
    to interpret under any normalization. Otherwise returns the canonical
    path that should be used both for the access decision and for
    constructing the upstream URL.

    Rules:

    * Percent-decode once (so ``%2F..%2F`` cannot smuggle ``..`` past us).
    * Reject any ``..`` segment, backslash, NUL byte.
    * Collapse redundant *interior* slashes (``/a//b`` → ``/a/b``) and
      guarantee exactly one leading slash.
    * **Preserve** a trailing slash. This is critical: the upstream's routing
      distinguishes ``/ui`` from ``/ui/`` (FastAPI/Starlette issue a 307
      directory redirect from the former to the latter). Stripping the
      trailing slash here would turn that into an infinite redirect loop:
      client → ``/ui/`` → gateway strips to ``/ui`` → upstream 307 →
      ``/ui/`` → gateway strips again → …
    """
    if not path:
        return None

    # Reject obviously hostile bytes before any normalization.
    if "\x00" in path or "\\" in path:
        return None

    # Single percent-decode pass. We do *not* re-decode after normalization
    # (that would allow double-encoding attacks).
    try:
        decoded = unquote(path, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None

    # Only absolute paths are valid for a proxy route.
    if not decoded.startswith("/"):
        return None

    # After decoding, reject traversal segments anywhere in the path. We do
    # not rely on normpath to "make them safe" — we forbid them outright so
    # the decision matches the literal intent of the caller.
    segments = decoded.split("/")
    if any(seg == ".." for seg in segments):
        return None

    # Collapse interior empty segments (//) but remember whether the original
    # ended in "/", so we can re-apply it and not break upstream routing.
    has_trailing_slash = decoded.endswith("/") and len(decoded) > 1
    non_empty = [s for s in segments if s != ""]
    normalized = "/" + "/".join(non_empty)
    if has_trailing_slash:
        normalized += "/"
    return normalized


def is_allowed(path: str) -> bool:
    """True iff ``path`` (already normalized via :func:`normalize_path`) is
    covered by an allow-list prefix.

    The match is performed on **path segments** rather than ``startswith`` so
    that ``/key/info`` does not match ``/key/infoleak``. A trailing slash on
    the request path is tolerated (``/key/info/`` matches the ``/key/info``
    prefix) since the normalized form preserves it for upstream routing.
    """
    # Strip a single trailing slash for the comparison only — never on the
    # path that gets forwarded upstream.
    check = path[:-1] if len(path) > 1 and path.endswith("/") else path
    return any(check == prefix or check.startswith(prefix + "/") for prefix in ALLOWED_PREFIXES)


def is_plugin_token(token: str | None, valid_tokens: Collection[str]) -> bool:
    """Constant-time membership test for the plugin-key set.

    Iterates over all valid tokens and compares each with
    ``hmac.compare_digest`` so that timing does not leak which prefix matched.
    An empty ``valid_tokens`` set denies everything.
    """
    if not token or not valid_tokens:
        return False
    token_bytes = token.encode("utf-8")
    matched = False
    for candidate in valid_tokens:
        cand_bytes = candidate.encode("utf-8")
        # compare_digest requires equal length to be useful as a constant-time
        # check; we OR results across all candidates so the loop runs in
        # time independent of which (if any) candidate matched.
        if len(token_bytes) == len(cand_bytes) and hmac.compare_digest(token_bytes, cand_bytes):
            matched = True
    return matched
