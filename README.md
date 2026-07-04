# LiteLLM Plugin Gateway

A thin reverse-proxy in front of [LiteLLM](https://github.com/BerriAI/litellm) that
lets you hand out **scoped** tokens to third-party plugins and scripts: such
tokens only work on a safe allow-list of endpoints (spend tracking, key/model
info, health checks) and grant neither read access to other users' traffic nor
the ability to mint new master keys.

For example, an IDE cost-tracking plugin
([opencode-litellm-costs](https://github.com/cleardevice/opencode-litellm-costs))
is issued a `plugin_opencode_costs` token, calls `/spend/logs` and
`/model/info`, and the proxy transparently
rewrites its `Authorization` to the LiteLLM `MASTER_KEY` — so the plugin itself
never sees the master key. On any other path the same token behaves like an
ordinary user key (LiteLLM applies its own authz).

---

## Why

LiteLLM ships [RBAC](https://docs.litellm.ai/docs/proxy/virtual_keys) and
team/organization keys, but wiring those through the database for one-off
integrations is often overkill. This proxy solves three specific problems:

1. **Keep `MASTER_KEY` locked down.** The LiteLLM master key never leaves the
   gateway perimeter — external integrations get "plugin" tokens with a narrow
   scope of action.
2. **Hybrid model.** On the allow-listed paths a plugin token is elevated to
   master privileges; everywhere else requests pass through unchanged and
   LiteLLM makes the call (including `/v1/chat/completions`, `/key/generate`,
   etc.).
3. **Observability.** Every request is logged as a single JSON line with a
   correlation id (`X-Request-ID`); secrets are masked at every log level.

---

## How it works

```
                ┌──────────────────────────────────────────────────────┐
                │                plugin-gateway :4010                   │
   client ─────►│  extract Bearer token                                │
                │   ├─ plugin-token + path on allow-list?              │
                │   │     Authorization → "Bearer ${MASTER_KEY}"       │
                │   └─ otherwise: Authorization unchanged (pass-through)│
                │                                                      │
                │  path normalization · body-size cap · redaction      │
                └────────────────────────┬─────────────────────────────┘
                                         │ httpx (keep-alive, pooling)
                                         ▼
                              ┌─────────────────────┐
                              │   LiteLLM :4000     │
                              └─────────────────────┘
```

The allow-list of path prefixes lives in `access.py:ALLOWED_PREFIXES`:
`/spend`, `/global/spend`, `/key/info`, `/model/info`, `/health`. Matching is
done on **segments** after path normalization, so `/key/infoleak` does **not**
match `/key/info`.

---

## Quick start in Docker (alongside LiteLLM)

Minimal `docker-compose.yaml` with the proxy in front of LiteLLM:

```yaml
services:
  litellm:
    image: litellm/litellm:latest
    ports:
      - "4000:4000"
    environment:
      # LiteLLM master key — the proxy will reuse it as its MASTER_KEY.
      LITELLM_MASTER_KEY: ${LITELLM_MASTER_KEY}
      DATABASE_URL: ${DATABASE_URL}
      UI_USERNAME: ${UI_USERNAME}
      UI_PASSWORD: ${UI_PASSWORD}
      # ... provider keys (OpenAI, Anthropic, …)
    volumes:
      - ./config.yaml:/app/config.yaml
    command: ["--config", "/app/config.yaml"]
    restart: unless-stopped

  litellm-gw:
    build: ./plugin-gateway          # or: image: ghcr.io/<owner>/plugin-gateway:latest
    depends_on:
      - litellm
    environment:
      # The "litellm" service name resolves inside the compose network.
      LITELLM_URL: "http://litellm:4000"
      # Same master key as the litellm service.
      MASTER_KEY: ${LITELLM_MASTER_KEY}
      # Plugin tokens, comma-separated. Do NOT reuse the master key as a plugin.
      PLUGIN_KEYS: ${PLUGIN_KEYS}
      LOG_LEVEL: "minimal"          # minimal | headers | body
      PORT: "4010"
      # MAX_BODY_BYTES: "33554432"  # default 32 MiB
    ports:
      - "4010:4010"
    restart: unless-stopped
```

Run it:

```bash
# 1. Put variables into .env (next to docker-compose.yaml):
#    LITELLM_MASTER_KEY=sk-...      # LiteLLM master key
#    PLUGIN_KEYS=plugin_one,plugin_two
#    DATABASE_URL=postgresql://...
#    UI_USERNAME=admin
#    UI_PASSWORD=...

# 2. Bring both services up:
docker compose up -d

# 3. Smoke test:
curl -H "Authorization: Bearer plugin_one" http://localhost:4010/health/liveliness
curl -H "Authorization: Bearer plugin_one" http://localhost:4010/spend/logs
```

External clients should talk **only** to `:4010` (the gateway). In production
you generally want to keep LiteLLM's `:4000` port private to the compose network
so all traffic flows through the gateway.

> ⚠️ `LITELLM_MASTER_KEY` (LiteLLM) and the proxy's `MASTER_KEY` must match. If
> they diverge, plugin-token elevation silently stops working (LiteLLM returns
> 401); the fail-fast check only fires when `MASTER_KEY` is entirely empty.

---

## Configuration

All variables are read from the environment or a `.env` file.

| Variable           | Required | Default                | Description                                              |
|--------------------|:--------:|------------------------|----------------------------------------------------------|
| `LITELLM_URL`      | yes      | `http://localhost:4000`| Upstream LiteLLM base URL.                               |
| `MASTER_KEY`       | yes      | _(empty → fail fast)_  | LiteLLM master key; injected for plugin routes.          |
| `PLUGIN_KEYS`      | no       | _(empty)_              | Comma-separated plugin tokens.                           |
| `LOG_LEVEL`        | no       | `headers`              | `minimal` / `headers` / `body`.                          |
| `PORT`             | no       | `4010`                 | Listen port.                                             |
| `MAX_BODY_BYTES`   | no       | `33554432` (32 MiB)    | Inbound request body cap; exceeded → `413`.              |
| `MAX_RESPONSE_BYTES`| no      | `67108864` (64 MiB)    | Cap above which response bodies are dropped from logs.   |
| `QUIET_PATHS`      | no       | `/health/liveliness,…` | Paths silenced at the `minimal` log level.               |

### Adding a new allow-listed path

1. Append the prefix to `ALLOWED_PREFIXES` in `access.py`.
2. Add a regression test in `tests/test_access.py`.
3. Explain the operational rationale in the commit message (which privilege you are granting).

---

## Security model

What the proxy enforces:

- **Path normalization** is the single source of truth for both the allow-list
  decision and the upstream URL. Any `..`, `\`, or NUL byte is rejected outright;
  requests like `/key/info/../generate` do not elevate privileges.
- **Constant-time** plugin-token comparison via `hmac.compare_digest`.
- **Secret masking** in all logs: headers containing `key`/`token`/`secret`/
  `password`/`auth`/`cookie`, `Bearer`/`Basic` schemes, and JSON keys like
  `api_key`, `password`, `token`, `secret`, … — at every log level.
- **Request body cap** (anti-DoS): `MAX_BODY_BYTES` → `413`, streamed reads.
- **No internal error leakage**: clients only see a stable
  `{"error": "...", "rid": "..."}`; details (`ConnectError: …`) go to logs only.
- **Correlation id**: every response carries `X-Request-ID` (64 bits of entropy,
  or the validated incoming value).
- **Image runs as a non-root user** (uid 1001); `conftest.py`, `tests/`, and
  `.env` are not shipped in the image.

What the proxy **does not** do (by design):

- Does not terminate TLS — put it behind nginx/Caddy/Traefik.
- Does not authorize ordinary requests — LiteLLM handles that (pass-through).
- Does not keep state and does not cache.

See [`SECURITY.md`](SECURITY.md) for the vulnerability-disclosure policy.

---

## Development

Requires Python 3.11+. All commands run from the `plugin-gateway/` directory.

```bash
pip install -r requirements-dev.txt

ruff check .              # linter
ruff format --check .     # format check (run `ruff format .` to apply)
mypy *.py                 # strict type checking
pytest -q                 # full suite (124+ tests)
```

Full conventions (layout, security invariants, commit regime) are in
[`AGENTS.md`](AGENTS.md).

---

## Roadmap / Contributions

Ideas ordered by impact-to-effort. Issues and PRs are welcome.

### Infrastructure & releases

- **CI on GitHub Actions**: Python 3.11/3.12/3.13 matrix running ruff/mypy/pytest
  on every PR. No CI is wired up today — checks live only in `AGENTS.md`.
- **Supply-chain hardening**: a `requirements.lock` with SHA-256 hashes
  (`uv pip compile --generate-hashes`) and a Docker build with `--require-hashes`;
  pin the base image by digest instead of the `python:3.11-slim` tag.
- **Automated image builds** to GHCR on `v*` tags (GitHub Actions +
  `docker/build-push-action`).
- **CodeQL** static analysis in CI to catch security regressions.
- **Semver releases** + a `CHANGELOG.md`.

### Security

- **Rate limiting**: today the gateway is open to anyone holding a plugin token.
  Token/IP bucketing via `slowapi` or at the ingress layer.
- **IP allowlist** for privilege-elevating paths (`/key/info`, `/global/spend`).
- **Audit log to a dedicated sink**: logs currently go to stdout; for elevated
  plugin requests a separate, durable stream is useful (journald, Loki, rotated
  file).
- **Crash-safe logging**: acknowledge a log line before returning the response
  (today `print` can be lost if the process crashes).
- **mTLS** between the gateway and LiteLLM instead of plain HTTP inside the
  compose network.
- **Dedicated management endpoints**: the gateway's own FastAPI docs are disabled
  (so they don't intercept LiteLLM's `/docs`); consider an explicit mount of
  `/__gateway/health` and `/__gateway/metrics`, clearly separated from proxied
  paths.

### Features

- **Prometheus metrics endpoint** (`/metrics`): RPS by rtype/path, latency
  histograms, 4xx/5xx counters, active-stream gauge.
- **Retry/timeout policies** for the upstream via
  `httpx.AsyncHTTPTransport(retries=…)`, configurable per-path.
- **Hot-reload of `PLUGIN_KEYS`** without a restart (file watch on `.env` or a
  SIGHUP handler). Today keys are read once at startup.
- **Manage plugin tokens via LiteLLM**: store them in the LiteLLM database as
  virtual keys with metadata, instead of an env var — enables revocation without
  a redeploy.
- **Caching** of idempotent `GET /model/info`, `/health/*` with a short TTL.
- **Operator status page / WebUI**: list active plugin tokens, usage counters,
  recent errors.

### Code quality

- **Move `conftest.py` into `tests/`** and pin `testpaths` in `pyproject.toml` —
  today it lives at the repo root.
- **Migrate the test client to `httpx2`** (or `httpx.AsyncClient` +
  `ASGITransport`) — the current `httpx` raises a deprecation warning under
  Starlette 1.x.
- **Property-based tests** for `access.normalize_path` with Hypothesis: for any
  input, the output is either `None` or a path free of `..`/`//`/`\`/NUL.
- **Fuzz the path matcher**: a test asserting that no combination of
  percent-encoding, trailing slash, and case variation elevates privileges
  beyond `ALLOWED_PREFIXES`.

---

## License

MIT. See [`LICENSE`](LICENSE).

---

## Acknowledgements

- [LiteLLM](https://github.com/BerriAI/litellm) — the proxied upstream.
- [FastAPI](https://fastapi.tiangolo.com/) / [Starlette](https://github.com/Kludex/starlette)
  / [httpx](https://www.python-httpx.org/) — the stack this gateway is built on.
