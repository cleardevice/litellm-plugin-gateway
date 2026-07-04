# AGENTS.md

Operational conventions for AI agents (and humans) working in this directory.

## Project

A thin reverse-proxy in front of LiteLLM. Plugin tokens (env `PLUGIN_KEYS`)
on an allow-list of paths get their `Authorization` rewritten to
`MASTER_KEY`; everything else is passed through unchanged.

## Layout

- `main.py` — FastAPI app, request handler, streaming/buffered proxy paths.
- `access.py` — bearer-token parsing, path normalization, allow-list.
- `config.py` — pydantic-settings, env vars, cached key sets.
- `log.py` — structured JSON logging with secret redaction.
- `tests/` — pytest suite.
- `conftest.py` — test-only env defaults (NOT shipped in the Docker image).

## Environment

Production reads from env vars (or `.env`):

| Var              | Required | Default                       | Notes                                            |
|------------------|----------|-------------------------------|--------------------------------------------------|
| `LITELLM_URL`    | yes      | `http://localhost:4000`       | Upstream LiteLLM base URL.                       |
| `MASTER_KEY`     | yes      | _(empty — startup fails)_     | LiteLLM master key, injected for plugin routes.  |
| `PLUGIN_KEYS`    | no       | _(empty)_                     | Comma-separated plugin tokens.                   |
| `LOG_LEVEL`      | no       | `headers`                     | One of `minimal`, `headers`, `body`.             |
| `PORT`           | no       | `4010`                        | Listen port.                                     |
| `MAX_BODY_BYTES` | no       | `33554432` (32 MiB)           | Inbound request body cap.                        |

## Commands

Run everything from this directory using the venv/python of your choice
(`python3.11+`, dependencies in `requirements-dev.txt`).

```bash
# Install dev tooling
pip install -r requirements-dev.txt

# Lint (fast, must pass)
ruff check .

# Format check (run `ruff format .` to apply)
ruff format --check .

# Type-check (must pass; strict mode)
mypy *.py

# Tests (must pass)
pytest -q
```

## Before committing

1. `ruff check .` — clean.
2. `ruff format --check .` — clean.
3. `mypy *.py` — clean.
4. `pytest -q` — all green.

## Security invariants (do not regress)

- Path normalization (`access.normalize_path`) is the single source of truth
  for both `is_allowed` and upstream URL construction. Never re-introduce
  `startswith`-only matching.
- `..` segments, backslashes, and NUL bytes in paths are rejected outright.
- Client-facing error responses must NOT contain raw exception text — only
  the stable `error` string plus `rid`. Verbose diagnostics go to logs only.
- `MASTER_KEY` and any header containing `key`/`token`/`secret`/`password`/
  `auth`/`cookie` must be masked in all log output, at every log level.
- Body masking covers JSON keys `api_key`, `api-key`, `apikey`, `key`,
  `token`, `password`, `passwd`, `secret`, `authorization`, `access_token`,
  `refresh_token`, plus `Bearer ...` / `Basic ...` substrings.
- Plugin-token comparison is constant-time (`access.is_plugin_token`).
- The Docker image runs as non-root `appuser` (uid 1001) and does NOT ship
  `conftest.py`, `tests/`, or `.env`.

## Adding a new allow-listed path

1. Append to `ALLOWED_PREFIXES` in `access.py`.
2. Add a regression test in `tests/test_access.py`.
3. Document the operational reason in the commit message.
