from __future__ import annotations

from functools import cached_property

from pydantic_settings import BaseSettings

VALID_LOG_LEVELS = ("body", "headers", "minimal")


class Settings(BaseSettings):
    """Runtime configuration, populated from environment / ``.env``.

    All security-sensitive defaults are deliberately empty so that a missing
    ``MASTER_KEY`` is loud rather than silently sending ``Bearer `` upstream.
    """

    litellm_url: str = "http://localhost:4000"
    master_key: str = ""
    plugin_keys: str = ""
    log_level: str = "headers"
    port: int = 4010

    # Hard cap on inbound request body size (bytes). 32 MiB accommodates
    # large LLM contexts with attachment payloads while bounding memory use.
    max_body_bytes: int = 32 * 1024 * 1024

    # Hard cap on buffered upstream *response* bodies. Responses larger than
    # this are still streamed through to the client but are not retained for
    # logging — prevents a malicious or buggy upstream from exhausting RAM.
    max_response_bytes: int = 64 * 1024 * 1024

    # Comma-separated list of paths that are silenced at the ``minimal``
    # log level (typically noisy health probes).
    quiet_paths: str = "/health/liveliness,/health/liveness,/health/readiness"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    @cached_property
    def plugin_key_set(self) -> frozenset[str]:
        """Plugin tokens parsed once and frozen. Subsequent calls are O(1)."""
        return frozenset(k.strip() for k in self.plugin_keys.split(",") if k.strip())

    @cached_property
    def quiet_path_set(self) -> frozenset[str]:
        return frozenset(p.strip() for p in self.quiet_paths.split(",") if p.strip())

    @property
    def valid_log_level(self) -> str:
        """Clamped log level — single source of truth used by ``log``."""
        return self.log_level if self.log_level in VALID_LOG_LEVELS else "headers"

    def assert_configured(self) -> None:
        """Fail fast at startup if required secrets are missing.

        Raising here beats running with ``Authorization: Bearer `` against
        LiteLLM, which produces confusing 401s and leaks that the gateway is
        misconfigured.
        """
        if not self.master_key:
            raise RuntimeError("MASTER_KEY must be set (got empty value)")
        if not self.litellm_url:
            raise RuntimeError("LITELLM_URL must be set (got empty value)")


settings = Settings()
