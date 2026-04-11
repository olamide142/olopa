"""Configuration for the Python control-plane service."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    return value


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """Runtime settings loaded from environment variables."""

    host: str
    port: int
    rust_ingest_base_url: str
    rust_request_timeout_s: float
    compiler_timeout_s: int
    oilc_manifest_path: str
    agent_download_url: str
    agent_binary_path: str

    @classmethod
    def from_env(cls) -> "Settings":
        """Create settings from environment with safe defaults."""
        repo_root = Path(__file__).resolve().parents[3]
        default_manifest = repo_root / "oilc" / "Cargo.toml"
        # Prefer explicit control-plane config, but accept ingest URL aliases
        # typically used in deployment systems (for example Railway).
        rust_base = _env_str(
            "RUST_INGEST_BASE_URL",
            _env_str("INGEST_SERVER_URL", "http://127.0.0.1:8000"),
        ).strip()
        if "://" not in rust_base:
            rust_base = f"http://{rust_base}"
        rust_base = rust_base.rstrip("/")
        return cls(
            host=_env_str("CONTROL_HOST", "0.0.0.0"),
            port=_env_int("CONTROL_PORT", 8100),
            rust_ingest_base_url=rust_base,
            rust_request_timeout_s=_env_float("RUST_REQUEST_TIMEOUT_S", 3.0),
            compiler_timeout_s=_env_int("COMPILER_TIMEOUT_S", 20),
            oilc_manifest_path=_env_str("OILC_MANIFEST_PATH", str(default_manifest)),
            agent_download_url=_env_str("AGENT_DOWNLOAD_URL", ""),
            agent_binary_path=_env_str("AGENT_BINARY_PATH", ""),
        )
