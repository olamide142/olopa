"""Shared dependencies — settings and the built dashboard SPA location.

Imported by routers so they don't re-initialise these objects independently.
Landing/docs are static files served by Caddy now; this process only needs to
know where the built React console lives.
"""

from pathlib import Path

from .config import Settings

settings: Settings = Settings.from_env()
webdist_root: Path = Path(__file__).resolve().parent / "webdist"
