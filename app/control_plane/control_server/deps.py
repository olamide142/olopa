"""Shared dependencies — settings, template root, and Jinja2 templates.

Imported by routers so they don't re-initialise these objects independently.
"""

from pathlib import Path

from fastapi.templating import Jinja2Templates

from .config import Settings

settings: Settings = Settings.from_env()
template_root: Path = Path(__file__).resolve().parent / "template"
templates: Jinja2Templates = Jinja2Templates(directory=str(template_root))
