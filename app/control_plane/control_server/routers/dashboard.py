"""Dashboard / app shell pages.

Serves the React console SPA (built into ``control_server/webdist``).  Client-side
routes (``/fleet``, ``/incidents`` …) all resolve to the SPA ``index.html`` so the
in-app router can take over.  If the SPA build is missing (e.g. a dev checkout
without ``npm run build``), falls back to the legacy Jinja ``app.html``.
"""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..deps import templates, template_root

router = APIRouter(tags=["app"])

webdist_root: Path = template_root.parent / "webdist"
_spa_index: Path = webdist_root / "index.html"

# Client-side routes owned by the SPA router; each returns index.html.
SPA_ROUTES = ["/", "/fleet", "/incidents", "/graph", "/oil", "/compiler", "/install"]


def _render_console(request: Request) -> HTMLResponse:
    """Return the built SPA shell, or the legacy template when unbuilt."""
    if _spa_index.is_file():
        return HTMLResponse(_spa_index.read_text(encoding="utf-8"))
    return templates.TemplateResponse(
        request=request, name="app.html", context={"request": request}
    )


for _path in SPA_ROUTES:
    router.add_api_route(
        _path,
        _render_console,
        methods=["GET"],
        response_class=HTMLResponse,
        include_in_schema=False,
    )


@router.get("/app", include_in_schema=False)
async def legacy_app_redirect() -> RedirectResponse:
    """Backwards-compatible redirect from /app to /."""
    return RedirectResponse(url="/", status_code=307)


@router.get("/legacy", include_in_schema=False)
async def legacy_console(request: Request) -> HTMLResponse:
    """Escape hatch to the previous vanilla-JS console during migration."""
    return templates.TemplateResponse(
        request=request, name="app.html", context={"request": request}
    )
