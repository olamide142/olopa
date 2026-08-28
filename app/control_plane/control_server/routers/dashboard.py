"""Dashboard / app shell pages.

Serves the React console SPA (built into ``control_server/webdist``).  Client-side
routes (``/fleet``, ``/incidents`` …) all resolve to the SPA ``index.html`` so the
in-app router can take over.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse

from ..deps import webdist_root

router = APIRouter(tags=["app"])

_spa_index = webdist_root / "index.html"

# Client-side routes owned by the SPA router; each returns index.html.
SPA_ROUTES = [
    "/",
    "/fleet",
    "/incidents",
    "/graph",
    "/oil",
    "/compiler",
    "/rules",
    "/deployments",
    "/install",
]


def _render_console() -> HTMLResponse:
    """Return the built SPA shell."""
    if not _spa_index.is_file():
        return HTMLResponse(
            "Dashboard build not found. Run `make web-build` (or `npm run build` "
            f"in app/control_plane/web) so {_spa_index} exists.",
            status_code=503,
        )
    return HTMLResponse(_spa_index.read_text(encoding="utf-8"))


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
