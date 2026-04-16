"""Dashboard / app shell pages."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..deps import templates

router = APIRouter(tags=["app"])


@router.get("/", response_class=HTMLResponse)
async def app_page(request: Request) -> HTMLResponse:
    """Render the control dashboard shell."""
    return templates.TemplateResponse(request=request, name="app.html", context={"request": request})


@router.get("/app", include_in_schema=False)
async def legacy_app_redirect() -> RedirectResponse:
    """Backwards-compatible redirect from /app to /."""
    return RedirectResponse(url="/", status_code=307)
