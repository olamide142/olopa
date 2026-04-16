"""Docs pages — quickstart, agent config, OIL language reference."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..deps import templates

router = APIRouter(tags=["docs"])


@router.get("/quickstart", response_class=HTMLResponse)
@router.get("/quickstart/", response_class=HTMLResponse, include_in_schema=False)
async def quickstart_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="docs_quickstart.html", context={"request": request})


@router.get("/agent/config", response_class=HTMLResponse)
@router.get("/agent/config/", response_class=HTMLResponse, include_in_schema=False)
async def agent_config_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="docs_agent_config.html", context={"request": request})


@router.get("/oil", response_class=HTMLResponse)
@router.get("/oil/", response_class=HTMLResponse, include_in_schema=False)
async def oil_reference_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="docs_oil.html", context={"request": request})
