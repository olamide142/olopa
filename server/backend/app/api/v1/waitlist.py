import time

from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import check_rate_limit
from app.config import get_settings
from app.models.waitlist import WaitlistEntry
from app.schemas.waitlist import WaitlistCreate, WaitlistResponse, WaitlistCountResponse

router = APIRouter(prefix="/waitlist", tags=["waitlist"])

# Simple in-memory cache for count (invalidated on new signup)
_count_cache: int | None = None
_count_cache_ts: float = 0
COUNT_CACHE_TTL = 300  # 5 minutes


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host or "127.0.0.1"


@router.post("", response_model=WaitlistResponse)
async def join_waitlist(
    body: WaitlistCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> WaitlistResponse:
    settings = get_settings()
    ip = _client_ip(request)
    if not check_rate_limit(ip, settings.waitlist_rate_limit_per_hour, 3600):
        raise HTTPException(status_code=429, detail="Too many signups. Try again later.")

    existing = await db.execute(select(WaitlistEntry).where(WaitlistEntry.email == body.email))
    if existing.scalar_one_or_none() is not None:
        return WaitlistResponse(message="You're already on the list.")

    entry = WaitlistEntry(
        email=body.email,
        name=body.name,
        company=body.company,
        source=body.source,
    )
    db.add(entry)
    global _count_cache, _count_cache_ts
    _count_cache = None
    return WaitlistResponse()


@router.get("/count", response_model=WaitlistCountResponse)
async def waitlist_count(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> WaitlistCountResponse:
    global _count_cache, _count_cache_ts
    now = time.time()
    if _count_cache is not None and (now - _count_cache_ts) < COUNT_CACHE_TTL:
        return WaitlistCountResponse(count=_count_cache)
    result = await db.execute(select(func.count()).select_from(WaitlistEntry))
    count = result.scalar() or 0
    _count_cache = count
    _count_cache_ts = now
    return WaitlistCountResponse(count=count)
