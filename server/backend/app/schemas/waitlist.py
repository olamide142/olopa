from pydantic import BaseModel, EmailStr 


class WaitlistCreate(BaseModel):
    email: EmailStr
    name: str | None = None
    company: str | None = None
    source: str = "landing"


class WaitlistResponse(BaseModel):
    ok: bool = True
    message: str = "You're on the list."


class WaitlistCountResponse(BaseModel):
    count: int
