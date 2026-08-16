"""Enrollment token and WireGuard key lifecycle.

Two hard rules govern this module:

- the control plane only ever stores public keys — endpoint private material is
  generated on and never leaves the device,
- an enrollment token is redeemable exactly once, enforced by a conditional
  UPDATE on the token's `jti` rather than a read-then-write check.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Any, Dict, Optional, Tuple

import jwt
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..models.secure_connect import (
    SecureConnectEnrollment,
    SecureConnectKeyMaterial,
    SecureConnectSession,
    as_utc,
    utc_now,
)

#: Distinguishes enrollment tokens from ordinary control-plane bearer tokens so
#: a stolen API token can never be replayed as an enrollment credential.
ENROLLMENT_TOKEN_PURPOSE = "secure_connect_enrollment"

#: The plan caps enrollment tokens at 15 minutes.
MAX_ENROLLMENT_TTL_MINUTES = 15


class KeyManagerError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def validate_wireguard_key(label: str, key: str) -> str:
    """Reject anything that is not a base64 Curve25519 public key."""
    candidate = (key or "").strip()
    try:
        decoded = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyManagerError(
            "INVALID_WIREGUARD_KEY", f"{label} is not valid base64"
        ) from exc
    if len(decoded) != 32:
        raise KeyManagerError(
            "INVALID_WIREGUARD_KEY", f"{label} must decode to 32 bytes"
        )
    return candidate


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_enrollment_token(
    db: Session,
    *,
    secret: str,
    tenant_id: str,
    user_id: str,
    issued_by: str,
    device_hint: str = "",
    profile_id: Optional[str] = None,
    ttl_minutes: int = MAX_ENROLLMENT_TTL_MINUTES,
    issuer: str = "",
    audience: str = "",
) -> Tuple[str, SecureConnectEnrollment]:
    """Mint a single-use enrollment JWT and record its `jti` for replay checks."""
    ttl = max(1, min(ttl_minutes, MAX_ENROLLMENT_TTL_MINUTES))
    issued = utc_now()
    expires_at = issued + timedelta(minutes=ttl)
    jti = secrets.token_urlsafe(24)

    claims: Dict[str, Any] = {
        "purpose": ENROLLMENT_TOKEN_PURPOSE,
        "sub": user_id,
        "tenant_id": tenant_id,
        "jti": jti,
        "device_hint": device_hint,
        "profile_id": profile_id,
        "iat": int(issued.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    if issuer:
        claims["iss"] = issuer
    if audience:
        claims["aud"] = audience

    token = jwt.encode(claims, secret, algorithm="HS256")
    record = SecureConnectEnrollment(
        tenant_id=tenant_id,
        jti=jti,
        user_id=user_id,
        device_hint=device_hint,
        token_hash=token_hash(token),
        profile_id=profile_id,
        issued_by=issued_by,
        expires_at=expires_at,
    )
    db.add(record)
    db.flush()
    return token, record


def decode_enrollment_token(
    token: str, *, secret: str, issuer: str = "", audience: str = ""
) -> Dict[str, Any]:
    """Verify an enrollment token's signature, purpose, and required claims."""
    decode_args: Dict[str, Any] = {
        "algorithms": ["HS256"],
        "options": {"require": ["exp", "iat", "sub", "tenant_id", "jti"]},
    }
    if issuer:
        decode_args["issuer"] = issuer
    if audience:
        decode_args["audience"] = audience

    try:
        claims = jwt.decode(token, secret, **decode_args)
    except jwt.ExpiredSignatureError as exc:
        raise KeyManagerError(
            "ENROLLMENT_TOKEN_EXPIRED", "Enrollment token has expired"
        ) from exc
    except jwt.PyJWTError as exc:
        raise KeyManagerError(
            "ENROLLMENT_TOKEN_INVALID", "Enrollment token is not valid"
        ) from exc

    if claims.get("purpose") != ENROLLMENT_TOKEN_PURPOSE:
        raise KeyManagerError(
            "ENROLLMENT_TOKEN_INVALID",
            "Token was not issued for Secure Connect enrollment",
        )
    return claims


def redeem_enrollment(
    db: Session, *, jti: str, tenant_id: str, device_id: str
) -> SecureConnectEnrollment:
    """Consume a token exactly once.

    The conditional UPDATE is the single-use gate: concurrent redemptions of the
    same `jti` produce exactly one row update, and the loser is rejected.
    """
    record = db.scalars(
        select(SecureConnectEnrollment).where(SecureConnectEnrollment.jti == jti)
    ).first()
    if record is None or record.tenant_id != tenant_id:
        raise KeyManagerError(
            "ENROLLMENT_TOKEN_UNKNOWN", "Enrollment token is not recognised"
        )
    if record.used_at is not None:
        raise KeyManagerError(
            "ENROLLMENT_TOKEN_CONSUMED", "Enrollment token has already been used"
        )
    expires_at = as_utc(record.expires_at)
    if expires_at is not None and expires_at <= utc_now():
        raise KeyManagerError(
            "ENROLLMENT_TOKEN_EXPIRED", "Enrollment token has expired"
        )

    result = db.execute(
        update(SecureConnectEnrollment)
        .where(
            SecureConnectEnrollment.jti == jti,
            SecureConnectEnrollment.tenant_id == tenant_id,
            SecureConnectEnrollment.used_at.is_(None),
        )
        .values(used_at=utc_now(), device_id=device_id)
    )
    if result.rowcount != 1:
        raise KeyManagerError(
            "ENROLLMENT_TOKEN_CONSUMED", "Enrollment token has already been used"
        )
    db.expire(record)
    return record


def issue_key_material(
    db: Session,
    session: SecureConnectSession,
    public_key: str,
    expires_at: Optional[datetime] = None,
) -> SecureConnectKeyMaterial:
    """Record a new session peer key and revoke whatever it replaces."""
    revoke_key_material(db, session.id)
    material = SecureConnectKeyMaterial(
        session_id=session.id,
        gateway_id=session.gateway_id,
        public_key=public_key,
        assigned_address=session.assigned_address,
        expires_at=expires_at,
    )
    db.add(material)
    db.flush()
    return material


def revoke_key_material(db: Session, session_id: str) -> int:
    """Mark every live key for a session revoked; returns the number revoked."""
    result = db.execute(
        update(SecureConnectKeyMaterial)
        .where(
            SecureConnectKeyMaterial.session_id == session_id,
            SecureConnectKeyMaterial.revoked_at.is_(None),
        )
        .values(revoked_at=utc_now())
    )
    return int(result.rowcount or 0)


def utc_from_unix(value: int) -> datetime:
    return datetime.fromtimestamp(value, tz=timezone.utc)
