"""OAuth2-compatible bearer authentication, password hashing, and RBAC."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field

from guardianos.core.config import settings

logger = logging.getLogger(__name__)
ALGORITHM = "HS256"
_development_secret: str | None = None


class UserRole(str, Enum):
    VIEWER = "viewer"
    SECURITY_ENGINEER = "security_engineer"
    ADMIN = "admin"


ROLE_LEVEL = {
    UserRole.VIEWER: 10,
    UserRole.SECURITY_ENGINEER: 20,
    UserRole.ADMIN: 30,
}


class CurrentUser(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    role: UserRole
    org_id: str = Field(default="default-org", min_length=1, max_length=128)


class TokenData(BaseModel):
    sub: str = Field(min_length=1, max_length=256)
    role: UserRole
    org_id: str = Field(default="default-org", min_length=1, max_length=128)
    exp: datetime | None = None


oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/token", auto_error=False)


def get_secret_key() -> str:
    """Return the configured signing key; development uses a process-local random key."""
    global _development_secret
    configured = (settings.SECRET_KEY or "").strip()
    if configured:
        if len(configured.encode("utf-8")) < 32:
            raise RuntimeError("SECRET_KEY must contain at least 32 bytes")
        return configured
    if settings.ENVIRONMENT.lower() in {"production", "prod"}:
        raise RuntimeError("SECRET_KEY must be configured in production")
    if _development_secret is None:
        _development_secret = secrets.token_urlsafe(48)
        logger.warning("Using a process-local signing key; configure SECRET_KEY for stable development tokens")
    return _development_secret


def get_password_hash(password: str, *, rounds: int = 310_000) -> str:
    """Hash a password using salted PBKDF2-HMAC-SHA256."""
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return "pbkdf2_sha256${}${}${}".format(
        rounds,
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
    )


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        scheme, rounds_s, salt_s, digest_s = password_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        rounds = int(rounds_s)
        if rounds < 100_000 or rounds > 2_000_000:
            return False
        salt = base64.urlsafe_b64decode(salt_s + "=" * (-len(salt_s) % 4))
        expected = base64.urlsafe_b64decode(digest_s + "=" * (-len(digest_s) % 4))
        actual = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, rounds)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def configured_users() -> dict[str, dict[str, str]]:
    raw = settings.AUTH_USERS_JSON.strip()
    if not raw:
        return {}
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AUTH_USERS_JSON must be valid JSON") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError("AUTH_USERS_JSON must be a JSON object")
    users: dict[str, dict[str, str]] = {}
    for username, record in decoded.items():
        if not isinstance(username, str) or not isinstance(record, dict):
            continue
        password_hash = record.get("password_hash")
        try:
            role = UserRole(str(record.get("role", "viewer")).lower())
        except ValueError:
            continue
        org_id = str(record.get("org_id", "default-org"))
        if (isinstance(password_hash, str) and len(password_hash) <= 256
                and password_hash.startswith("pbkdf2_sha256$")
                and isinstance(org_id, str) and 1 <= len(org_id) <= 128):
            users[username] = {
                "password_hash": password_hash,
                "role": role.value,
                "org_id": org_id,
            }
    return users


def configured_organization_ids() -> set[str]:
    """Return configured tenant IDs without trusting request-supplied IDs."""
    return {record["org_id"] for record in configured_users().values()}


def stored_organization_ids() -> set[str]:
    """Find tenant IDs in records whose owning organization is represented."""
    from guardianos.storage.sqlite import state_store

    organizations: set[str] = set()
    for record_type in ("components", "sboms", "findings", "remediation_workflows"):
        for payload in state_store.list(record_type).values():
            if not isinstance(payload, dict):
                continue
            organization_id = payload.get("organization_id", payload.get("org_id", "default-org"))
            if isinstance(organization_id, str) and organization_id:
                organizations.add(organization_id)
    return organizations


def single_organization_context_allowed(org_id: str) -> bool:
    """Global legacy stores are usable only when all known records belong to this tenant."""
    if len(configured_organization_ids()) > 1:
        return False
    stored = stored_organization_ids()
    return not stored or stored == {org_id}


def authenticate_credentials(username: str, password: str) -> CurrentUser | None:
    record = configured_users().get(username)
    if not record or not verify_password(password, record["password_hash"]):
        return None
    return CurrentUser(username=username, role=UserRole(record["role"]), org_id=record["org_id"])


def create_access_token(
    subject: str,
    role: UserRole = UserRole.VIEWER,
    org_id: str = "default-org",
    expires_delta: timedelta | None = None,
) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    claims: dict[str, Any] = {
        "sub": subject,
        "role": role.value,
        "org_id": org_id,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(claims, get_secret_key(), algorithm=ALGORITHM)


def decode_token(token: str) -> TokenData | None:
    try:
        claims = jwt.decode(token, get_secret_key(), algorithms=[ALGORITHM])
        if not claims.get("sub") or not claims.get("exp") or not claims.get("role"):
            return None
        return TokenData(
            sub=claims["sub"],
            role=UserRole(claims["role"]),
            org_id=claims.get("org_id", "default-org"),
            exp=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
        )
    except (JWTError, KeyError, ValueError, TypeError):
        return None


async def get_current_user(token: str | None = Depends(oauth2_scheme)) -> CurrentUser:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token_data = decode_token(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    account = configured_users().get(token_data.sub)
    if not account or account["role"] != token_data.role.value or account["org_id"] != token_data.org_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token user is not currently configured",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return CurrentUser(username=token_data.sub, role=token_data.role, org_id=token_data.org_id)


def require_role(minimum_role: UserRole):
    async def dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if ROLE_LEVEL[current_user.role] < ROLE_LEVEL[minimum_role]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return current_user

    return dependency


async def require_single_organization(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Fail closed for legacy global stores that do not carry tenant ownership."""
    if not single_organization_context_allowed(current_user.org_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ENDPOINT_UNAVAILABLE_IN_MULTI_ORGANIZATION_MODE",
        )
    return current_user
