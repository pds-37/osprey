"""Security utilities: JWT, password hashing, and RBAC roles."""

from datetime import datetime, timezone, timedelta
from typing import Optional, Any
from enum import Enum
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from guardianos.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    DEVELOPER = "developer"
    AUDITOR = "auditor"


class TokenData(BaseModel):
    sub: str
    role: UserRole = UserRole.ANALYST
    org_id: Optional[str] = "default-org"
    exp: Optional[datetime] = None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(
    subject: str,
    role: UserRole = UserRole.ANALYST,
    org_id: str = "default-org",
    expires_delta: Optional[timedelta] = None
) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode: dict[str, Any] = {
        "sub": subject,
        "role": role.value,
        "org_id": org_id,
        "exp": expire,
        "iat": datetime.now(timezone.utc)
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> Optional[TokenData]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return TokenData(
            sub=payload.get("sub", ""),
            role=UserRole(payload.get("role", UserRole.ANALYST.value)),
            org_id=payload.get("org_id", "default-org"),
            exp=datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc) if payload.get("exp") else None
        )
    except jwt.PyJWTError:
        return None
