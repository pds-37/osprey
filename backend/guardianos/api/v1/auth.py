"""OAuth2 password-token endpoint for configured local accounts."""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from guardianos.core.config import settings
from guardianos.core.security import authenticate_credentials, create_access_token

router = APIRouter(prefix="/auth", tags=["Authentication"])


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


@router.post("/token", response_model=TokenResponse)
async def issue_token(form: OAuth2PasswordRequestForm = Depends()):
    if not settings.AUTH_USERS_JSON.strip():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="No API users are configured")
    if len(form.username) > 256 or len(form.password) > 1024:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = authenticate_credentials(form.username, form.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenResponse(
        access_token=create_access_token(user.username, user.role, user.org_id),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
