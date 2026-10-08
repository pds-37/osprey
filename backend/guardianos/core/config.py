"""Application configuration and settings."""

from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    APP_NAME: str = "Osprey"
    APP_VERSION: str = "0.2.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    
    # API & Security
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: Optional[str] = Field(default=None, description="JWT signing key; required in production")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    AUTH_USERS_JSON: str = Field(default="", description="Configured username to password-hash and role map")
    ALLOWED_ORIGINS: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    ENABLE_DEMO_FIXTURES: bool = False
    MAX_REQUEST_BODY_BYTES: int = Field(default=10 * 1024 * 1024, ge=1024)
    WORKSPACE_ROOT: Optional[str] = Field(default=None, description="Root directory permitted for local manifest scans")
    STATE_DB_PATH: str = Field(default="./osprey-state.sqlite3", description="Local SQLite document store for backend state")

    # The copilot is deterministic and local by default. Remote providers are opt-in.
    COPILOT_PROVIDER: str = Field(default="evidence-only", pattern=r"^(evidence-only|openai-compatible)$")
    COPILOT_BASE_URL: Optional[str] = None
    COPILOT_API_KEY: Optional[str] = Field(default=None, repr=False)
    COPILOT_MODEL: Optional[str] = None
    COPILOT_TIMEOUT_SECONDS: float = Field(default=5.0, ge=0.1, le=15.0)
    COPILOT_RATE_LIMIT_PER_MINUTE: int = Field(default=30, ge=1, le=120)

    # Optional graph adapter settings; no current analysis path requires Neo4j.
    NEO4J_URI: Optional[str] = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: Optional[str] = None
    USE_IN_MEMORY_GRAPH: bool = True  # Defaults to True for self-contained portability

    model_config = {
        "env_file": ".env",
        "extra": "ignore"
    }


settings = Settings()
