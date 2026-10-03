"""Application configuration and settings."""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    APP_NAME: str = "GuardianOS"
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # API & Security
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = Field(default="guardianos-dev-super-secret-key-change-in-prod-32chars!", description="JWT secret key")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    ALLOWED_ORIGINS: list[str] = ["*"]

    # Database (PostgreSQL with SQLite fallback for self-contained testing)
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./guardianos.db",
        description="Async SQLAlchemy database connection URL"
    )
    SYNC_DATABASE_URL: str = Field(
        default="sqlite:///./guardianos.db",
        description="Sync SQLAlchemy database connection URL for sync tools/migrations"
    )

    # Graph Database (Neo4j with in-memory NetworkX fallback)
    NEO4J_URI: Optional[str] = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"
    USE_IN_MEMORY_GRAPH: bool = True  # Defaults to True for self-contained portability

    # Redis (with in-memory fallback)
    REDIS_URL: Optional[str] = "redis://localhost:6379/0"

    # Qdrant Vector Search (REST API)
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333
    QDRANT_URL: Optional[str] = "http://localhost:6333"

    model_config = {
        "env_file": ".env",
        "extra": "ignore"
    }


settings = Settings()
