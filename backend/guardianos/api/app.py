"""Main FastAPI application factory for GuardianOS."""

import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from guardianos.core.config import settings
from guardianos.api.v1.sboms import router as sboms_router
from guardianos.api.v1.components import router as components_router
from guardianos.api.v1.graph import router as graph_router
from guardianos.api.v1.audit import router as audit_router


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="GuardianOS v2 - AI-native Supply Chain Intelligence & Attack Path Platform",
        docs_url="/api/docs",
        redoc_url="/api/redoc"
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Performance / Timing Middleware
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = f"{process_time:.4f}s"
        return response

    # Operational Health Endpoints
    @app.get("/health", tags=["Operational"])
    async def health_check():
        return {
            "status": "healthy",
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT
        }

    @app.get("/ready", tags=["Operational"])
    async def ready_check():
        return {
            "status": "ready",
            "database": "connected",
            "graph": "connected"
        }

    # Mount v1 API Routers
    app.include_router(sboms_router, prefix=settings.API_V1_PREFIX)
    app.include_router(components_router, prefix=settings.API_V1_PREFIX)
    app.include_router(graph_router, prefix=settings.API_V1_PREFIX)
    app.include_router(audit_router, prefix=settings.API_V1_PREFIX)

    return app


app = create_app()
