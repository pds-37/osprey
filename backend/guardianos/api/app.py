"""Main FastAPI application factory for Osprey."""

import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from guardianos.core.config import settings
from guardianos.core.security import get_secret_key
from guardianos.api.v1.auth import router as auth_router
from guardianos.api.v1.analysis import router as analysis_router
from guardianos.api.v1.evidence import router as evidence_router
from guardianos.api.v1.sboms import router as sboms_router
from guardianos.api.v1.components import router as components_router
from guardianos.api.v1.graph import router as graph_router
from guardianos.api.v1.audit import router as audit_router
from guardianos.api.v1.vulnerabilities import router as vulnerabilities_router
from guardianos.api.v1.upstream_changes import router as upstream_changes_router
from guardianos.api.v1.patches import router as patches_router
from guardianos.api.v1.exposure import router as exposure_router
from guardianos.api.v1.attack_paths import router as attack_paths_router
from guardianos.api.v1.risks import router as risks_router
from guardianos.api.v1.ai import router as ai_router
from guardianos.ai.copilot import router as copilot_router
from guardianos.api.v1.remediation import router as remediation_router
from guardianos.api.v1.demo import router as demo_router


class RequestBodyLimitMiddleware:
    """Bound request bytes even when clients omit or falsify Content-Length."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        chunks = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.max_bytes:
                body = b'{"detail":"Request body exceeds configured size limit"}'
                await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body, "more_body": False})
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        buffered_body = b"".join(chunks)
        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": buffered_body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)


def create_app() -> FastAPI:
    if settings.ENVIRONMENT.lower() in {"production", "prod"}:
        get_secret_key()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Osprey vulnerability intelligence and evidence-backed reachability analysis",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=settings.MAX_REQUEST_BODY_BYTES)

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
            "inventory_storage": "sqlite-document-store",
            "storage_path_configured": bool(settings.STATE_DB_PATH),
            "graph_storage": "networkx-in-memory" if settings.USE_IN_MEMORY_GRAPH else "configured-adapter-not-probed",
        }

    # Mount v1 API Routers
    app.include_router(auth_router, prefix=settings.API_V1_PREFIX)
    app.include_router(analysis_router, prefix=settings.API_V1_PREFIX)
    app.include_router(evidence_router, prefix=settings.API_V1_PREFIX)
    app.include_router(sboms_router, prefix=settings.API_V1_PREFIX)
    app.include_router(components_router, prefix=settings.API_V1_PREFIX)
    app.include_router(graph_router, prefix=settings.API_V1_PREFIX)
    app.include_router(audit_router, prefix=settings.API_V1_PREFIX)
    app.include_router(vulnerabilities_router, prefix=settings.API_V1_PREFIX)
    app.include_router(upstream_changes_router, prefix=settings.API_V1_PREFIX)
    app.include_router(patches_router, prefix=settings.API_V1_PREFIX)
    app.include_router(exposure_router, prefix=settings.API_V1_PREFIX)
    app.include_router(attack_paths_router, prefix=settings.API_V1_PREFIX)
    app.include_router(risks_router, prefix=settings.API_V1_PREFIX)
    app.include_router(ai_router, prefix=settings.API_V1_PREFIX)
    app.include_router(copilot_router, prefix=settings.API_V1_PREFIX)
    app.include_router(remediation_router, prefix=settings.API_V1_PREFIX)
    app.include_router(demo_router, prefix=settings.API_V1_PREFIX)

    return app


app = create_app()
