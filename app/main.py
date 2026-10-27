"""
Leadline - Main Application Entry Point
Phase 1: UI + Project Structure
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from app.config import settings
from app.db import init_db, close_db, mark_interrupted_scans
from app.api.targets import router as targets_router
from app.api.scans import router as scans_router
from app.api.reports import router as reports_router
from app.api.findings import router as findings_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    await init_db()
    # A scan runs inside the API process today. If the process died or was
    # restarted, its row can still say "running" forever. Mark it failed on
    # boot so target history never shows a zombie scan.
    await mark_interrupted_scans()
    yield
    # Shutdown
    await close_db()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Local-first attack surface mapper with target history",
    lifespan=lifespan
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class HostAllowListMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Host header is not explicitly allowed.

    Leadline has no authentication, so a browser-based DNS-rebinding attack
    against a localhost service is more relevant than a conventional auth
    bypass: an attacker-controlled domain can resolve to 127.0.0.1, making
    the API look same-origin to the browser. Validating Host breaks that
    trick. Configure ALLOWED_HOSTS if you put Leadline behind a different
    hostname.
    """

    async def dispatch(self, request, call_next):
        host_header = request.headers.get("host", "")
        hostname = urlsplit(f"//{host_header}").hostname or ""
        if hostname not in settings.ALLOWED_HOSTS:
            return JSONResponse(
                {"detail": "Host header not allowed"},
                status_code=400,
            )
        return await call_next(request)


app.add_middleware(HostAllowListMiddleware)

# Include routers
app.include_router(targets_router, prefix=settings.API_PREFIX)
app.include_router(scans_router, prefix=settings.API_PREFIX)
app.include_router(reports_router, prefix=settings.API_PREFIX)
app.include_router(findings_router, prefix=settings.API_PREFIX)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "Local-first attack surface mapper with target history"
    }


@app.get("/health")
@app.get(f"{settings.API_PREFIX}/health")
async def health_check():
    """Health check endpoint. Available at both /health (for infra-level
    checks -- Docker HEALTHCHECK, load balancers, etc.) and /api/health
    (what the frontend actually polls, so it goes through the same proxy/
    prefix as every other API call instead of needing a special case)."""
    return {"status": "healthy"}
