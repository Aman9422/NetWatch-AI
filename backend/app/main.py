"""NetWatch AI — FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import api_router
from app.config.settings import settings
from app.database.init_db import init_db
from app.utils.logging import configure_logging

logger = logging.getLogger(__name__)

configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager.

    Runs startup and shutdown tasks.

    On startup, the database schema is created automatically during
    development, then the app is ready to accept requests. On shutdown it
    just logs the event.
    """
    logger.info("Starting %s (%s) — environment: %s", settings.app_name, settings.app_version, settings.app_env)
    if settings.app_env == "development":
        init_db()
    yield
    logger.info("Shutting down %s", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="NetWatch AI — network monitoring and security detection platform.",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure CORS for the frontend development server.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API router under /api/v1.
app.include_router(api_router, prefix="/api/v1")
