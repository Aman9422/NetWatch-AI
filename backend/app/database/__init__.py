"""Database package for NetWatch AI.

Exposes the declarative base, engine, session factory, and FastAPI dependency.
"""

from app.database.base import Base
from app.database.session import SessionLocal, engine, get_db

__all__ = ["Base", "SessionLocal", "engine", "get_db"]
