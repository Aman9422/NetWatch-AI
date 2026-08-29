"""SQLAlchemy declarative base for NetWatch AI."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all NetWatch AI ORM models.

    Every model (User, Device, Packet, ...) will inherit from this class.
    SQLAlchemy uses it to discover and create the corresponding tables.
    """
