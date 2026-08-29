"""Base repository for NetWatch AI."""

from typing import Generic, Protocol, TypeVar

from sqlalchemy import func, select
from sqlalchemy.orm import Mapped, Session

from app.database.base import Base


class IdModel(Protocol):
    """Structural contract for ORM models that expose an integer primary key.

    Pyright cannot know that ``Base`` subclasses have an ``id`` attribute —
    each model declares its own primary key. This protocol says: *any class
    with an ``id`` column satisfies this*.

    ``id`` is typed as ``Mapped[int]`` (not ``int``) because the generic
    repository accesses it in two ways:

    * On the *class* (``model_class.id``) it is a SQLAlchemy column
      expression, which is what ``order_by()`` needs.
    * On an *instance* (``obj.id``) it is a plain ``int``.

    SQLAlchemy's ``Mapped`` descriptor type is set up so Pyright understands
    both usages correctly.
    """

    id: Mapped[int]


ModelType = TypeVar("ModelType", bound=IdModel)


class BaseRepository(Generic[ModelType]):
    """Base class providing common CRUD operations for all repositories.

    A *repository* wraps the database session and hides low-level SQLAlchemy
    calls behind simple, reusable methods. This keeps business logic clean
    and makes the code easy to test (we can swap the real database for a fake
    one in tests without touching the rest of the app).

    Attributes:
        db: The active SQLAlchemy session.
        model_class: The ORM model this repository manages.
    """

    def __init__(self, db: Session, model_class: type[ModelType]) -> None:
        self.db = db
        self.model_class = model_class

    def get(self, obj_id: int) -> ModelType | None:
        """Return a single record by primary key, or None if not found."""
        return self.db.get(self.model_class, obj_id)

    def get_all(self, *, skip: int = 0, limit: int = 100) -> list[ModelType]:
        """Return a page of records ordered by primary key."""
        stmt = (
            select(self.model_class)
            .order_by(self.model_class.id)
            .offset(skip)
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def create(self, **data: object) -> ModelType:
        """Create and persist a new record."""
        obj = self.model_class(**data)
        self.db.add(obj)
        self.db.commit()
        self.db.refresh(obj)
        return obj

    def update(self, obj: ModelType, **data: object) -> ModelType:
        """Update an existing record with the given attributes."""
        for key, value in data.items():
            setattr(obj, key, value)
        self.db.commit()
        self.db.refresh(obj)
        return obj

    def delete(self, obj: ModelType) -> None:
        """Delete a record."""
        self.db.delete(obj)
        self.db.commit()

    def count(self) -> int:
        """Return the number of records in this table."""
        stmt = select(func.count()).select_from(self.model_class)
        return int(self.db.scalar(stmt) or 0)
