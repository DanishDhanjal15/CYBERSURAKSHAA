"""
database/db.py
--------------
SQLAlchemy engine and session factory for SQLite.

The database file is stored at ``./betting_detector.db`` by default.
Override by setting the ``DATABASE_URL`` environment variable.
"""

from __future__ import annotations

import os
from typing import Generator

from loguru import logger
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./betting_detector.db")

# ``check_same_thread=False`` is required for SQLite when used with FastAPI
# (which may run handlers in different threads).
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,  # Set to True for SQL query logging during development
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ---------------------------------------------------------------------------
# Declarative base (shared by all ORM models)
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------
def get_db() -> Generator[Session, None, None]:
    """
    Yield a SQLAlchemy session and ensure it is closed after the request.

    Usage in FastAPI route::

        @router.get("/example")
        def example(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Table creation helper
# ---------------------------------------------------------------------------
def init_db() -> None:
    """Create all tables defined via the ORM (called at application startup)."""
    # Import models so SQLAlchemy registers them with the Base metadata.
    from database import models as _  # noqa: F401

    Base.metadata.create_all(bind=engine)
    logger.info(f"Database initialised at {DATABASE_URL}")
