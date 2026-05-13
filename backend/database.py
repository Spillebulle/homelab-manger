import logging
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/homelab.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    from . import models  # noqa: F401 — ensure models are registered
    Base.metadata.create_all(bind=engine)
    _migrate_device_cache_unique(engine)


def _migrate_device_cache_unique(engine):
    """Pre-v0.4.2 deployments accumulated duplicate device_cache rows because
    the table had no UniqueConstraint and the poller's SELECT-then-INSERT
    upsert had a race. SQLite won't retroactively add a table-level constraint
    via create_all, so on every startup we (a) drop duplicates, keeping the
    highest-id row per (device_id, cache_key), and (b) add a unique index that
    blocks future duplicates atomically. Idempotent — safe to run repeatedly."""
    with engine.begin() as conn:
        deleted = conn.execute(text(
            "DELETE FROM device_cache WHERE id NOT IN ("
            "SELECT MAX(id) FROM device_cache GROUP BY device_id, cache_key)"
        )).rowcount
        if deleted:
            logger.warning("device_cache: removed %d duplicate row(s) on startup", deleted)
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_device_cache_key "
            "ON device_cache(device_id, cache_key)"
        ))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
