import logging
import os
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/homelab.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Per-connection SQLite tuning, applied automatically when the pool hands
    out a fresh connection. Three pragmas matter for our concurrency profile:

    - journal_mode=WAL: writers don't block readers, lock acquisition is much
      faster, and the database file stays consistent on crash. Persists at the
      database level once set; the event listener just ensures it's on after a
      fresh-DB bootstrap.
    - busy_timeout=10000: 10 s wait when contending for the write lock, up from
      SQLite's default 5 s. The poller fans out polls in parallel and each writes
      its own cache rows; under bursty conditions (manual refresh stacking on top
      of a scheduled tick) the default sometimes wasn't enough.
    - synchronous=NORMAL: WAL mode's default; explicit so it's obvious. FULL is
      pointlessly slow once you're already on WAL.
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=10000")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


class Base(DeclarativeBase):
    pass


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    from . import models  # noqa: F401 — ensure models are registered
    Base.metadata.create_all(bind=engine)
    _migrate_device_cache_unique(engine)
    _migrate_add_poll_interval(engine)
    _migrate_add_shutdown_rule_ordering(engine)
    _migrate_credentials_to_encrypted(engine)


def _migrate_add_poll_interval(engine):
    """Add the `devices.poll_interval` column to pre-existing databases.
    `create_all` only creates missing *tables*, never adds columns to an
    existing one, so we ALTER it in by hand. SQLite has no `ADD COLUMN IF NOT
    EXISTS`, so check `PRAGMA table_info` first. Idempotent."""
    with engine.begin() as conn:
        cols = [r[1] for r in conn.execute(text("PRAGMA table_info(devices)")).fetchall()]
        if "poll_interval" not in cols:
            conn.execute(text("ALTER TABLE devices ADD COLUMN poll_interval INTEGER"))
            logger.warning("devices: added poll_interval column on startup")


def _migrate_add_shutdown_rule_ordering(engine):
    """Add `priority` + `delay_after_sec` to pre-existing `shutdown_rules`
    tables (outage-orchestration ordering). Same ALTER-by-hand pattern as
    poll_interval — create_all never alters existing tables. Idempotent."""
    with engine.begin() as conn:
        cols = [r[1] for r in conn.execute(text("PRAGMA table_info(shutdown_rules)")).fetchall()]
        if not cols:
            return  # table doesn't exist yet → create_all already made it with the columns
        if "priority" not in cols:
            conn.execute(text("ALTER TABLE shutdown_rules ADD COLUMN priority INTEGER NOT NULL DEFAULT 100"))
            logger.warning("shutdown_rules: added priority column on startup")
        if "delay_after_sec" not in cols:
            conn.execute(text("ALTER TABLE shutdown_rules ADD COLUMN delay_after_sec INTEGER NOT NULL DEFAULT 0"))
            logger.warning("shutdown_rules: added delay_after_sec column on startup")


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


def _migrate_credentials_to_encrypted(engine):
    """Pre-encryption deployments stored `devices.credentials` as plaintext
    JSON. The EncryptedJSON column type decodes those transparently on read,
    but every NEW write goes out as ciphertext — so a row only flips to
    encrypted form when the user next saves that device. To avoid leaving
    plaintext sitting in the DB indefinitely, do a one-shot rewrite here on
    startup: for every row whose `credentials` doesn't start with `enc:`,
    decode it and re-write it back through the encryption path.

    Idempotent — encrypted rows are skipped. Safe to run repeatedly."""
    # Lazy import — models.py imports credentials_crypto which imports
    # database.py for the DB_PATH constant. The cycle resolves at function-
    # call time but not at module-import time.
    from .credentials_crypto import is_encrypted, encrypt_credentials, decrypt_credentials
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT id, credentials FROM devices")).fetchall()
        upgraded = 0
        for row_id, raw in rows:
            if raw is None or is_encrypted(raw):
                continue
            # Decode plaintext JSON via the same helper used at read time, so
            # malformed legacy values produce {} rather than crashing the
            # migration — the user can re-enter creds via the edit modal.
            value = decrypt_credentials(raw)
            new_blob = encrypt_credentials(value)
            conn.execute(
                text("UPDATE devices SET credentials = :c WHERE id = :i"),
                {"c": new_blob, "i": row_id},
            )
            upgraded += 1
        if upgraded:
            logger.warning(
                "devices.credentials: encrypted %d plaintext row(s) on startup. "
                "From now on credentials live as Fernet-encrypted blobs; the key "
                "lives in CREDENTIAL_KEY (env) or .credential_key next to the DB.",
                upgraded,
            )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
