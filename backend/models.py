from datetime import datetime
from sqlalchemy import (
    Column, Integer, Float, String, Boolean, Text, DateTime, ForeignKey,
    UniqueConstraint, Index, TypeDecorator,
)
from .database import Base
from .credentials_crypto import encrypt_credentials, decrypt_credentials


class EncryptedJSON(TypeDecorator):
    """Stores a JSON-able value as Fernet-encrypted text. Read sites get a
    dict (or None) back automatically; write sites pass a dict (or None) and
    the column handles serialization + encryption. Legacy plaintext rows
    decode transparently — they're re-encrypted by the startup migration in
    `database.py`, but until that runs (or for fresh ad-hoc reads) the
    fallback in decrypt_credentials handles them.

    Backing column type stays TEXT so the existing schema (and any external
    inspection tools) see the same column shape; only the *content* is now
    a base64url-encoded ciphertext with an `enc:` prefix instead of raw
    JSON."""

    impl = Text
    cache_ok = True  # SQLAlchemy 2.x — compile-time caching is safe; we have no per-instance state

    def process_bind_param(self, value, dialect):
        return encrypt_credentials(value)

    def process_result_value(self, value, dialect):
        return decrypt_credentials(value)


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=False)
    device_type = Column(String(50), nullable=False)   # switch | server | router | pdu | ups
    adapter_type = Column(String(50), nullable=False)  # snmp | dlink | cimc | redfish | ilo | idrac | ibmc
    # Column type is EncryptedJSON — read/write as a dict; the TypeDecorator
    # handles JSON serialization and Fernet encryption transparently. See
    # `credentials_crypto.py` for the key-management model.
    credentials = Column(EncryptedJSON)
    enabled = Column(Boolean, default=True)
    notes = Column(Text)
    # Per-device poll interval in seconds. NULL ⇒ use the poller's default
    # (DEFAULT_POLL_INTERVAL). The poller clamps to a sane minimum at read time.
    poll_interval = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class DeviceCache(Base):
    __tablename__ = "device_cache"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    cache_key = Column(String(100), nullable=False)  # status | ports | poe | hardware | storage | …
    data = Column(Text)                               # JSON
    updated_at = Column(DateTime)
    error = Column(Text)

    # Without this, two concurrent polls can both SELECT-miss and both INSERT,
    # leaving duplicate (device_id, cache_key) rows. The cache_map reader picks
    # whichever row SQLite returns last — sometimes the stale one — so the UI
    # shows yesterday's data with no indication that's what happened.
    __table_args__ = (
        UniqueConstraint("device_id", "cache_key", name="uq_device_cache_key"),
    )


class DeviceMetric(Base):
    """Time-series samples for graphing. One row per (device, metric, sample).

    Unlike `device_cache` (which keeps only the latest value per key), this
    table accumulates history. The poller writes the numeric members of an
    adapter's `metrics` cache key here every poll cycle and prunes rows beyond
    METRICS_RETENTION_DAYS. New table ⇒ `Base.metadata.create_all` in init_db
    creates it automatically; no manual migration needed.

    Float storage (not the EncryptedJSON dict pattern) because these are
    non-secret numeric series queried by range — encryption would defeat the
    indexed time-window scans the history endpoint relies on."""
    __tablename__ = "device_metrics"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    metric = Column(String(50), nullable=False)   # load_pct | watts | charge_pct | runtime_sec | …
    value = Column(Float, nullable=False)
    ts = Column(DateTime, nullable=False, default=datetime.utcnow)

    # The history endpoint always filters by (device_id, metric) over a ts
    # range and orders by ts — this composite index serves both the scan and
    # the retention-prune DELETE.
    __table_args__ = (
        Index("ix_device_metrics_lookup", "device_id", "metric", "ts"),
    )


class AuthUser(Base):
    __tablename__ = "auth_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ApiKey(Base):
    """A bearer token for programmatic API access, as an alternative to the
    cookie session. Only the SHA-256 hash is stored — the plaintext is shown
    once at creation and never recoverable. `prefix` is a non-secret leading
    slice kept purely so the UI can identify which key is which."""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)  # sha256 hex
    prefix = Column(String(20), nullable=False)                              # display only
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
