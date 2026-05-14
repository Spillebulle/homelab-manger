from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, UniqueConstraint, TypeDecorator
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


class AuthUser(Base):
    __tablename__ = "auth_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
