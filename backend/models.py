from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, UniqueConstraint
from .database import Base


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=False)
    device_type = Column(String(50), nullable=False)   # switch | server | router | pdu | ups
    adapter_type = Column(String(50), nullable=False)  # snmp | dlink | cimc | redfish | ilo | idrac | ibmc
    credentials = Column(Text)                         # JSON blob (plaintext — homelab use only)
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
