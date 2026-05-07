from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey
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


class AuthUser(Base):
    __tablename__ = "auth_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
