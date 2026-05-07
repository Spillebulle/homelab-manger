from typing import Any, Optional
from pydantic import BaseModel


class DeviceCreate(BaseModel):
    name: str
    hostname: str
    device_type: str
    adapter_type: str
    credentials: dict[str, Any] = {}
    enabled: bool = True
    notes: Optional[str] = None


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    adapter_type: Optional[str] = None
    credentials: Optional[dict[str, Any]] = None
    enabled: Optional[bool] = None
    notes: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
