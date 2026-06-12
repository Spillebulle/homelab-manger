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
    # Seconds between polls; None ⇒ poller default. Clamped to a minimum by the
    # poller. Empty form values arrive as None.
    poll_interval: Optional[int] = None


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    adapter_type: Optional[str] = None
    credentials: Optional[dict[str, Any]] = None
    enabled: Optional[bool] = None
    notes: Optional[str] = None
    poll_interval: Optional[int] = None


class ApiKeyCreate(BaseModel):
    name: Optional[str] = None


class ShutdownRuleCreate(BaseModel):
    target_device_id: int
    action: str = "graceful_shutdown"
    trigger_charge_pct: Optional[int] = None
    trigger_runtime_sec: Optional[int] = None
    enabled: bool = True
    priority: int = 100             # lower fires first during an outage
    delay_after_sec: int = 0        # wait after this rule before the next


class ShutdownRuleUpdate(BaseModel):
    action: Optional[str] = None
    trigger_charge_pct: Optional[int] = None
    trigger_runtime_sec: Optional[int] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    delay_after_sec: Optional[int] = None


class NotificationConfigUpdate(BaseModel):
    webhook_url: Optional[str] = None
    enabled: Optional[bool] = None
    notify_offline: Optional[bool] = None
    notify_ups_state: Optional[bool] = None
    notify_action: Optional[bool] = None


class ServiceCreate(BaseModel):
    """A published web service. The public domain comes from the Namecheap
    integration config (snapshotted onto the row at creation), so the form
    only supplies the subdomain + where to forward."""
    name: str
    subdomain: str
    forward_scheme: str = "http"
    forward_host: str
    forward_port: int
    websockets: bool = True


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class PreflightRequest(BaseModel):
    """Active connectivity test for a *prospective* device. The add-device
    modal POSTs this so the user can validate creds before saving.

    When the modal is in *edit* mode the secret credential fields come back
    blanked from /api/devices/{id}/credentials (so the browser never holds
    the real passwords), and the user can save without re-typing them
    because the PUT handler merges blanks with stored values. The preflight
    endpoint applies the same merge when `device_id` is supplied — without
    that, clicking "Test connection" on an unmodified edit form sends empty
    passwords and probes fail with "no credentials configured" even though
    the saved device has perfectly good creds in the DB."""
    hostname: str
    adapter_type: str
    credentials: dict[str, Any] = {}
    device_id: Optional[int] = None
