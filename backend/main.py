import asyncio
import json
import logging
import secrets
import ssl
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from threading import Lock

import httpx
from fastapi import APIRouter, FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import __version__ as APP_VERSION
from .database import get_db, init_db
from .models import (
    Device, DeviceCache, DeviceMetric, AuthUser, ApiKey, ShutdownRule,
    Event, NotificationConfig,
)
from .schemas import (
    DeviceCreate, DeviceUpdate, LoginRequest, ChangePasswordRequest,
    PreflightRequest, ApiKeyCreate, ShutdownRuleCreate, ShutdownRuleUpdate,
    NotificationConfigUpdate,
)
from . import events as events_mod
from . import poller
from .adapters import get_adapter
from .adapters import oui as oui_db
from .auth import (
    SESSION_USER_KEY,
    authenticate,
    bootstrap_admin,
    current_user,
    generate_api_key,
    get_session_secret,
    hash_password,
    verify_password,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Connection Manager for WebSockets ────────────────────────────────────────

class ConnectionManager:
    # Per-connection send timeout. If a client's socket buffer is wedged we
    # don't want a poll-cycle broadcast to hang the event loop waiting on it —
    # drop the slow client instead.
    _SEND_TIMEOUT_SECONDS = 5.0

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, message: dict):
        # Snapshot upfront so disconnect() mutating self.active_connections
        # mid-iteration can't skip a connection. asyncio.wait_for caps the
        # per-send budget so a single slow client doesn't stall the broadcast.
        for connection in list(self.active_connections):
            try:
                await asyncio.wait_for(
                    connection.send_json(message),
                    timeout=self._SEND_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                logger.warning("WebSocket send timed out after %.1fs — dropping client",
                               self._SEND_TIMEOUT_SECONDS)
                self.disconnect(connection)
            except Exception as exc:
                logger.debug("WebSocket send failed (%s) — dropping client", exc)
                self.disconnect(connection)

manager = ConnectionManager()

# ── Lifecycle (Database & Poller) ────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    bootstrap_admin()
    # Non-blocking — if IEEE is unreachable, startup proceeds against the
    # bundled OUI CSV. Refresh runs once at boot; the 30-day staleness check
    # inside refresh_if_stale makes restarts cheap.
    oui_refresh_task = asyncio.create_task(oui_db.refresh_if_stale())
    poll_task = asyncio.create_task(poller.poll_loop(on_update=manager.broadcast_json))
    yield
    poll_task.cancel()
    oui_refresh_task.cancel()
    for t in (poll_task, oui_refresh_task):
        try:
            await t
        except asyncio.CancelledError:
            pass

app = FastAPI(title="HomeLab Manger", lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=get_session_secret(),
    session_cookie="homelab_session",
    same_site="lax",
    https_only=False,  # homelab — flip to True when fronted by HTTPS
    max_age=60 * 60 * 24 * 14,  # 14 days
)

# ── Helpers ──────────────────────────────────────────────────────────────────

def _device_or_404(device_id: int, db: Session) -> Device:
    d = db.query(Device).filter(Device.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    return d

def _cache_map(device_id: int, db: Session) -> dict:
    """Robust JSON parsing for the device cache."""
    rows = db.query(DeviceCache).filter(DeviceCache.device_id == device_id).all()
    out: dict = {}
    for r in rows:
        if r.data:
            try:
                out[r.cache_key] = json.loads(r.data)
            except json.JSONDecodeError:
                logger.error(f"Malformed JSON in cache for device {device_id}, key {r.cache_key}")
                out[r.cache_key] = None
        if r.error:
            out[f"{r.cache_key}_error"] = r.error
        if r.updated_at:
            out[f"{r.cache_key}_updated"] = r.updated_at.isoformat()
    return out


# ── Auth (unauthenticated endpoints) ─────────────────────────────────────────

auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


@auth_router.get("/me")
def whoami(request: Request):
    user = request.session.get(SESSION_USER_KEY)
    return {"authenticated": bool(user), "username": user}


# Unauthenticated on purpose: the version string isn't sensitive and the login
# page should be able to show it too without round-tripping a session.
@app.get("/api/version")
def app_version():
    return {
        "version": APP_VERSION,
        "github_url": "https://github.com/Spillebulle/homelab-manger",
        "dockerhub_url": "https://hub.docker.com/r/spillebulle/homelab-manger",
    }


@auth_router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = authenticate(db, body.username, body.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    request.session[SESSION_USER_KEY] = user.username
    return {"ok": True, "username": user.username}


@auth_router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@auth_router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(current_user),
):
    user = db.query(AuthUser).filter(AuthUser.username == username).first()
    if not user or not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be at least 8 characters")
    user.password_hash = hash_password(body.new_password)
    db.commit()
    return {"ok": True}


app.include_router(auth_router)


# ── Authenticated API ────────────────────────────────────────────────────────

api = APIRouter(prefix="/api", dependencies=[Depends(current_user)])


@api.get("/devices")
def list_devices(db: Session = Depends(get_db)):
    devices = db.query(Device).all()
    result = []
    for d in devices:
        status_row = db.query(DeviceCache).filter(
            DeviceCache.device_id == d.id, DeviceCache.cache_key == "status"
        ).first()

        status_data = None
        if status_row and status_row.data:
            try:
                status_data = json.loads(status_row.data)
            except json.JSONDecodeError:
                pass

        result.append({
            "id": d.id,
            "name": d.name,
            "hostname": d.hostname,
            "device_type": d.device_type,
            "adapter_type": d.adapter_type,
            "poll_interval": d.poll_interval,
            "status": status_data,
            "status_error": status_row.error if status_row else None,
            "last_seen": status_row.updated_at.isoformat() if status_row and status_row.updated_at else None,
        })
    return result


@api.get("/api-keys")
def list_api_keys(db: Session = Depends(get_db)):
    """List API keys (metadata only — the secret is never returned after
    creation). Ordered newest first."""
    keys = db.query(ApiKey).order_by(ApiKey.id.desc()).all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "prefix": k.prefix,
            "created_at": k.created_at.isoformat() if k.created_at else None,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
        }
        for k in keys
    ]


@api.post("/api-keys", status_code=201)
def create_api_key(body: ApiKeyCreate, db: Session = Depends(get_db)):
    """Create a key and return the plaintext token ONCE. Only its hash is
    stored, so this is the only chance to copy it."""
    token, prefix, key_hash = generate_api_key()
    k = ApiKey(name=(body.name or "API key").strip()[:120], key_hash=key_hash, prefix=prefix)
    db.add(k)
    db.commit()
    db.refresh(k)
    return {"id": k.id, "name": k.name, "prefix": prefix, "key": token}


@api.delete("/api-keys/{key_id}")
def delete_api_key(key_id: int, db: Session = Depends(get_db)):
    k = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not k:
        raise HTTPException(status_code=404, detail="API key not found")
    db.delete(k)
    db.commit()
    return {"ok": True}


@api.post("/devices", status_code=201)
def create_device(body: DeviceCreate, db: Session = Depends(get_db)):
    # EncryptedJSON column accepts a dict directly — encryption happens on flush.
    dev = Device(
        name=body.name, hostname=body.hostname, device_type=body.device_type,
        adapter_type=body.adapter_type, credentials=body.credentials,
        enabled=body.enabled, notes=body.notes, poll_interval=body.poll_interval,
    )
    db.add(dev)
    db.commit()
    db.refresh(dev)
    return {"id": dev.id}


# Secret credential keys: when the edit modal re-submits these as empty
# strings, we keep the existing decrypted value rather than overwriting it
# with "". That's what lets the user edit a non-secret field (hostname, port,
# community) without re-typing every password. Non-secret keys overwrite
# unconditionally so legitimate clearing still works.
_SECRET_CRED_KEYS = {
    "password",
    "ssh_password",
    "web_password",
    "snmp_auth_pass",
    "snmp_priv_pass",
}


def _merge_credentials_for_update(existing: dict | None, incoming: dict) -> dict:
    """Right-bias merge with a sentinel for masked secrets. The frontend
    sends `""` (or just omits the key) for password fields the user didn't
    touch; we treat both as "keep existing". Any other value — including a
    non-empty string the user just typed — overwrites."""
    merged = dict(existing or {})
    for k, v in (incoming or {}).items():
        if k in _SECRET_CRED_KEYS and (v is None or v == ""):
            continue  # keep existing
        merged[k] = v
    return merged


@api.put("/devices/{device_id}")
def update_device(device_id: int, body: DeviceUpdate, db: Session = Depends(get_db)):
    d = _device_or_404(device_id, db)
    for field, value in body.model_dump(exclude_unset=True).items():
        if field == "credentials":
            # Merge so masked password fields don't clobber the stored value.
            setattr(d, field, _merge_credentials_for_update(d.credentials, value))
        else:
            setattr(d, field, value)
    db.commit()
    return {"id": d.id}


@api.delete("/devices/{device_id}")
def delete_device(device_id: int, db: Session = Depends(get_db)):
    d = _device_or_404(device_id, db)
    # SQLite FK cascade isn't enforced (PRAGMA foreign_keys is off), so clean up
    # dependent rows explicitly: cache, time-series, and any shutdown rules that
    # reference this device as either the UPS or the target.
    db.query(DeviceCache).filter(DeviceCache.device_id == device_id).delete()
    db.query(DeviceMetric).filter(DeviceMetric.device_id == device_id).delete()
    db.query(ShutdownRule).filter(
        (ShutdownRule.ups_device_id == device_id)
        | (ShutdownRule.target_device_id == device_id)
    ).delete(synchronize_session=False)
    db.query(NotificationConfig).filter(
        NotificationConfig.device_id == device_id).delete(synchronize_session=False)
    # Keep the event history (device_name is denormalised), just detach it.
    db.query(Event).filter(Event.device_id == device_id).update(
        {Event.device_id: None}, synchronize_session=False)
    db.delete(d)
    db.commit()
    return {"ok": True}


# ── Events (log) + notifications ─────────────────────────────────────────────

@api.get("/events")
def list_events(device_id: int | None = None, event_type: str | None = None,
                limit: int = 100, db: Session = Depends(get_db)):
    """Recent events, newest first. Optional filters by device and type."""
    q = db.query(Event)
    if device_id is not None:
        q = q.filter(Event.device_id == device_id)
    if event_type:
        q = q.filter(Event.event_type == event_type)
    rows = q.order_by(Event.id.desc()).limit(max(1, min(limit, 1000))).all()
    return [
        {
            "id": e.id,
            "ts": e.ts.isoformat() if e.ts else None,
            "device_id": e.device_id,
            "device_name": e.device_name,
            "event_type": e.event_type,
            "severity": e.severity,
            "title": e.title,
            "detail": e.detail,
        }
        for e in rows
    ]


def _serialize_notif(cfg: NotificationConfig) -> dict:
    return {
        "device_id": cfg.device_id,
        "webhook_url": cfg.webhook_url or "",
        "enabled": cfg.enabled,
        "notify_offline": cfg.notify_offline,
        "notify_ups_state": cfg.notify_ups_state,
        "notify_action": cfg.notify_action,
    }


def _get_or_create_notif(device_id: int, db: Session) -> NotificationConfig:
    cfg = (db.query(NotificationConfig)
           .filter(NotificationConfig.device_id == device_id).first())
    if cfg is None:
        cfg = NotificationConfig(device_id=device_id)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


@api.get("/devices/{device_id}/notifications")
def get_notifications(device_id: int, db: Session = Depends(get_db)):
    _device_or_404(device_id, db)
    return _serialize_notif(_get_or_create_notif(device_id, db))


@api.put("/devices/{device_id}/notifications")
def update_notifications(device_id: int, body: NotificationConfigUpdate,
                         db: Session = Depends(get_db)):
    _device_or_404(device_id, db)
    cfg = _get_or_create_notif(device_id, db)
    for field, value in body.model_dump(exclude_unset=True).items():
        if field == "webhook_url" and value is not None:
            value = value.strip() or None
        setattr(cfg, field, value)
    db.commit()
    return _serialize_notif(cfg)


@api.post("/devices/{device_id}/notifications/test")
async def test_notification(device_id: int, db: Session = Depends(get_db)):
    d = _device_or_404(device_id, db)
    cfg = _get_or_create_notif(device_id, db)
    if not cfg.webhook_url:
        raise HTTPException(status_code=400, detail="No webhook URL configured")
    ok, note = await events_mod.post_discord(
        cfg.webhook_url, f"Test notification — {d.name}",
        "If you can read this, HomeLab-Manger notifications are working.",
        "info", d.name,
    )
    if not ok:
        raise HTTPException(status_code=502, detail=note)
    return {"ok": True, "detail": note}


# ── Shutdown rules (Phase-2 outage orchestration) ────────────────────────────
#
# Rules live under a UPS and target another device. The poller evaluates them
# after each UPS poll (see poller._evaluate_shutdown_rules) — these endpoints
# are just CRUD. Actions are pass-through to the target adapter's
# execute_action, so the available actions depend on the target.

_SHUTDOWN_ACTIONS = {"graceful_shutdown", "power_off", "power_cycle", "hard_reset"}


def _serialize_rule(r: ShutdownRule, db: Session) -> dict:
    t = db.query(Device).filter(Device.id == r.target_device_id).first()
    return {
        "id": r.id,
        "ups_device_id": r.ups_device_id,
        "target_device_id": r.target_device_id,
        "target_name": t.name if t else f"(deleted #{r.target_device_id})",
        "target_type": t.device_type if t else None,
        "target_adapter": t.adapter_type if t else None,
        "action": r.action,
        "trigger_charge_pct": r.trigger_charge_pct,
        "trigger_runtime_sec": r.trigger_runtime_sec,
        "enabled": r.enabled,
        "last_triggered_at": r.last_triggered_at.isoformat() if r.last_triggered_at else None,
    }


@api.get("/devices/{ups_id}/shutdown-rules")
def list_shutdown_rules(ups_id: int, db: Session = Depends(get_db)):
    _device_or_404(ups_id, db)
    rules = (db.query(ShutdownRule)
             .filter(ShutdownRule.ups_device_id == ups_id)
             .order_by(ShutdownRule.id).all())
    return [_serialize_rule(r, db) for r in rules]


@api.post("/devices/{ups_id}/shutdown-rules", status_code=201)
def create_shutdown_rule(ups_id: int, body: ShutdownRuleCreate, db: Session = Depends(get_db)):
    _device_or_404(ups_id, db)
    _device_or_404(body.target_device_id, db)
    if body.target_device_id == ups_id:
        raise HTTPException(status_code=400, detail="A UPS can't target itself")
    if db.query(ShutdownRule).filter(
        ShutdownRule.ups_device_id == ups_id,
        ShutdownRule.target_device_id == body.target_device_id,
    ).first():
        raise HTTPException(status_code=409, detail="A rule for that device already exists")
    rule = ShutdownRule(
        ups_device_id=ups_id, target_device_id=body.target_device_id,
        action=body.action if body.action in _SHUTDOWN_ACTIONS else "graceful_shutdown",
        trigger_charge_pct=body.trigger_charge_pct,
        trigger_runtime_sec=body.trigger_runtime_sec, enabled=body.enabled,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _serialize_rule(rule, db)


@api.put("/shutdown-rules/{rule_id}")
def update_shutdown_rule(rule_id: int, body: ShutdownRuleUpdate, db: Session = Depends(get_db)):
    r = db.query(ShutdownRule).filter(ShutdownRule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")
    data = body.model_dump(exclude_unset=True)
    if "action" in data and data["action"] not in _SHUTDOWN_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported action {data['action']!r}")
    for field, value in data.items():
        setattr(r, field, value)
    # Any edit re-arms the rule so a changed threshold takes effect cleanly.
    r.last_triggered_at = None
    db.commit()
    return _serialize_rule(r, db)


@api.delete("/shutdown-rules/{rule_id}")
def delete_shutdown_rule(rule_id: int, db: Session = Depends(get_db)):
    r = db.query(ShutdownRule).filter(ShutdownRule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(r)
    db.commit()
    return {"ok": True}


@api.post("/devices/{device_id}/refresh")
async def refresh_device(device_id: int, db: Session = Depends(get_db)):
    await poller.poll_device(device_id, on_update=manager.broadcast_json)
    return {"ok": True}


@api.get("/devices/{device_id}/cache")
def get_cache(device_id: int, db: Session = Depends(get_db)):
    return _cache_map(device_id, db)


def _downsample(points: list[tuple], max_points: int) -> list[list]:
    """Bucket-average a [(ts, value), …] series down to ~max_points so a
    30-day window doesn't ship 40k points to a canvas that's 600px wide. Each
    bucket reports its mid-time and mean value; short series pass through
    untouched. Returns [[iso_ts, value], …]."""
    n = len(points)
    if n <= max_points:
        return [[ts.isoformat(), v] for ts, v in points]
    out: list[list] = []
    bucket = n / max_points
    for i in range(max_points):
        lo = int(i * bucket)
        hi = int((i + 1) * bucket) or lo + 1
        chunk = points[lo:hi]
        if not chunk:
            continue
        mid = chunk[len(chunk) // 2][0]
        avg = sum(v for _, v in chunk) / len(chunk)
        out.append([mid.isoformat(), round(avg, 3)])
    return out


@api.get("/devices/{device_id}/history")
def get_history(
    device_id: int,
    metrics: str | None = None,
    hours: float = 24.0,
    max_points: int = 600,
    db: Session = Depends(get_db),
):
    """Time-series history for graphing. `metrics` is a comma-separated list
    (default: every metric the device has recorded); `hours` is the look-back
    window. Series longer than `max_points` are bucket-averaged. Shape:
    {from, to, metrics: {name: [[iso_ts, value], …]}}."""
    _device_or_404(device_id, db)
    since = datetime.utcnow() - timedelta(hours=max(0.0, hours))
    wanted = [m.strip() for m in metrics.split(",") if m.strip()] if metrics else None

    q = db.query(DeviceMetric).filter(
        DeviceMetric.device_id == device_id,
        DeviceMetric.ts >= since,
    )
    if wanted:
        q = q.filter(DeviceMetric.metric.in_(wanted))
    rows = q.order_by(DeviceMetric.ts.asc()).all()

    series: dict[str, list[tuple]] = {}
    for r in rows:
        series.setdefault(r.metric, []).append((r.ts, r.value))

    return {
        "from": since.isoformat(),
        "to": datetime.utcnow().isoformat(),
        "metrics": {m: _downsample(pts, max_points) for m, pts in series.items()},
    }


@api.get("/devices/{device_id}/usb-diagnostics")
async def usb_diagnostics(device_id: int, db: Session = Depends(get_db)):
    """Dump the raw HID report descriptor + decoded usages/values for a USB UPS.
    The USB analogue of the snmp-walk debug route — used to confirm a new UPS
    model is covered by the generic HID parser, or to see what's missing."""
    d = _device_or_404(device_id, db)
    if d.adapter_type != "usbups":
        raise HTTPException(status_code=400, detail="USB diagnostics only available for usbups devices")
    adapter = get_adapter(d.adapter_type, d.hostname, d.credentials or {})
    try:
        return await adapter.diagnostics()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"{type(exc).__name__}: {exc}")
    finally:
        try:
            await adapter.close()
        except Exception:
            pass


@api.get("/devices/{device_id}/credentials")
def get_device_credentials(device_id: int, db: Session = Depends(get_db)):
    """Return the device's credentials with secret fields blanked out, so the
    edit modal can pre-populate non-secret values (community, ports, usernames)
    without exposing the actual secrets to the browser. The PUT handler treats
    empty values for `_SECRET_CRED_KEYS` as "keep existing" — so the user can
    save the edit modal without re-typing every password.

    The list endpoint deliberately omits credentials entirely; this is the
    only path that surfaces them, which keeps the attack surface for any
    XSS / CSRF on the read side small."""
    d = _device_or_404(device_id, db)
    creds = dict(d.credentials or {})
    for k in list(creds.keys()):
        if k in _SECRET_CRED_KEYS:
            # Empty string (not the original value) so the frontend can render
            # a "(unchanged — leave blank to keep)" placeholder without ever
            # holding the secret in DOM.
            creds[k] = ""
    return creds


# ── Preflight (service requirements + active connectivity test) ──────────────
#
# Two flavours, both consumed by the add-device modal:
#   GET  /api/adapter-requirements        → static metadata keyed by adapter
#                                            type. Drives the "?" tooltip.
#   POST /api/devices/preflight           → active per-service check. Drives
#                                            the "Test connection" button and
#                                            the post-save warning toast.
# Preflight tests are best-effort: a fail here doesn't block creating the
# device (the user might be testing from a network that can't reach SSH but
# the polling host can — homelab scenarios are weird).


@api.get("/adapter-requirements")
def adapter_requirements():
    """Returns {adapter_type: [{service, transport, port, description, required}]}
    keyed by every entry in ADAPTER_MAP. Used by the SPA's tooltip; the port
    value uses the adapter's *default* (no credentials applied) because we
    don't have a device context here."""
    from .adapters import ADAPTER_MAP
    out: dict[str, list[dict]] = {}
    for atype in ADAPTER_MAP:
        try:
            inst = get_adapter(atype, "preflight.local", {})
        except Exception as exc:
            logger.warning("Cannot build adapter %s for requirements lookup: %s", atype, exc)
            continue
        out[atype] = inst.requirements()
    return out


def _summarise_preflight(results: list[dict]) -> str:
    """Roll up per-service results into a headline outcome the SPA can render
    in one glance. None/skipped don't count against the rollup since UDP
    probes are intentionally indeterminate."""
    required_fail = any(r.get("required") and r.get("ok") is False for r in results)
    optional_fail = any((not r.get("required")) and r.get("ok") is False for r in results)
    if required_fail:
        return "fail"
    if optional_fail:
        return "partial"
    return "ok"


async def _run_preflight(adapter) -> dict:
    try:
        results = await adapter.preflight()
    finally:
        try:
            await adapter.close()
        except Exception as exc:
            logger.debug("adapter.close() after preflight failed: %s", exc)
    return {"status": _summarise_preflight(results), "results": results}


@api.post("/devices/preflight")
async def preflight_device(body: PreflightRequest, db: Session = Depends(get_db)):
    """Run each requirement's active test against a *prospective* device
    (called by the modal's Test button before the device exists). Returns
    {status, results} where results is the per-service list.

    If `device_id` is supplied, merge the incoming form credentials with the
    device's stored decrypted credentials using the same rule the PUT
    handler applies: empty values in secret fields fall through to the
    existing stored secret. This lets "Test connection" work in the edit
    modal without re-typing masked passwords."""
    creds = dict(body.credentials or {})
    if body.device_id is not None:
        existing = db.query(Device).filter(Device.id == body.device_id).first()
        if existing is not None:
            creds = _merge_credentials_for_update(existing.credentials, creds)
    try:
        adapter = get_adapter(body.adapter_type, body.hostname, creds)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return await _run_preflight(adapter)


@api.post("/devices/{device_id}/preflight")
async def preflight_existing_device(device_id: int, db: Session = Depends(get_db)):
    """Preflight an *already-saved* device using its decrypted stored
    credentials. The auto-preflight after Save/Edit calls this instead of
    /devices/preflight so masked password fields in the edit modal don't
    produce false-negative results — the form-state path can only see
    whatever the user typed, not the secrets we kept hidden."""
    d = _device_or_404(device_id, db)
    creds = d.credentials or {}
    try:
        adapter = get_adapter(d.adapter_type, d.hostname, creds)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return await _run_preflight(adapter)


@api.post("/devices/{device_id}/action")
async def device_action(device_id: int, action: dict, db: Session = Depends(get_db)):
    d = _device_or_404(device_id, db)
    creds = d.credentials or {}
    adapter = get_adapter(d.adapter_type, d.hostname, creds)
    try:
        return await adapter.execute_action(action)
    finally:
        # close() releases BMC session slots (CIMC has a 4-slot cap; iBMC
        # rejects new logins past ~4 active sessions). Ad-hoc actions used
        # to leak one slot per click; the poll path already cleans up.
        try:
            await adapter.close()
        except Exception as exc:
            logger.warning("adapter.close() after action on device %d failed: %s",
                           device_id, exc)


@api.post("/devices/{device_id}/port/{port_id}/action")
async def port_action(device_id: int, port_id: str, action: dict, db: Session = Depends(get_db)):
    d = _device_or_404(device_id, db)
    creds = d.credentials or {}
    adapter = get_adapter(d.adapter_type, d.hostname, creds)
    action["port_id"] = port_id
    try:
        return await adapter.execute_action(action)
    finally:
        try:
            await adapter.close()
        except Exception as exc:
            logger.warning("adapter.close() after port action on device %d failed: %s",
                           device_id, exc)


@api.get("/devices/{device_id}/kvm.jnlp")
async def download_kvm_jnlp(device_id: int, request: Request, db: Session = Depends(get_db)):
    """
    KVM JNLP launcher for server adapters that use Java Web Start (CIMC, iBMC).
    CRITICAL: We do NOT call adapter.close() here for CIMC, as tokens are tied
    to the active XMLAPI session.

    For `cimc_redfish` we additionally rewrite the JAR URLs in the JNLP body to
    proxy through `/api/cimc-kvm-proxy/{id}/...`. CIMC 3.0+ returns 403 on
    HEAD requests against `/software/*` (GET works fine), and JWS issues a
    HEAD on every cached JAR before launch — so without the proxy, JWS
    aborts on the second launch with `Server returned HTTP response code:
    403 for URL: .../avctNuova.jar.pack.gz`. The proxy synthesises a 200 OK
    on HEAD and streams the GET through.
    """
    d = _device_or_404(device_id, db)
    if d.adapter_type not in ["cimc", "cimc_redfish", "ibmc"]:
        raise HTTPException(status_code=400, detail=f"KVM JNLP not supported for {d.adapter_type}")

    creds = d.credentials or {}
    adapter = get_adapter(d.adapter_type, d.hostname, creds)

    result = await adapter.execute_action({"type": "kvm_launch"})

    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])

    body = result["jnlp"]
    if d.adapter_type == "cimc_redfish":
        body = _rewrite_cimc_jnlp_for_proxy(body, d, creds, request)

    filename = f"{d.adapter_type}-{d.name}.jnlp"
    return Response(
        content=body,
        media_type="application/x-java-jnlp-file",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache"
        }
    )


# ── CIMC KVM JAR proxy ───────────────────────────────────────────────────────
#
# JWS launches the Cisco KVM viewer by fetching a handful of .jar.pack.gz
# files from `https://<bmc>/software/`. CIMC 3.0(4r) firmware returns 403
# on HEAD requests there (verified empirically on a UCS C22 M3S; the same
# paths return 200 on GET, even unauthenticated). JWS HEAD-validates each
# cached resource on launch via `ResourceProviderImpl.checkUpdateAvailable`
# regardless of the JNLP `<update>` element, hits the 403, and aborts.
#
# To work around this, the JNLP we serve for `cimc_redfish` rewrites every
# `https://<bmc>/software/<jar>` URL to `/api/cimc-kvm-proxy/<id>/<jar>?t=<token>`.
# The proxy below answers HEAD with a synthetic 200 (so JWS happily proceeds)
# and streams the GET through to CIMC. JWS doesn't carry our session cookie,
# so the proxy is gated by a one-shot token minted alongside the JNLP — the
# token is good for 10 minutes and only for the device it was issued
# against. Tokens stay valid for repeat fetches because JWS will issue
# multiple GETs per launch (different OS-arch native libs, etc.).

_KVM_PROXY_TTL_SECONDS = 600
_kvm_proxy_tokens: dict[str, dict] = {}
_kvm_proxy_lock = Lock()


def _mint_kvm_proxy_token(device_id: int) -> str:
    token = secrets.token_urlsafe(24)
    expires = time.time() + _KVM_PROXY_TTL_SECONDS
    with _kvm_proxy_lock:
        # Drop expired entries opportunistically — no separate sweeper task.
        now = time.time()
        for tok in [t for t, e in _kvm_proxy_tokens.items() if e["expires"] < now]:
            _kvm_proxy_tokens.pop(tok, None)
        _kvm_proxy_tokens[token] = {"device_id": device_id, "expires": expires}
    return token


def _validate_kvm_proxy_token(device_id: int, token: str) -> bool:
    with _kvm_proxy_lock:
        entry = _kvm_proxy_tokens.get(token)
        if not entry:
            return False
        if entry["device_id"] != device_id:
            return False
        if entry["expires"] < time.time():
            _kvm_proxy_tokens.pop(token, None)
            return False
        return True


def _rewrite_cimc_jnlp_for_proxy(body: str, device, creds: dict, request: Request) -> str:
    """Rewrite every `https://<bmc>:<port>/software/<file>` in the JNLP body
    to an authenticated `/api/cimc-kvm-proxy/{id}/<file>?t=<token>` URL on
    our backend. Leaves codebase / icon / helpurl alone — they're not
    fetched by JWS in a way that exposes the HEAD-403 issue."""
    import re
    port = int(creds.get("port", 443))
    proxy_base = str(request.base_url).rstrip("/") + f"/api/cimc-kvm-proxy/{device.id}"
    token = _mint_kvm_proxy_token(device.id)
    pat = re.compile(
        rf"https://{re.escape(device.hostname)}:{port}/software/([A-Za-z0-9._-]+)"
    )
    return pat.sub(lambda m: f"{proxy_base}/{m.group(1)}?t={token}", body)


def _legacy_bmc_ssl_context() -> ssl.SSLContext:
    """Same legacy-cipher SSLContext the CIMC adapter uses — UCS C-series
    BMCs ship 1024-bit RSA self-signed certs that modern OpenSSL refuses
    under SECLEVEL=2 with `verify=False` alone."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    return ctx


@app.api_route("/api/cimc-kvm-proxy/{device_id}/{jar_name}", methods=["GET", "HEAD"])
async def cimc_kvm_proxy(device_id: int, jar_name: str, t: str, request: Request,
                         db: Session = Depends(get_db)):
    if not _validate_kvm_proxy_token(device_id, t):
        raise HTTPException(status_code=403, detail="Invalid or expired proxy token")
    d = _device_or_404(device_id, db)
    if d.adapter_type != "cimc_redfish":
        raise HTTPException(status_code=400, detail="Proxy only available for cimc_redfish")
    # Defensive — `jar_name` should be a single segment by virtue of the route
    # not using `:path`, but reject anything weird anyway.
    if "/" in jar_name or "\\" in jar_name or jar_name.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid path")

    creds = d.credentials or {}
    port = int(creds.get("port", 443))
    target = f"https://{d.hostname}:{port}/software/{jar_name}"

    # JWS HEADs cached resources before launch. CIMC 3.0+ refuses HEAD on
    # /software/* with 403 — synthesise a 200 here so JWS proceeds to GET.
    # Returning a Last-Modified that's always "now" forces JWS to skip the
    # cache and re-fetch (its cached Last-Modified is older), which is the
    # desired behaviour: the cached version may be from an older firmware
    # rev where the JARs differed.
    if request.method == "HEAD":
        return Response(
            status_code=200,
            headers={
                "Content-Type": "application/octet-stream",
                "Last-Modified": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
                "Cache-Control": "no-cache",
            },
        )

    ctx = _legacy_bmc_ssl_context()
    try:
        async with httpx.AsyncClient(verify=ctx, timeout=60) as c:
            r = await c.get(target)
    except httpx.HTTPError as e:
        logger.warning("CIMC KVM proxy GET %s failed: %s", target, e)
        raise HTTPException(status_code=502, detail=f"BMC fetch failed: {e}")

    if r.status_code >= 400:
        logger.warning(
            "CIMC KVM proxy: %s returned HTTP %d for jar %s (token=%s)",
            d.hostname, r.status_code, jar_name, t[:8],
        )

    # Strip hop-by-hop headers and the Server header so we don't leak
    # the BMC's `Server: Monkey` banner.
    drop = {"transfer-encoding", "connection", "keep-alive", "server",
            "content-encoding", "content-length"}
    forwarded = {k: v for k, v in r.headers.items() if k.lower() not in drop}
    forwarded.setdefault("Content-Type", "application/octet-stream")
    return Response(content=r.content, status_code=r.status_code, headers=forwarded)


app.include_router(api)


# ── WebSocket (gated by session cookie) ──────────────────────────────────────

@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    if not websocket.session.get(SESSION_USER_KEY):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ── Frontend ─────────────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="frontend/static"), name="static")


@app.get("/login")
def serve_login():
    return FileResponse("frontend/login.html")


@app.get("/")
@app.get("/{path:path}")
def serve_spa(request: Request, path: str = ""):
    # Anything under /api or /static is handled by other routes; this catch-all
    # only fires for SPA paths. Send unauthenticated visitors to the login page
    # so they don't get a flash of the empty app shell.
    if not request.session.get(SESSION_USER_KEY):
        return FileResponse("frontend/login.html")
    return FileResponse("frontend/index.html")
