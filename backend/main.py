import asyncio
import json
import logging
import re
import secrets
import ssl
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from threading import Lock

import httpx
from fastapi import APIRouter, FastAPI, HTTPException, Depends, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import __version__ as APP_VERSION
from .database import get_db, init_db
from .models import (
    Device, DeviceCache, DeviceMetric, AuthUser, ApiKey, ShutdownRule,
    Event, NotificationConfig, Integration, Service,
)
from .schemas import (
    DeviceCreate, DeviceUpdate, LoginRequest, ChangePasswordRequest,
    PreflightRequest, ApiKeyCreate, ShutdownRuleCreate, ShutdownRuleUpdate,
    NotificationConfigUpdate, ServiceCreate, ServiceUpdate,
)
from . import events as events_mod
from . import poller
from . import services_manager
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

# Quiet the chatty third-party loggers. At INFO they drown the log: httpx emits a
# line per Redfish/Discord request (and that includes the full webhook URL — a
# secret — in plaintext), and paramiko logs every SSH connect/auth. Our own
# loggers stay at INFO so device-poll warnings and events remain visible.
for _noisy in ("httpx", "httpcore", "paramiko", "paramiko.transport", "urllib3", "pysnmp"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

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

def _iso_z(dt: datetime) -> str:
    """Render a naive-UTC timestamp as RFC 3339 with a trailing `Z`. Every
    timestamp this API emits goes through here. Our stored timestamps are naive
    UTC (`datetime.utcnow()`); without the `Z` downstream consumers (browsers,
    Grafana, anything calling `new Date()`) guess the zone and shift the value."""
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


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
            out[f"{r.cache_key}_updated"] = _iso_z(r.updated_at)
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


# Unauthenticated container/orchestration health probe. Confirms the process is
# up AND the SQLite DB is reachable (a wedged DB is the realistic failure mode);
# the Dockerfile HEALTHCHECK hits this. Returns 503 so Docker marks the
# container unhealthy and can restart it.
@app.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error("healthz DB check failed: %s", exc)
        return JSONResponse(status_code=503, content={"status": "error", "db": False})
    return {"status": "ok", "db": True, "version": APP_VERSION}


# ── Login brute-force throttle ───────────────────────────────────────────────
# Single-user homelab app, but an exposed login with unlimited guesses is an easy
# win for a bot. Track failed attempts per client IP in-memory (no persistence —
# a restart clears it, which is fine) and lock out after _LOGIN_MAX_FAILS within
# _LOGIN_WINDOW. Successful login clears the counter.
_LOGIN_MAX_FAILS = 5
_LOGIN_WINDOW = 300          # seconds to remember failures / lockout duration
_login_fails: dict[str, list[float]] = {}
_login_lock = Lock()


def _login_client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _login_throttle_check(key: str) -> None:
    now = time.monotonic()
    with _login_lock:
        hits = [t for t in _login_fails.get(key, []) if now - t < _LOGIN_WINDOW]
        _login_fails[key] = hits
        if len(hits) >= _LOGIN_MAX_FAILS:
            retry = int(_LOGIN_WINDOW - (now - hits[0]))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again later.",
                headers={"Retry-After": str(max(retry, 1))},
            )


def _login_record_fail(key: str) -> None:
    now = time.monotonic()
    with _login_lock:
        _login_fails.setdefault(key, []).append(now)


def _login_clear(key: str) -> None:
    with _login_lock:
        _login_fails.pop(key, None)


@auth_router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    key = _login_client_key(request)
    _login_throttle_check(key)
    user = authenticate(db, body.username, body.password)
    if not user:
        _login_record_fail(key)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    _login_clear(key)
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
            "shutdown_actions": _shutdown_actions_for(d.adapter_type),
            "status": status_data,
            "status_error": status_row.error if status_row else None,
            "last_seen": _iso_z(status_row.updated_at) if status_row and status_row.updated_at else None,
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
            "created_at": _iso_z(k.created_at) if k.created_at else None,
            "last_used_at": _iso_z(k.last_used_at) if k.last_used_at else None,
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
            "ts": _iso_z(e.ts) if e.ts else None,
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

def _shutdown_actions_for(adapter_type: str) -> list[str]:
    """Shutdown-style actions the given adapter type actually supports (its
    class `SHUTDOWN_ACTIONS`). Empty for devices that can't be powered off
    (switches, the UPS itself) so the UI won't offer them as targets."""
    from .adapters import ADAPTER_MAP
    cls = ADAPTER_MAP.get(adapter_type)
    return list(getattr(cls, "SHUTDOWN_ACTIONS", []) or [])


def _serialize_rule(r: ShutdownRule, db: Session) -> dict:
    t = db.query(Device).filter(Device.id == r.target_device_id).first()
    return {
        "id": r.id,
        "ups_device_id": r.ups_device_id,
        "target_device_id": r.target_device_id,
        "target_name": t.name if t else f"(deleted #{r.target_device_id})",
        "target_type": t.device_type if t else None,
        "target_adapter": t.adapter_type if t else None,
        "target_shutdown_actions": _shutdown_actions_for(t.adapter_type) if t else [],
        "action": r.action,
        "trigger_charge_pct": r.trigger_charge_pct,
        "trigger_runtime_sec": r.trigger_runtime_sec,
        "enabled": r.enabled,
        "priority": r.priority,
        "delay_after_sec": r.delay_after_sec,
        "last_triggered_at": _iso_z(r.last_triggered_at) if r.last_triggered_at else None,
    }


@api.get("/devices/{ups_id}/shutdown-rules")
def list_shutdown_rules(ups_id: int, db: Session = Depends(get_db)):
    _device_or_404(ups_id, db)
    rules = (db.query(ShutdownRule)
             .filter(ShutdownRule.ups_device_id == ups_id)
             .order_by(ShutdownRule.priority, ShutdownRule.id).all())
    return [_serialize_rule(r, db) for r in rules]


@api.post("/devices/{ups_id}/shutdown-rules", status_code=201)
def create_shutdown_rule(ups_id: int, body: ShutdownRuleCreate, db: Session = Depends(get_db)):
    _device_or_404(ups_id, db)
    target = _device_or_404(body.target_device_id, db)
    if body.target_device_id == ups_id:
        raise HTTPException(status_code=400, detail="A UPS can't target itself")
    supported = _shutdown_actions_for(target.adapter_type)
    if not supported:
        raise HTTPException(
            status_code=400,
            detail=f"{target.name} ({target.adapter_type}) can't be powered off — "
                   "no shutdown action is supported for this device type.")
    if db.query(ShutdownRule).filter(
        ShutdownRule.ups_device_id == ups_id,
        ShutdownRule.target_device_id == body.target_device_id,
    ).first():
        raise HTTPException(status_code=409, detail="A rule for that device already exists")
    action = body.action if body.action in supported else supported[0]
    rule = ShutdownRule(
        ups_device_id=ups_id, target_device_id=body.target_device_id,
        action=action,
        trigger_charge_pct=body.trigger_charge_pct,
        trigger_runtime_sec=body.trigger_runtime_sec, enabled=body.enabled,
        priority=body.priority, delay_after_sec=body.delay_after_sec,
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
    if "action" in data:
        target = db.query(Device).filter(Device.id == r.target_device_id).first()
        supported = _shutdown_actions_for(target.adapter_type) if target else []
        if data["action"] not in supported:
            raise HTTPException(
                status_code=400,
                detail=f"Action {data['action']!r} isn't supported for "
                       f"{target.name if target else 'this device'}.")
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


@api.post("/devices/{ups_id}/shutdown-rules/test")
async def test_shutdown_plan(ups_id: int, db: Session = Depends(get_db)):
    """Dry-run the outage plan: simulate a full outage and report which rules
    would fire, in order — without sending any action to a device. Emits a
    `[Dry run]` event per rule (so notifications also get exercised) and nothing
    is stamped/armed. Lets the user sanity-check the plan before relying on it."""
    ups = _device_or_404(ups_id, db)
    plan = await poller.dry_run_shutdown_plan(db, ups)
    return {"ok": True, "dry_run": True, "count": len(plan), "plan": plan}


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
        return [[_iso_z(ts), v] for ts, v in points]
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
        out.append([_iso_z(mid), round(avg, 3)])
    return out


@api.get("/devices/{device_id}/history")
def get_history(
    device_id: int,
    metrics: str | None = None,
    hours: float = 24.0,
    max_points: int = 600,
    from_: str | None = Query(None, alias="from"),
    to_: str | None = Query(None, alias="to"),
    db: Session = Depends(get_db),
):
    """Time-series history for graphing. `metrics` is a comma-separated list
    (default: every metric the device has recorded). The window is either the
    last `hours` (default 24) OR an explicit `from`/`to` (epoch-ms / epoch-s /
    ISO — same parsing as `/graph`) for a custom range. Series longer than
    `max_points` are bucket-averaged. Shape:
    {from, to, metrics: {name: [[iso_ts, value], …]}}."""
    _device_or_404(device_id, db)
    until = _parse_time_param(to_) or datetime.utcnow()
    since = _parse_time_param(from_)
    if since is None:
        since = until - timedelta(hours=max(0.0, hours))
    if since > until:
        since, until = until, since
    wanted = [m.strip() for m in metrics.split(",") if m.strip()] if metrics else None

    series = _load_metric_series(device_id, wanted, since, until, db)
    return {
        "from": _iso_z(since),
        "to": _iso_z(until),
        "metrics": {m: _downsample(pts, max_points) for m, pts in series.items()},
    }


# ── Graph endpoint (BI / charting tool friendly) ─────────────────────────────
#
# `/history` returns a nested `{metrics: {name: [[ts, value], …]}}` object whose
# rows are 2-element arrays — convenient for the bundled SPA, awkward for generic
# charting tools (Grafana Infinity, Metabase, Observable, pandas.read_json …),
# which all want a flat array of objects with named, typed columns and an
# unambiguous timestamp. `/graph` is that shape. It's intentionally generic
# (any device that records `metrics` works, not just UPS) and named `graph`
# rather than e.g. `grafana` so it reads as tool-agnostic.
#
# Differences from `/history` that make it "work like other APIs":
#   • Top-level JSON array — no root/object to drill into.
#   • RFC 3339 timestamps with an explicit `Z` (UTC), so no tool guesses the zone.
#   • Accepts a `from`/`to` window in epoch-ms (Grafana's ${__from}/${__to}),
#     epoch-seconds, or ISO-8601 — so the tool's own time picker can drive it.

def _parse_time_param(val: str | None) -> datetime | None:
    """Parse a `from`/`to` query value into naive UTC. Accepts epoch
    milliseconds (Grafana ${__from}/${__to}), epoch seconds, or an ISO-8601
    string (with or without an offset). Returns None for missing/blank."""
    if not val or not val.strip():
        return None
    val = val.strip()
    if val.lstrip("-").isdigit():
        n = int(val)
        # Grafana sends epoch *milliseconds*; bare seconds are ~1.7e9, ms ~1.7e12.
        if abs(n) >= 100_000_000_000:  # 1e11 — anything larger is milliseconds
            return datetime.utcfromtimestamp(n / 1000.0)
        return datetime.utcfromtimestamp(n)
    dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _load_metric_series(device_id: int, wanted: list[str] | None,
                        since: datetime, until: datetime,
                        db: Session) -> dict[str, list[tuple]]:
    """Group raw metric samples in [since, until] into {metric: [(ts, value)]}."""
    q = db.query(DeviceMetric).filter(
        DeviceMetric.device_id == device_id,
        DeviceMetric.ts >= since,
        DeviceMetric.ts <= until,
    )
    if wanted:
        q = q.filter(DeviceMetric.metric.in_(wanted))
    rows = q.order_by(DeviceMetric.ts.asc()).all()
    series: dict[str, list[tuple]] = {}
    for r in rows:
        series.setdefault(r.metric, []).append((r.ts, r.value))
    return series


def _downsample_tuples(points: list[tuple], max_points: int) -> list[tuple]:
    """Bucket-average a [(ts, value), …] series to ~max_points, preserving
    (datetime, value) tuples (the tuple-returning sibling of `_downsample`)."""
    n = len(points)
    if n <= max_points:
        return points
    out: list[tuple] = []
    bucket = n / max_points
    for i in range(max_points):
        lo = int(i * bucket)
        hi = int((i + 1) * bucket) or lo + 1
        chunk = points[lo:hi]
        if not chunk:
            continue
        mid = chunk[len(chunk) // 2][0]
        avg = sum(v for _, v in chunk) / len(chunk)
        out.append((mid, round(avg, 3)))
    return out


def _wide_rows(series: dict[str, list[tuple]], start: datetime,
               until: datetime, max_points: int) -> list[dict]:
    """Align every metric onto a shared time grid of `max_points` buckets so
    each output row carries one timestamp + a column per metric. Metrics with
    no sample in a bucket are simply absent from that row (a gap, not a zero)."""
    span = (until - start).total_seconds()
    bucket = span / max_points if span > 0 else 1.0
    grid: dict[int, dict[str, list[float]]] = {}
    for metric, pts in series.items():
        for ts, v in pts:
            idx = int((ts - start).total_seconds() / bucket) if bucket else 0
            idx = max(0, min(idx, max_points - 1))
            grid.setdefault(idx, {}).setdefault(metric, []).append(v)
    out: list[dict] = []
    for idx in sorted(grid):
        mid = start + timedelta(seconds=(idx + 0.5) * bucket)
        row: dict = {"time": _iso_z(mid)}
        for metric, vals in grid[idx].items():
            row[metric] = round(sum(vals) / len(vals), 3)
        out.append(row)
    return out


@api.get("/devices/{device_id}/graph")
def get_graph(
    device_id: int,
    metrics: str | None = None,
    hours: float = 24.0,
    from_: str | None = Query(None, alias="from"),
    to: str | None = None,
    max_points: int = 600,
    format: str = "long",
    db: Session = Depends(get_db),
):
    """Charting-tool-friendly time-series, as a flat JSON array.

    Query params:
      • `metrics`    — comma-separated metric names (default: all recorded).
      • `from`/`to`  — window bounds; epoch-ms (Grafana ${__from}/${__to}),
                       epoch-seconds, or ISO-8601. `to` defaults to now.
      • `hours`      — used only when `from` is omitted (default 24).
      • `max_points` — per-series downsample cap (default 600).
      • `format`     — `long` (default) or `wide`.

    `long` → one object per point, ideal for a multi-series panel that splits
    by the `metric` label:
        [ {"time": "2026-06-01T19:38:45.942Z", "metric": "watts", "value": 840.0}, … ]

    `wide` → one object per timestamp, a column per metric (spreadsheet shape):
        [ {"time": "2026-06-01T19:38:00.000Z", "watts": 840.0, "load_pct": 70.0}, … ]
    """
    _device_or_404(device_id, db)
    if format not in ("long", "wide"):
        raise HTTPException(status_code=400, detail="format must be 'long' or 'wide'")

    until = _parse_time_param(to) or datetime.utcnow()
    start = _parse_time_param(from_)
    if start is None:
        start = until - timedelta(hours=max(0.0, hours))
    wanted = [m.strip() for m in metrics.split(",") if m.strip()] if metrics else None

    series = _load_metric_series(device_id, wanted, start, until, db)

    if format == "wide":
        return _wide_rows(series, start, until, max(1, max_points))

    rows: list[dict] = []
    for metric, pts in series.items():
        for ts, v in _downsample_tuples(pts, max(1, max_points)):
            rows.append({"time": _iso_z(ts), "metric": metric, "value": v})
    rows.sort(key=lambda r: (r["time"], r["metric"]))
    return rows


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


# Adapters signal failure in-band: `execute_action` returns `{"error": ...}` (or
# `{"errors": [...]}` for batch ops like vlan_batch) rather than raising. Other
# API clients expect failure to surface as a non-2xx status, so map it here.
# The body is left untouched, so the SPA (which reads `data.error`/`data.errors`
# off the parsed body regardless of status) keeps working unchanged.
def _action_response(result):
    if not isinstance(result, dict):
        return result
    err, errs = result.get("error"), result.get("errors")
    if err or errs:
        msg = str(err or "").lower()
        # Unsupported/invalid action = client error; anything else = the device
        # or its adapter failed downstream.
        code = 400 if ("unsupported" in msg or "not supported" in msg) else 502
        return JSONResponse(status_code=code, content=result)
    return result


@api.post("/devices/{device_id}/action")
async def device_action(device_id: int, action: dict, db: Session = Depends(get_db)):
    d = _device_or_404(device_id, db)
    creds = d.credentials or {}
    adapter = get_adapter(d.adapter_type, d.hostname, creds)
    try:
        result = await adapter.execute_action(action)
    finally:
        # close() releases BMC session slots (CIMC has a 4-slot cap; iBMC
        # rejects new logins past ~4 active sessions). Ad-hoc actions used
        # to leak one slot per click; the poll path already cleans up.
        try:
            await adapter.close()
        except Exception as exc:
            logger.warning("adapter.close() after action on device %d failed: %s",
                           device_id, exc)
    return _action_response(result)


@api.post("/devices/{device_id}/port/{port_id}/action")
async def port_action(device_id: int, port_id: str, action: dict, db: Session = Depends(get_db)):
    d = _device_or_404(device_id, db)
    creds = d.credentials or {}
    adapter = get_adapter(d.adapter_type, d.hostname, creds)
    action["port_id"] = port_id
    try:
        result = await adapter.execute_action(action)
    finally:
        try:
            await adapter.close()
        except Exception as exc:
            logger.warning("adapter.close() after port action on device %d failed: %s",
                           device_id, exc)
    return _action_response(result)


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


# ── Services (publish apps via Nginx Proxy Manager + Namecheap DNS) ─────────
#
# A "service" is an internal app published at https://<subdomain>.<domain>.
# Creating one kicks off a background provisioning pipeline (DNS record →
# NPM proxy host → Let's Encrypt cert) in services_manager; these endpoints
# are CRUD + the integration settings the pipeline reads. Integration configs
# (NPM admin creds, Namecheap API key) are stored Fernet-encrypted in the
# `integrations` table and get the same blank-keeps-existing PUT treatment
# as device credentials.

_SUBDOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _serialize_integration(name: str, cfg: dict) -> dict:
    out = dict(cfg)
    for k in services_manager.INTEGRATION_SECRET_KEYS.get(name, set()):
        if out.get(k):
            out[k] = ""  # blank, same contract as device credentials
    out["configured"] = services_manager.integration_configured(name, cfg)
    return out


_INTEGRATION_NAMES = ("npm", "namecheap", "portainer")


@api.get("/integrations")
def list_integrations(db: Session = Depends(get_db)):
    return {
        name: _serialize_integration(name, services_manager.get_integration_config(db, name))
        for name in _INTEGRATION_NAMES
    }


@api.put("/integrations/{name}")
def update_integration(name: str, body: dict, db: Session = Depends(get_db)):
    if name not in _INTEGRATION_NAMES:
        raise HTTPException(status_code=404, detail="Unknown integration")
    row = db.query(Integration).filter(Integration.name == name).first()
    existing = dict(row.config or {}) if row else {}
    secret_keys = services_manager.INTEGRATION_SECRET_KEYS.get(name, set())
    merged = dict(existing)
    for k, v in (body or {}).items():
        if k == "configured":
            continue  # derived field, never stored
        if k in secret_keys and (v is None or v == ""):
            continue  # blank secret ⇒ keep existing
        merged[k] = v.strip() if isinstance(v, str) else v
    if row is None:
        row = Integration(name=name, config=merged)
        db.add(row)
    else:
        row.config = merged
    db.commit()
    return _serialize_integration(name, merged)


@api.post("/integrations/{name}/test")
async def test_integration(name: str, db: Session = Depends(get_db)):
    """Live connectivity test using the *stored* config (call after Save)."""
    if name not in _INTEGRATION_NAMES:
        raise HTTPException(status_code=404, detail="Unknown integration")
    cfg = services_manager.get_integration_config(db, name)
    if not services_manager.integration_configured(name, cfg):
        raise HTTPException(status_code=400, detail="Integration is not fully configured — save the settings first")
    try:
        if name == "npm":
            return await services_manager.npm_client(cfg).test()
        if name == "portainer":
            return await services_manager.portainer_client(cfg).test()
        hosts = (await services_manager.nc_client(cfg).get_hosts(cfg["domain"]))["hosts"]
        return {"ok": True, "detail": f"Connected — {len(hosts)} DNS record(s) on {cfg['domain']}"}
    except Exception as exc:
        # The detail reaches the UI's test-result box, but log it too so the
        # server log explains its own 502 lines.
        logger.warning("Integration test failed (%s): %s", name, exc)
        raise HTTPException(status_code=502, detail=str(exc))


def _serialize_service(s: Service) -> dict:
    fqdn = f"{s.subdomain}.{s.domain}"
    state = s.state
    # A row can sit at state='provisioning' after a crash mid-pipeline; report
    # it as error so the UI offers Retry instead of spinning forever.
    if state == "provisioning" and not services_manager.service_provisioning(s.id):
        state = "error"
    return {
        "id": s.id,
        "name": s.name,
        "subdomain": s.subdomain,
        "domain": s.domain,
        "fqdn": fqdn,
        "url": f"https://{fqdn}",
        "forward_scheme": s.forward_scheme,
        "forward_host": s.forward_host,
        "forward_port": s.forward_port,
        "websockets": bool(s.websockets),
        "block_exploits": bool(s.block_exploits),
        "caching_enabled": bool(s.caching_enabled),
        "ssl_forced": bool(s.ssl_forced),
        "http2_support": bool(s.http2_support),
        "hsts_enabled": bool(s.hsts_enabled),
        "hsts_subdomains": bool(s.hsts_subdomains),
        "portainer_container": s.portainer_container,
        "portainer_endpoint_id": s.portainer_endpoint_id,
        "state": state,
        "steps": {
            "dns":  {"status": s.dns_status,  "detail": s.dns_detail},
            "proxy": {"status": s.npm_status,  "detail": s.npm_detail},
            "ssl":  {"status": s.cert_status, "detail": s.cert_detail},
        },
        "npm_proxy_host_id": s.npm_proxy_host_id,
        "created_at": _iso_z(s.created_at) if s.created_at else None,
    }


@api.get("/services")
def list_services(db: Session = Depends(get_db)):
    rows = db.query(Service).order_by(Service.name, Service.id).all()
    return [_serialize_service(s) for s in rows]


def _validate_subdomain(value: str) -> str:
    sub = (value or "").strip().lower()
    if not _SUBDOMAIN_RE.match(sub):
        raise HTTPException(status_code=400,
                            detail="Subdomain must be lowercase letters/digits/hyphens (no leading/trailing hyphen)")
    return sub


def _validate_forward(scheme: str | None, host: str | None, port: int | None) -> None:
    if scheme is not None and scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Forward scheme must be http or https")
    if port is not None and not (1 <= port <= 65535):
        raise HTTPException(status_code=400, detail="Forward port must be 1-65535")
    if host is not None and (not host.strip() or any(c.isspace() for c in host.strip())):
        raise HTTPException(status_code=400, detail="Forward host is required")


@api.get("/services/containers")
async def list_service_containers(db: Session = Depends(get_db)):
    """Portainer containers with suggested forward targets — feeds the
    add/edit modal's container dropdown and the container-state dots on the
    service list."""
    try:
        return await services_manager.list_portainer_containers(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.warning("Portainer container listing failed: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))


@api.get("/services/npm-hosts")
async def list_npm_hosts(db: Session = Depends(get_db)):
    """Live list of NPM proxy hosts, for the Services page's sync view. The
    SPA matches them against managed services client-side (by stored proxy
    host id or fqdn) so hosts created outside the app show up as importable."""
    cfg = services_manager.get_integration_config(db, "npm")
    if not services_manager.integration_configured("npm", cfg):
        raise HTTPException(status_code=400, detail="NPM integration is not configured")
    try:
        hosts = await services_manager.npm_client(cfg).list_proxy_hosts()
    except Exception as exc:
        logger.warning("NPM host listing failed: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))
    return [
        {
            "id": h.get("id"),
            "domain_names": h.get("domain_names") or [],
            "forward_scheme": h.get("forward_scheme"),
            "forward_host": h.get("forward_host"),
            "forward_port": h.get("forward_port"),
            "certificate_id": h.get("certificate_id") or 0,
            "enabled": bool(h.get("enabled")),
            # Toggle values, so the import modal can prefill its checkboxes.
            "websockets": bool(h.get("allow_websocket_upgrade")),
            "block_exploits": bool(h.get("block_exploits")),
            "caching_enabled": bool(h.get("caching_enabled")),
            "ssl_forced": bool(h.get("ssl_forced")),
            "http2_support": bool(h.get("http2_support")),
            "hsts_enabled": bool(h.get("hsts_enabled")),
            "hsts_subdomains": bool(h.get("hsts_subdomains")),
        }
        for h in hosts
    ]


_IMPORT_OVERRIDE_KEYS = (
    "name", "forward_scheme", "forward_host", "forward_port",
    "websockets", "block_exploits", "caching_enabled", "ssl_forced",
    "http2_support", "hsts_enabled", "hsts_subdomains",
    "portainer_container", "portainer_endpoint_id",
)


@api.post("/services/npm-import", status_code=201)
async def import_npm_host(body: dict, db: Session = Depends(get_db)):
    """Take an existing NPM proxy host under management. Body:
    {"npm_proxy_host_id": <id>, ...user edits from the import modal}. The
    pipeline runs after import, so edits sync back to NPM and a missing
    certificate gets issued."""
    try:
        host_id = int(body.get("npm_proxy_host_id"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="npm_proxy_host_id is required")
    overrides = {k: v for k, v in (body or {}).items() if k in _IMPORT_OVERRIDE_KEYS}
    if "forward_scheme" in overrides:
        overrides["forward_scheme"] = str(overrides["forward_scheme"] or "").strip().lower()
    _validate_forward(overrides.get("forward_scheme"), overrides.get("forward_host"),
                      overrides.get("forward_port"))
    try:
        svc = await services_manager.import_npm_host(db, host_id, overrides)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.warning("NPM host import failed: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))
    asyncio.create_task(services_manager.provision_service(
        svc.id, on_update=manager.broadcast_json))
    return _serialize_service(svc)


@api.post("/services", status_code=201)
async def create_service(body: ServiceCreate, db: Session = Depends(get_db)):
    npm_cfg = services_manager.get_integration_config(db, "npm")
    nc_cfg = services_manager.get_integration_config(db, "namecheap")
    if not services_manager.integration_configured("npm", npm_cfg):
        raise HTTPException(status_code=400, detail="Configure the Nginx Proxy Manager integration first")
    if not services_manager.integration_configured("namecheap", nc_cfg):
        raise HTTPException(status_code=400, detail="Configure the Namecheap integration first")

    subdomain = _validate_subdomain(body.subdomain)
    scheme = body.forward_scheme.strip().lower()
    _validate_forward(scheme, body.forward_host, body.forward_port)

    domain = nc_cfg["domain"].strip().lower()
    if db.query(Service).filter(Service.subdomain == subdomain,
                                Service.domain == domain).first():
        raise HTTPException(status_code=409, detail=f"A service for {subdomain}.{domain} already exists")

    svc = Service(
        name=body.name.strip() or subdomain, subdomain=subdomain, domain=domain,
        forward_scheme=scheme, forward_host=body.forward_host.strip(),
        forward_port=body.forward_port, websockets=body.websockets,
        block_exploits=body.block_exploits, caching_enabled=body.caching_enabled,
        ssl_forced=body.ssl_forced, http2_support=body.http2_support,
        hsts_enabled=body.hsts_enabled, hsts_subdomains=body.hsts_subdomains,
        portainer_container=(body.portainer_container or "").strip() or None,
        portainer_endpoint_id=body.portainer_endpoint_id,
    )
    db.add(svc)
    db.commit()
    db.refresh(svc)
    asyncio.create_task(services_manager.provision_service(
        svc.id, on_update=manager.broadcast_json))
    return _serialize_service(svc)


@api.put("/services/{service_id}")
async def update_service(service_id: int, body: ServiceUpdate,
                         db: Session = Depends(get_db)):
    """Edit a service. Forward/toggle changes are pushed to NPM by the
    pipeline's settings-sync step. A subdomain change is a rename: the old
    DNS record (if we created it) and our old certificate are removed here,
    the NPM host's domain list is rewritten in place (preserving any extra
    domains on imported hosts), and DNS + cert re-provision for the new name.
    Remote-cleanup hiccups during a rename degrade to `warnings` on the
    response — the re-provision itself still proceeds."""
    svc = db.query(Service).filter(Service.id == service_id).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")
    if services_manager.service_provisioning(service_id):
        raise HTTPException(status_code=409, detail="Wait for provisioning to finish first")

    data = body.model_dump(exclude_unset=True)
    if "subdomain" in data:
        data["subdomain"] = _validate_subdomain(data["subdomain"])
    if "forward_scheme" in data:
        data["forward_scheme"] = (data["forward_scheme"] or "").strip().lower()
    _validate_forward(data.get("forward_scheme"), data.get("forward_host"),
                      data.get("forward_port"))
    if "forward_host" in data:
        data["forward_host"] = data["forward_host"].strip()
    if "name" in data:
        data["name"] = (data["name"] or "").strip() or svc.subdomain
    if "portainer_container" in data:
        data["portainer_container"] = (data["portainer_container"] or "").strip() or None

    warnings: list[str] = []
    new_sub = data.get("subdomain", svc.subdomain)
    if new_sub != svc.subdomain:
        if db.query(Service).filter(Service.subdomain == new_sub,
                                    Service.domain == svc.domain,
                                    Service.id != svc.id).first():
            raise HTTPException(status_code=409,
                                detail=f"A service for {new_sub}.{svc.domain} already exists")
        old_fqdn = f"{svc.subdomain}.{svc.domain}"
        new_fqdn = f"{new_sub}.{svc.domain}"

        # Rewrite the NPM host's domain list in place and detach our cert
        # (it's bound to the old name; LE certs can't be renamed).
        npm_cfg = services_manager.get_integration_config(db, "npm")
        if svc.npm_proxy_host_id is not None and \
                services_manager.integration_configured("npm", npm_cfg):
            npm = services_manager.npm_client(npm_cfg)
            try:
                current = await npm.get_proxy_host(svc.npm_proxy_host_id)
                domains = [new_fqdn if d == old_fqdn else d
                           for d in (current.get("domain_names") or [])]
                if new_fqdn not in domains:
                    domains.append(new_fqdn)
                overrides: dict = {"domain_names": domains}
                if svc.npm_certificate_id is not None:
                    overrides.update({"certificate_id": 0, "ssl_forced": False,
                                      "http2_support": False, "hsts_enabled": False,
                                      "hsts_subdomains": False})
                await npm.update_proxy_host(svc.npm_proxy_host_id, overrides)
                if svc.npm_certificate_id is not None:
                    try:
                        await npm.delete_certificate(svc.npm_certificate_id)
                    except Exception as exc:
                        warnings.append(f"Old certificate #{svc.npm_certificate_id}: {exc}")
                    svc.npm_certificate_id = None
            except Exception as exc:
                warnings.append(f"NPM rename: {exc}")

        # Remove the old DNS record — only the exact one we created.
        nc_cfg = services_manager.get_integration_config(db, "namecheap")
        if svc.dns_record_type and \
                services_manager.integration_configured("namecheap", nc_cfg):
            try:
                await services_manager.nc_client(nc_cfg).remove_record(
                    svc.domain, svc.subdomain, svc.dns_record_type, svc.dns_record_target)
            except Exception as exc:
                warnings.append(f"Old DNS record: {exc}")
        svc.dns_record_type = svc.dns_record_target = None
        svc.dns_status, svc.dns_detail = "pending", None
        svc.cert_status, svc.cert_detail = "pending", None

    for field, value in data.items():
        setattr(svc, field, value)
    svc.state = "pending"
    db.commit()
    asyncio.create_task(services_manager.provision_service(
        svc.id, on_update=manager.broadcast_json))
    out = _serialize_service(svc)
    out["warnings"] = warnings
    return out


@api.post("/services/{service_id}/provision")
async def reprovision_service(service_id: int, db: Session = Depends(get_db)):
    """Retry: re-runs the pipeline; steps already marked ok are skipped."""
    svc = db.query(Service).filter(Service.id == service_id).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")
    if services_manager.service_provisioning(service_id):
        raise HTTPException(status_code=409, detail="Provisioning is already running")
    # Failed steps re-run because provision_service skips only status == ok.
    asyncio.create_task(services_manager.provision_service(
        svc.id, on_update=manager.broadcast_json))
    return {"ok": True}


@api.delete("/services/{service_id}")
async def delete_service(service_id: int, force: bool = False,
                         db: Session = Depends(get_db)):
    """Deprovision (NPM proxy host + cert, then the exact DNS record we
    created) and delete the row. If remote cleanup fails the row is kept and
    a 502 explains what's left — `?force=true` deletes the row anyway,
    leaving the remote leftovers for manual cleanup."""
    svc = db.query(Service).filter(Service.id == service_id).first()
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")
    if services_manager.service_provisioning(service_id):
        raise HTTPException(status_code=409, detail="Wait for provisioning to finish first")
    errors = await services_manager.deprovision_service(svc, db)
    if errors and not force:
        raise HTTPException(status_code=502, detail="Cleanup incomplete: " + "; ".join(errors))
    db.delete(svc)
    db.commit()
    return {"ok": True, "cleanup_errors": errors}


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
