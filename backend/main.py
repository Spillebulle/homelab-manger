import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .database import get_db, init_db
from .models import Device, DeviceCache, AuthUser
from .schemas import DeviceCreate, DeviceUpdate, LoginRequest, ChangePasswordRequest
from . import poller
from .adapters import get_adapter
from .auth import (
    SESSION_USER_KEY,
    authenticate,
    bootstrap_admin,
    current_user,
    get_session_secret,
    hash_password,
    verify_password,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Connection Manager for WebSockets ────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# ── Lifecycle (Database & Poller) ────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    bootstrap_admin()
    task = asyncio.create_task(poller.poll_loop(on_update=manager.broadcast_json))
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

app = FastAPI(title="HomeLab Manager", lifespan=lifespan)
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
            "status": status_data,
            "status_error": status_row.error if status_row else None,
            "last_seen": status_row.updated_at.isoformat() if status_row and status_row.updated_at else None,
        })
    return result


@api.post("/devices", status_code=201)
def create_device(body: DeviceCreate, db: Session = Depends(get_db)):
    dev = Device(
        name=body.name, hostname=body.hostname, device_type=body.device_type,
        adapter_type=body.adapter_type, credentials=json.dumps(body.credentials),
        enabled=body.enabled, notes=body.notes,
    )
    db.add(dev)
    db.commit()
    db.refresh(dev)
    return {"id": dev.id}


@api.put("/devices/{device_id}")
def update_device(device_id: int, body: DeviceUpdate, db: Session = Depends(get_db)):
    d = _device_or_404(device_id, db)
    for field, value in body.model_dump(exclude_unset=True).items():
        if field == "credentials":
            setattr(d, field, json.dumps(value))
        else:
            setattr(d, field, value)
    db.commit()
    return {"id": d.id}


@api.delete("/devices/{device_id}")
def delete_device(device_id: int, db: Session = Depends(get_db)):
    d = _device_or_404(device_id, db)
    db.query(DeviceCache).filter(DeviceCache.device_id == device_id).delete()
    db.delete(d)
    db.commit()
    return {"ok": True}


@api.post("/devices/{device_id}/refresh")
async def refresh_device(device_id: int, db: Session = Depends(get_db)):
    await poller.poll_device(device_id, on_update=manager.broadcast_json)
    return {"ok": True}


@api.get("/devices/{device_id}/cache")
def get_cache(device_id: int, db: Session = Depends(get_db)):
    return _cache_map(device_id, db)


@api.post("/devices/{device_id}/action")
async def device_action(device_id: int, action: dict, db: Session = Depends(get_db)):
    d = _device_or_404(device_id, db)
    creds = json.loads(d.credentials) if d.credentials else {}
    adapter = get_adapter(d.adapter_type, d.hostname, creds)
    return await adapter.execute_action(action)


@api.post("/devices/{device_id}/port/{port_id}/action")
async def port_action(device_id: int, port_id: str, action: dict, db: Session = Depends(get_db)):
    d = _device_or_404(device_id, db)
    creds = json.loads(d.credentials) if d.credentials else {}
    adapter = get_adapter(d.adapter_type, d.hostname, creds)
    action["port_id"] = port_id
    return await adapter.execute_action(action)


@api.get("/devices/{device_id}/kvm.jnlp")
async def download_kvm_jnlp(device_id: int, db: Session = Depends(get_db)):
    """
    KVM JNLP launcher for server adapters that use Java Web Start (CIMC, iBMC).
    CRITICAL: We do NOT call adapter.close() here for CIMC, as tokens are tied
    to the active XMLAPI session.
    """
    d = _device_or_404(device_id, db)
    if d.adapter_type not in ["cimc", "ibmc"]:
        raise HTTPException(status_code=400, detail=f"KVM JNLP not supported for {d.adapter_type}")

    creds = json.loads(d.credentials) if d.credentials else {}
    adapter = get_adapter(d.adapter_type, d.hostname, creds)

    result = await adapter.execute_action({"type": "kvm_launch"})

    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])

    filename = f"{d.adapter_type}-{d.name}.jnlp"
    return Response(
        content=result["jnlp"],
        media_type="application/x-java-jnlp-file",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache"
        }
    )


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
