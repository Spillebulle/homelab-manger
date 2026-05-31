import hashlib
import logging
import os
import secrets
from datetime import datetime

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .database import SessionLocal, get_db
from .models import ApiKey, AuthUser

logger = logging.getLogger(__name__)

DEFAULT_USERNAME = "admin"
SESSION_USER_KEY = "user"

# Bearer API keys: `hlm_` + 32 random url-safe bytes. Only the SHA-256 hash is
# persisted; the plaintext is returned once at creation.
API_KEY_PREFIX = "hlm_"


def hash_api_key(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Return (plaintext, display_prefix, sha256_hash) for a fresh key."""
    token = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return token, token[:12], hash_api_key(token)


def _api_key_from_request(request: Request) -> str | None:
    """Pull a bearer token from `Authorization: Bearer <key>` or `X-API-Key`."""
    auth = request.headers.get("Authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip() or None
    xkey = request.headers.get("X-API-Key")
    return xkey.strip() if xkey else None

# bcrypt has a hard 72-byte input limit. Truncate at the byte level (not chars)
# so multi-byte UTF-8 passwords don't get split mid-codepoint.
_BCRYPT_MAX_BYTES = 72


def _encode(plain: str) -> bytes:
    b = plain.encode("utf-8")
    return b[:_BCRYPT_MAX_BYTES]


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(_encode(plain), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_encode(plain), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def get_session_secret() -> str:
    """Read SESSION_SECRET from env, falling back to a persisted random value
    so cookies survive a process restart even without explicit config."""
    secret = os.environ.get("SESSION_SECRET")
    if secret:
        return secret
    # Fallback: cache a random secret on disk next to the DB so restarts don't
    # log everyone out. This is fine for a single-host homelab; in any real
    # deployment you'd set SESSION_SECRET explicitly.
    from .database import DB_PATH
    secret_path = os.path.join(os.path.dirname(DB_PATH) or ".", ".session_secret")
    if os.path.exists(secret_path):
        with open(secret_path) as f:
            return f.read().strip()
    secret = secrets.token_urlsafe(48)
    os.makedirs(os.path.dirname(secret_path) or ".", exist_ok=True)
    with open(secret_path, "w") as f:
        f.write(secret)
    try:
        os.chmod(secret_path, 0o600)
    except OSError:
        pass  # Windows / non-POSIX
    return secret


def bootstrap_admin() -> None:
    """If no auth user exists, create one from ADMIN_PASSWORD (or 'changeme').

    A commit failure here would otherwise crash FastAPI's lifespan with an
    opaque traceback and no auth_users row — the operator then can't even log
    in to investigate. Roll back, log loud, and let the app start anyway so
    `/api/auth/login` can return a clean 401 instead of a 500."""
    db: Session = SessionLocal()
    try:
        if db.query(AuthUser).count() > 0:
            return
        initial = os.environ.get("ADMIN_PASSWORD") or "changeme"
        username = os.environ.get("ADMIN_USERNAME") or DEFAULT_USERNAME
        user = AuthUser(username=username, password_hash=hash_password(initial))
        try:
            db.add(user)
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.error(
                "Auth bootstrap FAILED — cannot create admin user %r: %s: %s. "
                "Login will be impossible until the DB is repaired or "
                "auth_users is seeded manually.",
                username, type(exc).__name__, exc,
            )
            return
        if initial == "changeme":
            logger.warning(
                "Auth bootstrap: created default user %r with password 'changeme'. "
                "Log in and change it immediately, or set ADMIN_PASSWORD before first start.",
                username,
            )
        else:
            logger.info("Auth bootstrap: created user %r from ADMIN_PASSWORD env.", username)
    finally:
        db.close()


def current_user(request: Request, db: Session = Depends(get_db)) -> str:
    """Dependency: authenticate via cookie session OR a bearer API key.

    Session wins (cheap, no DB hit). Otherwise an `Authorization: Bearer` /
    `X-API-Key` header is matched against the api_keys table by hash; on a hit
    we stamp last_used_at and return the single admin user's name. 401 if
    neither path authenticates."""
    user = request.session.get(SESSION_USER_KEY)
    if user:
        return user

    token = _api_key_from_request(request)
    if token:
        key = db.query(ApiKey).filter(ApiKey.key_hash == hash_api_key(token)).first()
        if key:
            key.last_used_at = datetime.utcnow()
            try:
                db.commit()
            except Exception:
                db.rollback()  # last_used_at is best-effort; don't fail auth on it
            row = db.query(AuthUser).first()
            return row.username if row else "apikey"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )


def authenticate(db: Session, username: str, password: str) -> AuthUser | None:
    user = db.query(AuthUser).filter(AuthUser.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user
