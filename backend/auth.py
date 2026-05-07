import logging
import os
import secrets

import bcrypt
from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import AuthUser

logger = logging.getLogger(__name__)

DEFAULT_USERNAME = "admin"
SESSION_USER_KEY = "user"

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
    """If no auth user exists, create one from ADMIN_PASSWORD (or 'changeme')."""
    db: Session = SessionLocal()
    try:
        if db.query(AuthUser).count() > 0:
            return
        initial = os.environ.get("ADMIN_PASSWORD") or "changeme"
        username = os.environ.get("ADMIN_USERNAME") or DEFAULT_USERNAME
        user = AuthUser(username=username, password_hash=hash_password(initial))
        db.add(user)
        db.commit()
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


def current_user(request: Request) -> str:
    """Dependency: returns the username from session, or 401."""
    user = request.session.get(SESSION_USER_KEY)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user


def authenticate(db: Session, username: str, password: str) -> AuthUser | None:
    user = db.query(AuthUser).filter(AuthUser.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user
