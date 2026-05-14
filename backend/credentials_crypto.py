"""
Symmetric encryption of per-device credentials at rest.

Keys come from CREDENTIAL_KEY env var if set, otherwise from a persisted
random key at <DB_PATH dir>/.credential_key. Same precedence model as
SESSION_SECRET — explicit config wins, persisted fallback keeps zero-config
homelab installs working out of the box.

Encrypted values are stored with an `enc:` prefix so the migration / decoder
can tell encrypted from legacy plaintext rows without guessing. Fernet
tokens already have their own structure (timestamp + HMAC) so the prefix is
just disambiguation for our own tooling — don't treat its absence as a
security signal.

Operational note: rotating the key invalidates every existing encrypted row.
There is no key-rotation pipeline; if you set CREDENTIAL_KEY for the first
time on an already-populated DB, all devices need their credentials re-
entered. Conversely, going from "no env var" to "explicit env var that
happens to equal the auto-generated key" works transparently.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_ENC_PREFIX = "enc:"
_KEY_FILE_NAME = ".credential_key"
_cached_fernet: Fernet | None = None


def _key_path() -> str:
    from .database import DB_PATH
    return os.path.join(os.path.dirname(DB_PATH) or ".", _KEY_FILE_NAME)


def get_credential_key() -> bytes:
    """Resolve the Fernet key. Cached at module level after first call so we
    don't re-read the file or re-generate on every encrypt/decrypt."""
    env = os.environ.get("CREDENTIAL_KEY")
    if env:
        return env.encode("ascii")
    path = _key_path()
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read().strip()
    # First-time generation. Writes are atomic-ish (rename) so a half-written
    # key file isn't possible even if the process dies mid-write.
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(key)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows / non-POSIX
    logger.warning(
        "Credential encryption key generated and persisted at %s. "
        "Set CREDENTIAL_KEY in the environment if you want to manage it "
        "externally — the persisted file is the auto-generated fallback.",
        path,
    )
    return key


def _fernet() -> Fernet:
    global _cached_fernet
    if _cached_fernet is None:
        _cached_fernet = Fernet(get_credential_key())
    return _cached_fernet


def encrypt_credentials(value: Any) -> str | None:
    """Serialize the dict (or any JSON-able value) and Fernet-encrypt.
    Returns the storage representation: `enc:<token>` where <token> is the
    base64url-encoded Fernet ciphertext. None passes through unchanged so
    null columns stay null."""
    if value is None:
        return None
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    token = _fernet().encrypt(payload)
    return _ENC_PREFIX + token.decode("ascii")


def decrypt_credentials(stored: str | None) -> Any:
    """Inverse of encrypt_credentials, with graceful legacy fallback. Rows
    written before encryption was added don't have the prefix and are
    parsed as plain JSON; the startup migration re-encrypts them so this
    branch is only hit on a freshly-upgraded DB."""
    if stored is None:
        return None
    if stored.startswith(_ENC_PREFIX):
        token = stored[len(_ENC_PREFIX):].encode("ascii")
        try:
            payload = _fernet().decrypt(token)
        except InvalidToken:
            # The key changed (operator rotated CREDENTIAL_KEY, or the .credential_key
            # file was lost and regenerated). Surface this loudly — the device
            # can't be polled until the credential is re-entered, but we don't
            # want to crash the whole adapter pipeline either.
            logger.error(
                "Failed to decrypt credentials — Fernet key mismatch. The device "
                "credential must be re-entered via the edit modal. (Did CREDENTIAL_KEY "
                "change, or was %s regenerated?)",
                _key_path(),
            )
            return {}
        return json.loads(payload.decode("utf-8"))
    # Legacy plaintext row — parse as JSON.
    try:
        return json.loads(stored)
    except json.JSONDecodeError:
        logger.error("Stored credentials are neither encrypted nor valid JSON")
        return {}


def is_encrypted(stored: str | None) -> bool:
    """True if the column value already carries the `enc:` prefix. The
    startup migration uses this to decide which rows to upgrade."""
    return stored is not None and stored.startswith(_ENC_PREFIX)
