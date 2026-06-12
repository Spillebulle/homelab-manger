"""
MAC vendor lookup, backed by the IEEE OUI registry.

Two CSV locations are consulted, in order:
  1. `<DB_PATH dir>/oui.csv` - runtime cache, refreshed periodically against
     IEEE. Lives in the persistent /data volume so it survives container
     restarts. Used when present.
  2. `backend/adapters/oui.csv` - bundled with the source; ensures the app
     works offline on first start before the cache has been populated.

`refresh_if_stale()` (called from FastAPI lifespan) downloads a fresh copy
when the cache is missing or older than `_STALE_AFTER`. It uses
If-Modified-Since so an unchanged registry returns 304 and we don't waste
bandwidth. Failures (offline, IEEE down, etc.) are logged but never block
startup - the bundled CSV is always good enough to keep the lookup working.

Update the bundled file by re-downloading from
https://standards-oui.ieee.org/oui/oui.csv. The CSV has rows for MA-L, MA-M,
and MA-S; we only consume MA-L (full 24-bit OUIs - what virtually every
consumer/enterprise NIC uses).
"""
from __future__ import annotations

import csv
import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from email.utils import format_datetime, parsedate_to_datetime

import httpx

logger = logging.getLogger(__name__)

# Friendly-name overrides for cases where the IEEE registration string is
# clunky in a UI ("Hewlett Packard Enterprise" → "HPE", "Cisco Systems, Inc"
# → "Cisco"). Keys are 6-char uppercase hex (no separators); leave a vendor
# out of this map to use the raw IEEE name.
_FRIENDLY_OVERRIDES: dict[str, str] = {}

_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
_BUNDLED_FILE = os.path.join(os.path.dirname(__file__), "oui.csv")
_STALE_AFTER = 30 * 24 * 3600  # 30 days
_HTTP_TIMEOUT = 30.0

_OUI_VENDORS: dict[str, str] = {}


def _cache_path() -> str:
    """Where the runtime-refreshed copy lives. Derived from DB_PATH so it
    sits next to the SQLite DB (same persistent volume in Docker)."""
    db_path = os.environ.get("DB_PATH", "/data/homelab.db")
    return os.path.join(os.path.dirname(db_path) or ".", "oui.csv")


def _active_file() -> str:
    """Prefer the runtime cache when present and non-empty; otherwise the
    bundled fallback shipped with the source."""
    cache = _cache_path()
    if os.path.exists(cache) and os.path.getsize(cache) > 1024:
        return cache
    return _BUNDLED_FILE


def _parse(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # header
        for row in reader:
            if len(row) < 3 or row[0] != "MA-L":
                continue
            prefix = row[1].strip().upper()
            org = row[2].strip()
            if prefix and org:
                out[prefix] = org
    return out


def _load() -> None:
    """Populate `_OUI_VENDORS` from the active file. Safe to call multiple
    times - clears and rebuilds atomically."""
    path = _active_file()
    if not os.path.exists(path):
        logger.warning("OUI database missing at %s - vendor lookup disabled", path)
        return
    try:
        new = _parse(path)
        _OUI_VENDORS.clear()
        _OUI_VENDORS.update(new)
        logger.info("OUI database loaded from %s (%d entries)", path, len(_OUI_VENDORS))
    except Exception:
        logger.exception("Failed to parse %s - keeping previous lookup table", path)


def _normalise(mac: str) -> str:
    return mac.upper().replace(":", "").replace("-", "").replace(".", "")


def lookup(mac: str) -> str | None:
    """Return a vendor name for the given MAC, or None if unknown."""
    if not mac:
        return None
    if not _OUI_VENDORS:
        _load()
    n = _normalise(mac)
    if len(n) < 6:
        return None
    prefix = n[:6]
    if prefix in _FRIENDLY_OVERRIDES:
        return _FRIENDLY_OVERRIDES[prefix]
    return _OUI_VENDORS.get(prefix)


async def refresh_if_stale() -> None:
    """Download a fresh OUI registry into the runtime cache if the cache is
    missing or older than _STALE_AFTER. Uses If-Modified-Since so unchanged
    registries return 304 and we don't burn bandwidth. Never raises - any
    failure falls through to the bundled CSV."""
    cache = _cache_path()
    cache_dir = os.path.dirname(cache) or "."
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except OSError as exc:
        logger.warning("Cannot create OUI cache dir %s: %s", cache_dir, exc)
        return

    headers = {"User-Agent": "homelab-manger/oui-refresh"}
    cache_mtime: float | None = None
    if os.path.exists(cache):
        cache_mtime = os.path.getmtime(cache)
        age = datetime.now(timezone.utc).timestamp() - cache_mtime
        if age < _STALE_AFTER:
            logger.debug("OUI cache is fresh (%.0f hours old) - skipping refresh", age / 3600)
            return
        # Stale: ask IEEE only for the bytes if newer than what we have.
        headers["If-Modified-Since"] = format_datetime(
            datetime.fromtimestamp(cache_mtime, tz=timezone.utc), usegmt=True
        )

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
            r = await client.get(_OUI_URL, headers=headers)
    except Exception as exc:
        logger.warning("OUI refresh skipped - %s", exc)
        return

    if r.status_code == 304:
        # Server says we're current - bump mtime so we don't recheck for
        # another _STALE_AFTER seconds.
        if cache_mtime is not None:
            try:
                os.utime(cache, None)
            except OSError:
                pass
        logger.info("OUI registry unchanged (HTTP 304)")
        return

    if r.status_code != 200 or len(r.content) < 100_000:
        logger.warning(
            "OUI refresh got HTTP %s with %d bytes - keeping existing copy",
            r.status_code, len(r.content),
        )
        return

    # Atomic write: tmp file in the same dir, fsync, rename. Avoids leaving a
    # half-written CSV if the process dies mid-download.
    fd, tmp_path = tempfile.mkstemp(prefix="oui.", suffix=".csv.tmp", dir=cache_dir)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(r.content)
            f.flush()
            os.fsync(f.fileno())
        shutil.move(tmp_path, cache)
    except Exception:
        logger.exception("Failed to write OUI cache to %s", cache)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return

    last_mod = r.headers.get("Last-Modified")
    if last_mod:
        try:
            ts = parsedate_to_datetime(last_mod).timestamp()
            os.utime(cache, (ts, ts))
        except Exception:
            pass

    logger.info("OUI registry refreshed (%d bytes from %s)", len(r.content), _OUI_URL)
    _load()


# Eager-load at import so the first device poll doesn't pay the parse cost.
_load()
