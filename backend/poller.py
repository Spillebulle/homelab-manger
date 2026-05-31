import asyncio
import json
import logging
import os
from datetime import datetime, timedelta

from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .database import SessionLocal
from .models import Device, DeviceCache, DeviceMetric
from .adapters import get_adapter

logger = logging.getLogger(__name__)
POLL_INTERVAL = int(60)  # seconds between full polls

# How long to keep time-series samples (device_metrics). Pruned per device on
# every poll — an indexed DELETE, cheap at homelab scale. 0/negative disables
# pruning (unbounded history).
METRICS_RETENTION_DAYS = int(os.environ.get("METRICS_RETENTION_DAYS", "30"))

# Cache key whose numeric members are persisted to the time-series table. Any
# adapter that exposes a `metrics` key (currently usbups; PDUs/servers later)
# automatically gets graphed history with no extra poller code.
_METRICS_CACHE_KEY = "metrics"


def _record_metrics(db, device_id: int, data, ts: datetime) -> None:
    """Append the numeric members of a `metrics` payload to device_metrics, then
    prune anything older than the retention window. Silent no-op if the payload
    isn't a flat dict of numbers."""
    if not isinstance(data, dict):
        return
    rows = [
        {"device_id": device_id, "metric": k, "value": float(v), "ts": ts}
        for k, v in data.items()
        if isinstance(v, (int, float)) and not isinstance(v, bool)
    ]
    if rows:
        db.execute(sqlite_insert(DeviceMetric), rows)
    if METRICS_RETENTION_DAYS > 0:
        cutoff = ts - timedelta(days=METRICS_RETENTION_DAYS)
        db.query(DeviceMetric).filter(
            DeviceMetric.device_id == device_id,
            DeviceMetric.ts < cutoff,
        ).delete(synchronize_session=False)


def _upsert_cache(db, device_id: int, key: str, data: str | None, error: str | None):
    # SQLite's INSERT ... ON CONFLICT(...) DO UPDATE is atomic — pre-v0.4.2 we
    # did SELECT-then-INSERT, which let two concurrent polls both miss the
    # SELECT and both INSERT, leaving duplicate rows that confuse the cache
    # reader. The unique index on (device_id, cache_key) is what makes this
    # atomic; without it the ON CONFLICT clause has nothing to match against.
    now = datetime.utcnow()
    if data is not None:
        stmt = sqlite_insert(DeviceCache).values(
            device_id=device_id, cache_key=key, data=data, error=None, updated_at=now,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["device_id", "cache_key"],
            set_={"data": data, "error": None, "updated_at": now},
        )
    else:
        stmt = sqlite_insert(DeviceCache).values(
            device_id=device_id, cache_key=key, data=None, error=error, updated_at=now,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["device_id", "cache_key"],
            set_={"error": error, "updated_at": now},
        )
    db.execute(stmt)


async def poll_device(device_id: int, on_update=None):
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device or not device.enabled:
            return

        # device.credentials is a dict (or None) via the EncryptedJSON column.
        credentials = device.credentials or {}
        adapter = get_adapter(device.adapter_type, device.hostname, credentials)

        try:
            for key in adapter.get_supported_cache_keys():
                try:
                    data = await adapter.fetch(key)
                    _upsert_cache(db, device_id, key, json.dumps(data), None)
                    # The `metrics` key doubles as the time-series source —
                    # persist its numeric members for graphing.
                    if key == _METRICS_CACHE_KEY:
                        _record_metrics(db, device_id, data, datetime.utcnow())
                except Exception as exc:
                    logger.warning("poll %s/%s failed: %s", device.name, key, exc)
                    _upsert_cache(db, device_id, key, None, str(exc))
                # Commit after each key so the write lock isn't held across
                # the next adapter.fetch (which can run 20-30s on CIMC). Pre-
                # v0.4.3 we committed once at the bottom, which under SQLite
                # cascaded "database is locked" errors across parallel polls.
                try:
                    db.commit()
                except Exception as commit_exc:
                    logger.warning("poll %s/%s commit failed: %s", device.name, key, commit_exc)
                    db.rollback()
        finally:
            try:
                await adapter.close()
            except Exception:
                pass
        
        # Fire the websocket broadcast!
        if on_update:
            try:
                await on_update({"event": "device_updated", "device_id": device_id})
            except Exception as e:
                logger.error("Failed to broadcast update: %s", e)

    except Exception as exc:
        logger.error("poll_device %d failed: %s", device_id, exc)
    finally:
        db.close()

async def poll_loop(on_update=None):
    while True:
        db = SessionLocal()
        try:
            ids = [d.id for d in db.query(Device).filter(Device.enabled.is_(True)).all()]
        finally:
            db.close()

        if ids:
            # Pass the callback to each individual device poll. `poll_device`
            # has its own try/except so the only exceptions that surface here
            # are catastrophic ones (cancellation, OOM, programmer error in
            # poll_device itself). Don't let those vanish silently — log them
            # tagged with the device_id so the next poll cycle still runs.
            results = await asyncio.gather(
                *[poll_device(i, on_update) for i in ids], return_exceptions=True,
            )
            for device_id, exc in zip(ids, results):
                if isinstance(exc, Exception):
                    logger.error("poll_device %d raised through gather: %s: %s",
                                 device_id, type(exc).__name__, exc)

        await asyncio.sleep(POLL_INTERVAL)