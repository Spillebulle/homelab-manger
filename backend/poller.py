import asyncio
import json
import logging
from datetime import datetime

from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .database import SessionLocal
from .models import Device, DeviceCache
from .adapters import get_adapter

logger = logging.getLogger(__name__)
POLL_INTERVAL = int(60)  # seconds between full polls


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

        credentials = json.loads(device.credentials) if device.credentials else {}
        adapter = get_adapter(device.adapter_type, device.hostname, credentials)

        try:
            for key in adapter.get_supported_cache_keys():
                try:
                    data = await adapter.fetch(key)
                    _upsert_cache(db, device_id, key, json.dumps(data), None)
                except Exception as exc:
                    logger.warning("poll %s/%s failed: %s", device.name, key, exc)
                    _upsert_cache(db, device_id, key, None, str(exc))
        finally:
            try:
                await adapter.close()
            except Exception:
                pass

        db.commit()
        
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
            # Pass the callback to each individual device poll
            await asyncio.gather(*[poll_device(i, on_update) for i in ids], return_exceptions=True)

        await asyncio.sleep(POLL_INTERVAL)