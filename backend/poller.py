import asyncio
import json
import logging
from datetime import datetime

from .database import SessionLocal
from .models import Device, DeviceCache
from .adapters import get_adapter

logger = logging.getLogger(__name__)
POLL_INTERVAL = int(60)  # seconds between full polls


def _upsert_cache(db, device_id: int, key: str, data: str | None, error: str | None):
    row = (
        db.query(DeviceCache)
        .filter(DeviceCache.device_id == device_id, DeviceCache.cache_key == key)
        .first()
    )
    now = datetime.utcnow()
    if row:
        if data is not None:
            row.data = data
            row.error = None
        else:
            row.error = error
        row.updated_at = now
    else:
        row = DeviceCache(
            device_id=device_id,
            cache_key=key,
            data=data,
            error=error,
            updated_at=now,
        )
        db.add(row)


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