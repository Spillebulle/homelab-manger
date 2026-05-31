import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta

from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .database import SessionLocal
from .models import Device, DeviceCache, DeviceMetric, ShutdownRule
from .adapters import get_adapter

logger = logging.getLogger(__name__)

# Default seconds between polls when a device doesn't set its own
# `poll_interval`. Overridable per-process via the POLL_INTERVAL env var.
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "60"))
# Floor for a per-device override — stops a typo (e.g. 1) from hammering a
# device or busy-looping the scheduler.
MIN_POLL_INTERVAL = 5
# How often the scheduler wakes to check which devices are due. Polls fire as
# independent tasks, so this is just the scheduling granularity, not a cap on
# how long a single poll may take.
_BASE_TICK = 5


def _device_interval(device) -> float:
    """Effective poll interval (seconds) for a device: its `poll_interval` if
    set and sane, else the default. Clamped to MIN_POLL_INTERVAL."""
    iv = device.poll_interval
    if iv is None or iv <= 0:
        return float(POLL_INTERVAL)
    return float(max(int(iv), MIN_POLL_INTERVAL))

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
        # On error, PRESERVE the last good `data` and its `updated_at` — only
        # refresh `error`. This lets the UI keep showing the last-known reading
        # under an "offline / last status" treatment instead of going blank,
        # and makes `updated_at` mean "last successful poll" (which is what the
        # dashboard's last_seen / "Updated …" wants — previously it bumped on
        # every failed attempt, so an offline device falsely read "just now").
        # First-ever poll with no prior row inserts a data-less error row.
        stmt = sqlite_insert(DeviceCache).values(
            device_id=device_id, cache_key=key, data=None, error=error, updated_at=now,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["device_id", "cache_key"],
            set_={"error": error},
        )
    db.execute(stmt)


def _on_battery(status_data: dict) -> bool:
    """True when the UPS is running on its battery. Uses the adapter's derived
    state plus the ACPresent flag as a backstop."""
    state = status_data.get("state")
    flags = status_data.get("flags") or {}
    return state in ("on_battery", "low_battery") or flags.get("ac_present") is False


def _rule_threshold_met(rule, charge_pct, runtime_sec) -> bool:
    """OR-combine the configured thresholds. No thresholds set ⇒ fire as soon as
    on battery."""
    if rule.trigger_charge_pct is None and rule.trigger_runtime_sec is None:
        return True
    if (rule.trigger_charge_pct is not None and charge_pct is not None
            and charge_pct <= rule.trigger_charge_pct):
        return True
    if (rule.trigger_runtime_sec is not None and runtime_sec is not None
            and runtime_sec <= rule.trigger_runtime_sec):
        return True
    return False


async def _execute_shutdown_rule(db, rule) -> None:
    """Run a rule's action on its target device via that device's adapter."""
    target = db.query(Device).filter(Device.id == rule.target_device_id).first()
    if not target:
        logger.error("shutdown rule %d: target device %d no longer exists",
                     rule.id, rule.target_device_id)
        return
    logger.warning("OUTAGE ACTION: firing rule %d — %s on %r (%s)",
                   rule.id, rule.action, target.name, target.adapter_type)
    adapter = get_adapter(target.adapter_type, target.hostname, target.credentials or {})
    try:
        result = await adapter.execute_action({"type": rule.action})
        if isinstance(result, dict) and result.get("error"):
            logger.error("OUTAGE ACTION FAILED: rule %d %s on %r → %s",
                         rule.id, rule.action, target.name, result["error"])
        else:
            logger.warning("OUTAGE ACTION OK: rule %d %s on %r",
                           rule.id, rule.action, target.name)
    except Exception as exc:
        logger.error("OUTAGE ACTION ERROR: rule %d %s on %r → %s: %s",
                     rule.id, rule.action, target.name, type(exc).__name__, exc)
    finally:
        try:
            await adapter.close()
        except Exception:
            pass


async def _evaluate_shutdown_rules(db, ups_device, status_data: dict) -> None:
    """Evaluate (and fire) the shutdown rules owned by a UPS after each poll.

    On mains power: re-arm any rules that previously fired (so the next outage
    can trigger them again). On battery: fire each armed rule whose threshold is
    crossed exactly once — `last_triggered_at` is the persistent guard, so an
    app restart mid-outage won't re-shut-down an already-downed machine."""
    rules = (db.query(ShutdownRule)
             .filter(ShutdownRule.ups_device_id == ups_device.id,
                     ShutdownRule.enabled.is_(True))
             .order_by(ShutdownRule.id).all())
    if not rules:
        return

    if not _on_battery(status_data):
        rearmed = [r for r in rules if r.last_triggered_at is not None]
        if rearmed:
            for r in rearmed:
                r.last_triggered_at = None
            db.commit()
            logger.warning("UPS %r back on mains — re-armed %d shutdown rule(s)",
                           ups_device.name, len(rearmed))
        return

    charge_pct = status_data.get("charge_pct")
    runtime_sec = status_data.get("runtime_sec")
    for rule in rules:
        if rule.last_triggered_at is not None:
            continue  # already fired this outage
        if not _rule_threshold_met(rule, charge_pct, runtime_sec):
            continue
        await _execute_shutdown_rule(db, rule)
        rule.last_triggered_at = datetime.utcnow()
        db.commit()


async def poll_device(device_id: int, on_update=None):
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device or not device.enabled:
            return

        # device.credentials is a dict (or None) via the EncryptedJSON column.
        credentials = device.credentials or {}
        adapter = get_adapter(device.adapter_type, device.hostname, credentials)

        # Capture a fresh, successful status read so the shutdown-rule
        # evaluation below acts only on real data — never on a preserved/stale
        # reading from a failed poll (status_data stays None on a status error).
        status_data = None

        try:
            for key in adapter.get_supported_cache_keys():
                try:
                    data = await adapter.fetch(key)
                    _upsert_cache(db, device_id, key, json.dumps(data), None)
                    if key == "status":
                        status_data = data
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

        # Outage orchestration: after a UPS poll, evaluate its shutdown rules
        # against the fresh status. Only for UPS-type devices, and only with a
        # real status read (never a preserved/stale one).
        if device.device_type == "ups" and status_data is not None:
            try:
                await _evaluate_shutdown_rules(db, device, status_data)
            except Exception as exc:
                logger.error("shutdown-rule evaluation for %s failed: %s", device.name, exc)

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
    """Per-device scheduler. Wakes every _BASE_TICK, and for each enabled
    device whose `poll_interval` has elapsed since its last poll, fires
    `poll_device` as an independent task. Firing tasks (rather than awaiting a
    single gather of everyone) means a slow device — a CIMC poll can run 20-30s
    — doesn't delay a fast UPS set to a short interval, and each device is
    re-polled on its own cadence. A device already mid-poll is skipped until it
    finishes (no overlap), so an interval shorter than a device's actual poll
    time just polls it back-to-back."""
    last_polled: dict[int, float] = {}   # device_id → monotonic time of last fire
    in_flight: set[int] = set()          # devices whose poll task hasn't finished
    tasks: set = set()                   # keep task refs alive until done

    async def _run(device_id):
        try:
            await poll_device(device_id, on_update)
        except Exception as exc:
            logger.error("poll_device %d raised: %s: %s",
                         device_id, type(exc).__name__, exc)
        finally:
            in_flight.discard(device_id)

    while True:
        db = SessionLocal()
        try:
            devices = [(d.id, _device_interval(d))
                       for d in db.query(Device).filter(Device.enabled.is_(True)).all()]
        except Exception as exc:
            logger.error("poll_loop device query failed: %s", exc)
            devices = []
        finally:
            db.close()

        now = time.monotonic()
        # Drop bookkeeping for devices that are gone/disabled so the dicts
        # don't grow unbounded as devices come and go.
        live = {dev_id for dev_id, _ in devices}
        for stale in [k for k in last_polled if k not in live]:
            last_polled.pop(stale, None)

        for device_id, interval in devices:
            if device_id in in_flight:
                continue   # still polling from a previous tick — don't overlap
            if now - last_polled.get(device_id, float("-inf")) >= interval:
                last_polled[device_id] = now
                in_flight.add(device_id)
                t = asyncio.create_task(_run(device_id))
                tasks.add(t)
                t.add_done_callback(tasks.discard)

        await asyncio.sleep(_BASE_TICK)