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
from .events import (
    emit_event, EV_UPS_ON_BATTERY, EV_UPS_LOW, EV_UPS_ONLINE,
    EV_DEVICE_OFFLINE, EV_DEVICE_ONLINE, EV_ACTION,
)

logger = logging.getLogger(__name__)

# State-transition tracking for event generation (in-memory, per device).
# `_dev_offline`/`_dev_fail_count` debounce offline notifications so a single
# transient poll failure (common on the flaky USB UPS) doesn't spam events.
_OFFLINE_THRESHOLD = 3          # consecutive failed status polls ⇒ "offline"
_dev_offline: dict[int, bool] = {}
_dev_fail_count: dict[int, int] = {}
_ups_prev_state: dict[int, str] = {}   # device_id → last seen UPS state

# Default seconds between polls when a device doesn't set its own
# `poll_interval`. Overridable per-process via the POLL_INTERVAL env var.
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "60"))
# Floor for a per-device override - stops a typo (e.g. 1) from hammering a
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
# every poll - an indexed DELETE, cheap at homelab scale. 0/negative disables
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
    # SQLite's INSERT ... ON CONFLICT(...) DO UPDATE is atomic - pre-v0.4.2 we
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
        # On error, PRESERVE the last good `data` and its `updated_at` - only
        # refresh `error`. This lets the UI keep showing the last-known reading
        # under an "offline / last status" treatment instead of going blank,
        # and makes `updated_at` mean "last successful poll" (which is what the
        # dashboard's last_seen / "Updated …" wants - previously it bumped on
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


_ACTION_LABEL = {
    "graceful_shutdown": "Graceful shutdown", "power_off": "Force power off",
    "power_cycle": "Power cycle", "hard_reset": "Hard reset",
}


async def _execute_shutdown_rule(db, rule, ups_device, dry_run: bool = False) -> None:
    """Run a rule's action on its target device via that device's adapter, and
    record an event (attributed to the UPS so it shows in the UPS log and uses
    the UPS's notification config).

    `dry_run=True` performs no real action and stamps nothing - it just logs and
    emits a `[Dry run]` event (which still flows through the notification config,
    so the user can validate their Discord wiring without powering anything off)."""
    label = _ACTION_LABEL.get(rule.action, rule.action)
    target = db.query(Device).filter(Device.id == rule.target_device_id).first()
    if not target:
        logger.error("shutdown rule %d: target device %d no longer exists",
                     rule.id, rule.target_device_id)
        return
    if dry_run:
        logger.warning("OUTAGE ACTION (DRY RUN): would fire rule %d - %s on %r (%s)",
                       rule.id, rule.action, target.name, target.adapter_type)
        await emit_event(db, ups_device, EV_ACTION,
                         f"[Dry run] {label} → {target.name}",
                         detail="Test only - no action sent to the device.",
                         severity="info")
        return
    logger.warning("OUTAGE ACTION: firing rule %d - %s on %r (%s)",
                   rule.id, rule.action, target.name, target.adapter_type)
    ok, note = False, ""
    adapter = get_adapter(target.adapter_type, target.hostname, target.credentials or {})
    try:
        result = await adapter.execute_action({"type": rule.action})
        if isinstance(result, dict) and result.get("error"):
            note = str(result["error"])
            logger.error("OUTAGE ACTION FAILED: rule %d %s on %r → %s",
                         rule.id, rule.action, target.name, note)
        else:
            ok = True
            logger.warning("OUTAGE ACTION OK: rule %d %s on %r",
                           rule.id, rule.action, target.name)
    except Exception as exc:
        note = f"{type(exc).__name__}: {exc}"
        logger.error("OUTAGE ACTION ERROR: rule %d %s on %r → %s",
                     rule.id, rule.action, target.name, note)
    finally:
        try:
            await adapter.close()
        except Exception:
            pass
    title = (f"{label} → {target.name}" if ok
             else f"{label} → {target.name} FAILED")
    await emit_event(db, ups_device, EV_ACTION, title,
                     detail=(note or "action sent"),
                     severity=("warning" if ok else "critical"))


async def _evaluate_shutdown_rules(db, ups_device, status_data: dict) -> None:
    """Evaluate (and fire) the shutdown rules owned by a UPS after each poll.

    On mains power: re-arm any rules that previously fired (so the next outage
    can trigger them again). On battery: fire each armed rule whose threshold is
    crossed exactly once - `last_triggered_at` is the persistent guard, so an
    app restart mid-outage won't re-shut-down an already-downed machine."""
    rules = (db.query(ShutdownRule)
             .filter(ShutdownRule.ups_device_id == ups_device.id,
                     ShutdownRule.enabled.is_(True))
             .order_by(ShutdownRule.priority, ShutdownRule.id).all())
    if not rules:
        return

    if not _on_battery(status_data):
        rearmed = [r for r in rules if r.last_triggered_at is not None]
        if rearmed:
            for r in rearmed:
                r.last_triggered_at = None
            db.commit()
            logger.warning("UPS %r back on mains - re-armed %d shutdown rule(s)",
                           ups_device.name, len(rearmed))
            await emit_event(db, ups_device, EV_ACTION,
                             f"Shutdown rules re-armed ({len(rearmed)})",
                             detail="UPS back on mains power; rules can fire again next outage.",
                             severity="info")
        return

    charge_pct = status_data.get("charge_pct")
    runtime_sec = status_data.get("runtime_sec")
    for rule in rules:
        if rule.last_triggered_at is not None:
            continue  # already fired this outage
        if not _rule_threshold_met(rule, charge_pct, runtime_sec):
            continue
        await _execute_shutdown_rule(db, rule, ups_device)
        rule.last_triggered_at = datetime.utcnow()
        db.commit()
        # Inter-device delay: give this target time to actually go down before
        # the next rule fires (e.g. guests before their hypervisor). Capped so a
        # mistyped value can't wedge this UPS's poll task for an absurd duration.
        if rule.delay_after_sec and rule.delay_after_sec > 0:
            await asyncio.sleep(min(int(rule.delay_after_sec), 600))


async def dry_run_shutdown_plan(db, ups_device) -> list[dict]:
    """Simulate a full outage for the test-fire button: walk the UPS's enabled
    rules in firing order and emit a `[Dry run]` event per rule (no real action,
    nothing stamped). Returns the ordered plan for the HTTP response."""
    rules = (db.query(ShutdownRule)
             .filter(ShutdownRule.ups_device_id == ups_device.id,
                     ShutdownRule.enabled.is_(True))
             .order_by(ShutdownRule.priority, ShutdownRule.id).all())
    plan: list[dict] = []
    for rule in rules:
        target = db.query(Device).filter(Device.id == rule.target_device_id).first()
        await _execute_shutdown_rule(db, rule, ups_device, dry_run=True)
        plan.append({
            "rule_id": rule.id,
            "priority": rule.priority,
            "action": rule.action,
            "target_id": rule.target_device_id,
            "target_name": target.name if target else None,
            "delay_after_sec": rule.delay_after_sec,
        })
    logger.warning("OUTAGE PLAN (DRY RUN) for UPS %r: %d rule(s) would fire",
                   ups_device.name, len(plan))
    return plan


async def _emit_transition_events(db, device, status_data, status_ok: bool,
                                  status_error: str | None) -> None:
    """Emit device offline/online (debounced) and UPS state-change events from
    the latest poll result. Called once per poll per device."""
    did = device.id

    # Offline/online - debounced so a single transient failure isn't an event.
    if status_ok:
        if _dev_offline.get(did):
            _dev_offline[did] = False
            await emit_event(db, device, EV_DEVICE_ONLINE,
                             f"{device.name} is back online", severity="info")
        _dev_fail_count[did] = 0
    else:
        _dev_fail_count[did] = _dev_fail_count.get(did, 0) + 1
        if _dev_fail_count[did] >= _OFFLINE_THRESHOLD and not _dev_offline.get(did):
            _dev_offline[did] = True
            await emit_event(db, device, EV_DEVICE_OFFLINE,
                             f"{device.name} is offline",
                             detail=status_error, severity="warning")

    # UPS state changes - only for UPS devices, only on a fresh read.
    if device.device_type != "ups" or not status_ok or not isinstance(status_data, dict):
        return
    new_state = status_data.get("state")
    prev = _ups_prev_state.get(did)
    if new_state == prev:
        return
    _ups_prev_state[did] = new_state
    if prev is None:
        return  # first observation - set baseline silently, don't alert
    charge = status_data.get("charge_pct")
    runtime = status_data.get("runtime_text")
    ctx = []
    if charge is not None:
        ctx.append(f"charge {round(charge)}%")
    if runtime:
        ctx.append(f"runtime {runtime}")
    ctx = " · ".join(ctx) or None
    if new_state == "on_battery":
        await emit_event(db, device, EV_UPS_ON_BATTERY,
                         f"{device.name}: on battery (mains lost)", ctx, "warning")
    elif new_state == "low_battery":
        await emit_event(db, device, EV_UPS_LOW,
                         f"{device.name}: battery LOW", ctx, "critical")
    elif new_state == "online":
        await emit_event(db, device, EV_UPS_ONLINE,
                         f"{device.name}: back on mains power", ctx, "info")


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
        # evaluation below acts only on real data - never on a preserved/stale
        # reading from a failed poll (status_data stays None on a status error).
        status_data = None
        status_error = None
        status_seen = False   # did this poll attempt the status key at all?

        try:
            for key in adapter.get_supported_cache_keys():
                try:
                    data = await adapter.fetch(key)
                    _upsert_cache(db, device_id, key, json.dumps(data), None)
                    if key == "status":
                        status_data = data
                        status_seen = True
                    # The `metrics` key doubles as the time-series source -
                    # persist its numeric members for graphing.
                    if key == _METRICS_CACHE_KEY:
                        _record_metrics(db, device_id, data, datetime.utcnow())
                except Exception as exc:
                    logger.warning("poll %s/%s failed: %s", device.name, key, exc)
                    _upsert_cache(db, device_id, key, None, str(exc))
                    if key == "status":
                        status_seen = True
                        status_error = str(exc)
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

        # Emit offline/online + UPS state-change events from this poll.
        if status_seen:
            try:
                await _emit_transition_events(db, device, status_data,
                                              status_data is not None, status_error)
            except Exception as exc:
                logger.error("event emission for %s failed: %s", device.name, exc)

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
    single gather of everyone) means a slow device - a CIMC poll can run 20-30s
    - doesn't delay a fast UPS set to a short interval, and each device is
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

    try:
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
                    continue   # still polling from a previous tick - don't overlap
                if now - last_polled.get(device_id, float("-inf")) >= interval:
                    last_polled[device_id] = now
                    in_flight.add(device_id)
                    t = asyncio.create_task(_run(device_id))
                    tasks.add(t)
                    t.add_done_callback(tasks.discard)

            await asyncio.sleep(_BASE_TICK)
    except asyncio.CancelledError:
        # Lifespan teardown: cancel the per-device poll tasks we spawned so they
        # don't outlive the loop ("Task was destroyed but it is pending"). Await
        # them so any open DB sessions / SSH transports close cleanly.
        for t in list(tasks):
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        raise