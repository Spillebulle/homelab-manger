"""
Event log + notification dispatch.

`emit_event` is the single entry point: it stores an Event row (pruning the log
to a bound) and then fans the event out to any matching notification channels
(currently a per-device Discord webhook). Everything is best-effort - a failed
notification never breaks polling or the action that triggered it.
"""
import asyncio
import logging

import httpx

from .models import Event, NotificationConfig

logger = logging.getLogger(__name__)

# Keep the log bounded. Pruned opportunistically inside emit_event.
_MAX_EVENTS = 2000

# Event types (also the keys the notification toggles map to).
EV_UPS_ON_BATTERY = "ups_on_battery"
EV_UPS_LOW        = "ups_low"
EV_UPS_ONLINE     = "ups_online"
EV_DEVICE_OFFLINE = "device_offline"
EV_DEVICE_ONLINE  = "device_online"
EV_ACTION         = "action"

# Which notify_* flag gates each event type.
_FLAG_FOR_TYPE = {
    EV_UPS_ON_BATTERY: "notify_ups_state",
    EV_UPS_LOW:        "notify_ups_state",
    EV_UPS_ONLINE:     "notify_ups_state",
    EV_DEVICE_OFFLINE: "notify_offline",
    EV_DEVICE_ONLINE:  "notify_offline",
    EV_ACTION:         "notify_action",
}

# Discord embed colour per severity (decimal RGB).
_COLOR = {"info": 0x3498DB, "warning": 0xF1C40F, "critical": 0xE74C3C}


async def emit_event(db, device, event_type: str, title: str,
                     detail: str | None = None, severity: str = "info") -> None:
    """Record an event and dispatch notifications for it. `device` may be a
    Device ORM object or None (system-level event)."""
    device_id = getattr(device, "id", None)
    device_name = getattr(device, "name", None)
    ev = Event(
        device_id=device_id, device_name=device_name, event_type=event_type,
        severity=severity, title=title, detail=detail,
    )
    db.add(ev)
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("failed to record event %r: %s", title, exc)
        return

    _prune(db)
    log_fn = logger.warning if severity != "info" else logger.info
    log_fn("EVENT [%s/%s] %s%s", event_type, severity, title,
           f" - {detail}" if detail else "")

    if device_id is not None:
        try:
            await _dispatch(db, device_id, device_name, event_type, title, detail, severity)
        except Exception as exc:
            logger.error("notification dispatch for event %r failed: %s", title, exc)


def _prune(db) -> None:
    """Trim the log to the newest _MAX_EVENTS rows. Cheap: only deletes when
    over the cap."""
    try:
        count = db.query(Event.id).count()
        if count <= _MAX_EVENTS:
            return
        # Find the id cutoff and delete everything older.
        cutoff = (db.query(Event.id)
                  .order_by(Event.id.desc())
                  .offset(_MAX_EVENTS).limit(1).scalar())
        if cutoff is not None:
            db.query(Event).filter(Event.id <= cutoff).delete(synchronize_session=False)
            db.commit()
    except Exception as exc:
        db.rollback()
        logger.debug("event prune failed: %s", exc)


async def _dispatch(db, device_id, device_name, event_type, title, detail, severity) -> None:
    cfg = (db.query(NotificationConfig)
           .filter(NotificationConfig.device_id == device_id).first())
    if not cfg or not cfg.enabled or not cfg.webhook_url:
        return
    flag = _FLAG_FOR_TYPE.get(event_type)
    if flag and not getattr(cfg, flag, True):
        return  # this event type is muted for this device
    await post_discord(cfg.webhook_url, title, detail, severity, device_name)


async def post_discord(webhook_url: str, title: str, detail: str | None,
                       severity: str = "info", device_name: str | None = None) -> tuple[bool, str]:
    """POST a Discord embed to a webhook. Returns (ok, message). Best-effort -
    used both by the dispatcher and the 'send test' endpoint."""
    embed = {
        "title": title,
        "color": _COLOR.get(severity, _COLOR["info"]),
    }
    if detail:
        embed["description"] = detail
    if device_name:
        embed["footer"] = {"text": f"HomeLab-Manger · {device_name}"}
    payload = {"embeds": [embed]}
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.post(webhook_url, json=payload)
        if r.status_code in (200, 204):
            return True, "delivered"
        return False, f"Discord returned HTTP {r.status_code}: {r.text[:200]}"
    except httpx.HTTPError as exc:
        return False, f"{type(exc).__name__}: {exc}"
