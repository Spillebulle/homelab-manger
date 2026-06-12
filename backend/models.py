from datetime import datetime
from sqlalchemy import (
    Column, Integer, Float, String, Boolean, Text, DateTime, ForeignKey,
    UniqueConstraint, Index, TypeDecorator,
)
from .database import Base
from .credentials_crypto import encrypt_credentials, decrypt_credentials


class EncryptedJSON(TypeDecorator):
    """Stores a JSON-able value as Fernet-encrypted text. Read sites get a
    dict (or None) back automatically; write sites pass a dict (or None) and
    the column handles serialization + encryption. Legacy plaintext rows
    decode transparently — they're re-encrypted by the startup migration in
    `database.py`, but until that runs (or for fresh ad-hoc reads) the
    fallback in decrypt_credentials handles them.

    Backing column type stays TEXT so the existing schema (and any external
    inspection tools) see the same column shape; only the *content* is now
    a base64url-encoded ciphertext with an `enc:` prefix instead of raw
    JSON."""

    impl = Text
    cache_ok = True  # SQLAlchemy 2.x — compile-time caching is safe; we have no per-instance state

    def process_bind_param(self, value, dialect):
        return encrypt_credentials(value)

    def process_result_value(self, value, dialect):
        return decrypt_credentials(value)


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=False)
    device_type = Column(String(50), nullable=False)   # switch | server | router | pdu | ups
    adapter_type = Column(String(50), nullable=False)  # snmp | dlink | cimc | redfish | ilo | idrac | ibmc
    # Column type is EncryptedJSON — read/write as a dict; the TypeDecorator
    # handles JSON serialization and Fernet encryption transparently. See
    # `credentials_crypto.py` for the key-management model.
    credentials = Column(EncryptedJSON)
    enabled = Column(Boolean, default=True)
    notes = Column(Text)
    # Per-device poll interval in seconds. NULL ⇒ use the poller's default
    # (DEFAULT_POLL_INTERVAL). The poller clamps to a sane minimum at read time.
    poll_interval = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class DeviceCache(Base):
    __tablename__ = "device_cache"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    cache_key = Column(String(100), nullable=False)  # status | ports | poe | hardware | storage | …
    data = Column(Text)                               # JSON
    updated_at = Column(DateTime)
    error = Column(Text)

    # Without this, two concurrent polls can both SELECT-miss and both INSERT,
    # leaving duplicate (device_id, cache_key) rows. The cache_map reader picks
    # whichever row SQLite returns last — sometimes the stale one — so the UI
    # shows yesterday's data with no indication that's what happened.
    __table_args__ = (
        UniqueConstraint("device_id", "cache_key", name="uq_device_cache_key"),
    )


class DeviceMetric(Base):
    """Time-series samples for graphing. One row per (device, metric, sample).

    Unlike `device_cache` (which keeps only the latest value per key), this
    table accumulates history. The poller writes the numeric members of an
    adapter's `metrics` cache key here every poll cycle and prunes rows beyond
    METRICS_RETENTION_DAYS. New table ⇒ `Base.metadata.create_all` in init_db
    creates it automatically; no manual migration needed.

    Float storage (not the EncryptedJSON dict pattern) because these are
    non-secret numeric series queried by range — encryption would defeat the
    indexed time-window scans the history endpoint relies on."""
    __tablename__ = "device_metrics"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    metric = Column(String(50), nullable=False)   # load_pct | watts | charge_pct | runtime_sec | …
    value = Column(Float, nullable=False)
    ts = Column(DateTime, nullable=False, default=datetime.utcnow)

    # The history endpoint always filters by (device_id, metric) over a ts
    # range and orders by ts — this composite index serves both the scan and
    # the retention-prune DELETE.
    __table_args__ = (
        Index("ix_device_metrics_lookup", "device_id", "metric", "ts"),
    )


class AuthUser(Base):
    __tablename__ = "auth_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Event(Base):
    """Append-only event log: UPS state changes, device offline/online
    transitions, and shutdown actions. Feeds both the in-UI history and the
    notification dispatcher. Pruned by count so it can't grow unbounded."""
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"),
                       nullable=True, index=True)
    device_name = Column(String(255), nullable=True)   # denormalised so log survives device deletion
    event_type = Column(String(40), nullable=False)    # ups_on_battery | ups_low | ups_online | device_offline | device_online | action
    severity = Column(String(16), nullable=False, default="info")  # info | warning | critical
    title = Column(String(255), nullable=False)
    detail = Column(Text, nullable=True)


class NotificationConfig(Base):
    """Per-device notification settings. One row per device. Currently a single
    Discord webhook + per-event-type toggles; the webhook is stored plaintext
    (it's a capability URL, not a password — homelab stance, same as the rest)."""
    __tablename__ = "notification_configs"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"),
                       nullable=False, unique=True, index=True)
    webhook_url = Column(Text, nullable=True)          # Discord webhook
    enabled = Column(Boolean, default=True)
    notify_offline = Column(Boolean, default=True)     # device offline/online transitions
    notify_ups_state = Column(Boolean, default=True)   # UPS on-battery / low / restored
    notify_action = Column(Boolean, default=True)      # shutdown action fired


class ShutdownRule(Base):
    """Phase-2 outage orchestration. One rule = "when UPS X is on battery and a
    threshold is crossed, run <action> on target device Y". Rules are owned by a
    UPS device and target another device (server/switch/etc.).

    Firing is once-per-outage: `last_triggered_at` is stamped when a rule fires
    and cleared (re-armed) when the UPS returns to mains power — persisted so an
    app restart mid-outage doesn't re-shut-down a machine that's already down.

    Thresholds (either/both, OR-combined): fire when `charge_pct <=
    trigger_charge_pct` OR `runtime_sec <= trigger_runtime_sec`. Both NULL ⇒
    fire as soon as the UPS is on battery."""
    __tablename__ = "shutdown_rules"

    id = Column(Integer, primary_key=True, index=True)
    ups_device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    target_device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"),
                              nullable=False)
    action = Column(String(40), nullable=False, default="graceful_shutdown")
    trigger_charge_pct = Column(Integer, nullable=True)    # fire when charge% <= this
    trigger_runtime_sec = Column(Integer, nullable=True)   # fire when runtime(s) <= this
    enabled = Column(Boolean, default=True)
    last_triggered_at = Column(DateTime, nullable=True)    # NULL ⇒ armed
    # Ordering during an outage: rules fire in ascending `priority` (then id), so
    # you can bring VMs/hosts down before the host they depend on. After firing a
    # rule, the orchestrator waits `delay_after_sec` before the next one — time
    # for a guest OS to finish shutting down before its hypervisor is told to.
    priority = Column(Integer, nullable=False, default=100)
    delay_after_sec = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class Integration(Base):
    """Global third-party integration settings (Nginx Proxy Manager,
    Namecheap). One row per integration `name`, with the whole config dict
    stored Fernet-encrypted — same EncryptedJSON column as device
    credentials, since both integrations hold secrets (NPM admin password,
    Namecheap API key)."""
    __tablename__ = "integrations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(40), nullable=False, unique=True)   # 'npm' | 'namecheap'
    config = Column(EncryptedJSON)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Service(Base):
    """A published web service: one subdomain routed through Nginx Proxy
    Manager to an internal IP:port, with the DNS record created in Namecheap
    and a Let's Encrypt certificate issued by NPM.

    Provisioning is a 3-step pipeline (DNS record → NPM proxy host → SSL
    certificate) run as a background task; each step records its own
    status/detail so a partial failure is visible and retryable — re-running
    provisioning skips steps already marked `ok`. The created NPM object ids
    and the exact DNS record we wrote are stored so deletion can clean up
    precisely what was provisioned and nothing else."""
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    subdomain = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False)             # snapshot of the Namecheap domain at creation
    forward_scheme = Column(String(8), nullable=False, default="http")
    forward_host = Column(String(255), nullable=False)
    forward_port = Column(Integer, nullable=False)
    # NPM proxy-host settings, pushed to NPM by the pipeline's sync step.
    # (Columns after `websockets` are ALTER-ed into pre-existing tables by
    # _migrate_add_service_columns — keep that migration in step.)
    websockets = Column(Boolean, default=True)
    block_exploits = Column(Boolean, default=True)
    caching_enabled = Column(Boolean, default=False)
    ssl_forced = Column(Boolean, default=True)
    http2_support = Column(Boolean, default=True)
    hsts_enabled = Column(Boolean, default=False)
    hsts_subdomains = Column(Boolean, default=False)
    # Optional link to a Portainer container (by name — stable across
    # container recreations, unlike the id). Display/navigation only; nothing
    # is ever sent to Portainer.
    portainer_container = Column(String(255), nullable=True)
    portainer_endpoint_id = Column(Integer, nullable=True)
    # Remote object ids / record identity, for retry-adoption and cleanup.
    npm_proxy_host_id = Column(Integer, nullable=True)
    npm_certificate_id = Column(Integer, nullable=True)
    dns_record_type = Column(String(8), nullable=True)       # CNAME | A (as provisioned)
    dns_record_target = Column(String(255), nullable=True)
    # Per-step status: pending | ok | error.
    dns_status = Column(String(16), nullable=False, default="pending")
    npm_status = Column(String(16), nullable=False, default="pending")
    cert_status = Column(String(16), nullable=False, default="pending")
    dns_detail = Column(Text, nullable=True)
    npm_detail = Column(Text, nullable=True)
    cert_detail = Column(Text, nullable=True)
    state = Column(String(16), nullable=False, default="pending")  # pending | provisioning | active | error
    created_at = Column(DateTime, default=datetime.utcnow)


class ApiKey(Base):
    """A bearer token for programmatic API access, as an alternative to the
    cookie session. Only the SHA-256 hash is stored — the plaintext is shown
    once at creation and never recoverable. `prefix` is a non-secret leading
    slice kept purely so the UI can identify which key is which."""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)  # sha256 hex
    prefix = Column(String(20), nullable=False)                              # display only
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
