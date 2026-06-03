# HomeLab Manger — HTTP API

HomeLab Manger is a single FastAPI process that serves both this JSON API and the
SPA. Everything the web UI does, it does through these endpoints — so the API is
the full surface of the app. This document covers authentication (cookie session
**and** API keys), every `/api/*` route, request/response shapes, and the device
action vocabulary.

- Base URL: whatever host/port the app listens on, e.g. `http://homelab.lan:8080`.
- All payloads are JSON unless noted. Timestamps are RFC 3339 / ISO-8601 in UTC
  with a trailing `Z` (e.g. `2026-06-01T19:38:45.942000Z`), so any consumer can
  parse them without guessing the zone.
- This is a **single-user** app. An API key grants exactly the same access as the
  one admin user; there is no scoping or per-key permission system.

> **Homelab stance.** There's no rate limiting, no CORS allowlist, and HTTPS is
> opt-in (`https_only=False` on the session cookie by default). Don't expose this
> to untrusted networks. See the main README.

---

## Authentication

Two mechanisms authenticate against the same single admin user. Every route under
`/api/*` is gated **except** the auth/login routes and `/api/version` (see
[Unauthenticated endpoints](#unauthenticated-endpoints)). `GET /healthz`
(container liveness; pings the DB, returns 200/503) is also open and lives
outside `/api`. The login route itself is brute-force throttled — 5 failed
attempts per client IP in 5 minutes returns `429` with `Retry-After`.

The gate (`current_user` in `backend/auth.py`) checks, in order:

1. **Cookie session** — set by `POST /api/auth/login`, stored in the
   `homelab_session` cookie. Used by the browser SPA. Checked first, no DB hit.
2. **API key** — a bearer token, checked only when there's no valid session.

On failure both paths return:

```
401 Unauthorized
{ "detail": "Not authenticated" }
```

### API keys (programmatic access)

This is the path you want for scripts, cron jobs, Home Assistant, Grafana, etc.

**Token format:** `hlm_` followed by 32 url-safe random bytes, e.g.
`hlm_x7Qa...`. Only a **SHA-256 hash** of the token is stored in the DB — the
plaintext is shown **once**, at creation, and is unrecoverable afterward. A
non-secret 12-char `prefix` is kept for display/identification.

**Present the key one of two ways** (either header works):

```http
Authorization: Bearer hlm_your_key_here
```
```http
X-API-Key: hlm_your_key_here
```

**Create a key** via the SPA (the `</>` icon in the account area) or the API:

```bash
curl -sX POST http://homelab.lan:8080/api/api-keys \
  -H 'Authorization: Bearer hlm_existing_key' \
  -H 'Content-Type: application/json' \
  -d '{"name": "grafana"}'
```
```json
{ "id": 3, "name": "grafana", "prefix": "hlm_x7Qa9bcd", "key": "hlm_x7Qa9bcd...full..." }
```
Copy `key` now — it is never returned again.

> **Bootstrapping the first key:** you need *some* credential to create the first
> API key. Log into the SPA in a browser (session cookie) and create one from the
> API Keys modal, or use the session cookie directly. There is no unauthenticated
> key-minting path by design.

**WebSocket auth is session-only.** `/api/ws` reads the session cookie directly
and does **not** accept API keys — it's only used by the browser SPA. Bearer
tokens won't open the socket.

Each successful key-authenticated request best-effort stamps `last_used_at` on the
key (visible in `GET /api/api-keys`).

---

## Unauthenticated endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/healthz` | Liveness probe (pings the DB). `200 {status:ok,db:true,version}` or `503`. Used by the Docker `HEALTHCHECK`. |
| `GET`  | `/api/version` | App version + project links. Open so the login page can show it. |
| `GET`  | `/api/auth/me` | `{ "authenticated": bool, "username": str\|null }` — reports session state. |
| `POST` | `/api/auth/login` | Body `{username, password}` → sets session cookie, returns `{ok, username}`. 401 on bad creds, 429 when throttled. |
| `POST` | `/api/auth/logout` | Clears the session. `{ok: true}`. |

`GET /api/version`:
```json
{
  "version": "0.5.7",
  "github_url": "https://github.com/Spillebulle/homelab-manger",
  "dockerhub_url": "https://hub.docker.com/r/spillebulle/homelab-manger"
}
```

`POST /api/auth/change-password` is **gated** (requires a session/key): body
`{current_password, new_password}`; new password must be ≥ 8 chars.

---

## Concepts

### Device, adapter, device_type

A **device** has a `device_type` (the UI category) and an `adapter_type` (the code
that talks to it). The valid pairings:

| `device_type` | valid `adapter_type` values |
|---------------|-----------------------------|
| `switch` | `snmp`, `dlink`, `hpe1820` |
| `router` | `snmp` |
| `pdu` | `snmp` |
| `server` | `cimc`, `cimc_redfish`, `redfish`, `ilo`, `idrac`, `ibmc` |
| `ups` | `usbups`, `snmp` |

`redfish`/`ilo`/`idrac`/`ibmc` are all the same Redfish adapter with vendor
quirks. The pairing isn't enforced server-side (you *can* POST an odd combination)
but the SPA only offers the combos above.

### The cache model (reads are never live)

The HTTP layer **never** calls a device directly for reads. A background poller
fetches each device on its own interval and writes results into a per-key cache.
Read endpoints (`/cache`, `/devices`) return the **last cached value**, which can
be up to one poll interval stale. Each adapter populates a different set of
**cache keys**:

| adapter | cache keys |
|---------|-----------|
| `snmp` | `status`, `ports`, `poe`, `connected` |
| `dlink` | `status`, `ports`, `poe`, `vlans`, `connected` |
| `hpe1820` | `status`, `ports`, `poe`, `vlans`, `connected` |
| `cimc`, `cimc_redfish`, `redfish`/`ilo`/`idrac`/`ibmc` | `status`, `hardware`, `storage`, `network`, `power`, `sensors` |
| `usbups` | `status`, `metrics` |

The special `metrics` cache key feeds the time-series history table (graphs). Any
adapter emitting a `metrics` dict gets graphed automatically.

**Writes bypass the cache** — actions (port toggles, power on/off) go straight to
the device via `execute_action` and return the result synchronously.

To force an out-of-band poll, use `POST /api/devices/{id}/refresh`.

---

## Devices

### `GET /api/devices`

List all devices with their latest `status` cache value. **Credentials are never
included here.**

```json
[
  {
    "id": 1,
    "name": "Core switch",
    "hostname": "10.0.0.2",
    "device_type": "switch",
    "adapter_type": "dlink",
    "poll_interval": 60,
    "shutdown_actions": [],
    "status": { "...": "adapter-specific status payload, or null" },
    "status_error": null,
    "last_seen": "2026-06-01T10:42:11.123456Z"
  }
]
```

- `shutdown_actions` — power-off actions this device type supports as a shutdown
  **target** (empty for switches/UPS; `["power_off"]` or
  `["graceful_shutdown","power_off"]` for servers).
- `last_seen` — timestamp of the last **successful** poll (not last attempt). An
  offline device keeps its last good `status` but `status_error` is populated.

### `POST /api/devices` → `201`

Create a device.

```json
{
  "name": "Core switch",
  "hostname": "10.0.0.2",
  "device_type": "switch",
  "adapter_type": "dlink",
  "credentials": { "community": "public", "ssh_username": "admin", "ssh_password": "..." },
  "enabled": true,
  "notes": "rack 1",
  "poll_interval": 60
}
```
Returns `{ "id": 5 }`. `credentials` are Fernet-encrypted at rest. `poll_interval`
is seconds; omit/`null` to use the global default; the poller clamps to a 5 s
minimum. Credential keys vary per adapter — see [Credential keys](#credential-keys-by-adapter).

### `PUT /api/devices/{id}`

Partial update — only the fields you send are changed (`exclude_unset`).

**Secret credential fields are merged, not overwritten.** Sending an empty string
(or omitting the key) for any of `password`, `ssh_password`, `web_password`,
`snmp_auth_pass`, `snmp_priv_pass` **keeps the existing stored secret**. Any other
value overwrites. Non-secret keys (community, ports, usernames) overwrite
unconditionally, so you *can* clear them. Returns `{ "id": 5 }`.

### `DELETE /api/devices/{id}`

Deletes the device and its cache, metrics, notification config, and any shutdown
rules referencing it (as UPS or target). Event-log rows are **detached** (kept,
`device_id` nulled) so history survives. Returns `{ "ok": true }`.

### `GET /api/devices/{id}/credentials`

Returns the credential dict with **secret fields blanked** (empty strings). The
only route that surfaces credentials at all; used by the edit modal to pre-fill
non-secret fields without ever shipping a password to the browser.

### `GET /api/devices/{id}/cache`

The full cache map for a device — every cache key plus per-key metadata:

```json
{
  "status": { "...": "..." },
  "status_updated": "2026-06-01T10:42:11.123456Z",
  "ports": [ { "...": "..." } ],
  "ports_updated": "2026-06-01T10:42:11.123456Z",
  "poe_error": "SSH auth failed: ...",
  "...": "..."
}
```
For each key `K`: `K` holds the data, `K_updated` its last-success timestamp, and
`K_error` an error string if the most recent fetch failed. On error the last good
`data` is preserved and only `K_error` is refreshed.

### `POST /api/devices/{id}/refresh`

Forces an immediate poll of the device outside the scheduler, then returns
`{ "ok": true }`. The cache (and any connected WebSocket clients) update as a
side effect.

### `GET /api/devices/{id}/graph`

**Charting-tool-friendly time-series**, returned as a **flat JSON array** — built
for Grafana (Infinity), Metabase, Observable, `pandas.read_json`, etc. This is the
endpoint to point external graphing software at. It works for any device that
records metrics, not just UPS.

Query params:
- `metrics` — comma-separated metric names. Default: every metric the device has.
- `from` / `to` — window bounds. Accepts **epoch milliseconds** (Grafana's
  `${__from}` / `${__to}`), epoch seconds, or ISO-8601. `to` defaults to now.
- `hours` — look-back window (float, default `24`); used only when `from` is omitted.
- `max_points` — per-series downsample cap (default `600`); longer series are
  bucket-averaged.
- `format` — `long` (default) or `wide`.

Timestamps are **RFC 3339 UTC with a trailing `Z`**, so no tool has to guess the
zone (this is the one wart `/history` has — see below).

**`long` (default)** — one object per data point, with the metric name as a label
column. Ideal for a multi-series panel that splits series by `metric`:
```json
[
  { "time": "2026-06-01T19:38:45.942Z", "metric": "watts",    "value": 840.0 },
  { "time": "2026-06-01T19:38:45.942Z", "metric": "load_pct", "value": 70.0 }
]
```

**`wide`** (`?format=wide`) — one object per timestamp, a column per metric
(spreadsheet shape). Metrics are aligned onto a shared time grid; a metric absent
from a bucket is simply omitted from that row (a gap, not a zero):
```json
[
  { "time": "2026-06-01T19:38:00.000Z", "watts": 840.0, "load_pct": 70.0, "charge_pct": 100.0 }
]
```

UPS metrics are `load_pct`, `watts`, `charge_pct`, `runtime_sec`, `input_voltage`.

#### Grafana (Infinity) setup — the easy way

Because the response is already a **top-level array of objects**, there's no root
selector to drill into and no array-index columns:

- Datasource: **Infinity**, with header `Authorization: Bearer hlm_...`.
- Query: **Type** JSON · **Parser** Backend · **Source** URL · **Format** Time series.
- **URL:** `/api/devices/7/graph?metrics=watts,load_pct&from=${__from}&to=${__to}`
- **Columns** (selected by **name**, not index):
  - `time` → format **Time**
  - `value` → format **Number**
  - `metric` → format **String** (this becomes the series label)

`${__from}` / `${__to}` let Grafana's time picker drive the window directly. For a
single metric you can drop the `metric` column and just chart `time` + `value`.

### `GET /api/devices/{id}/history`

> The SPA's own graphs use this. For external tools prefer **`/graph`** above —
> same data, but a flat array, named columns, and a `from`/`to` window, which is
> far less fiddly to wire into a charting tool than this nested shape.

Time-series data for graphing (driven by the `metrics` cache key).

Query params:
- `metrics` — comma-separated metric names. Default: every metric the device has.
- `hours` — look-back window (float, default `24`).
- `max_points` — cap per series (default `600`); longer series are bucket-averaged.

```json
{
  "from": "2026-05-31T10:42:00.000000Z",
  "to":   "2026-06-01T10:42:00.000000Z",
  "metrics": {
    "load_pct":  [ ["2026-05-31T10:42:00.000000Z", 31.0], ["2026-05-31T11:42:00.000000Z", 28.5] ],
    "watts":     [ ["...", 410.2] ]
  }
}
```

### `GET /api/devices/{id}/usb-diagnostics`

`usbups` devices only (else `400`). Dumps the raw HID report descriptor hex +
every decoded usage/field + a live read — the USB analogue of an SNMP walk. Useful
to confirm a new UPS model is covered by the generic parser.

---

## Device actions (writes)

Actions bypass the cache and hit the device synchronously. The action vocabulary
depends on the adapter.

**Status codes:**
- `200` — success. Body is the adapter's result, usually `{ "ok": true }` (some
  actions return data, e.g. parsed CLI output).
- `400` — the action `type` isn't supported for this adapter. Body
  `{ "error": "Unsupported action: ..." }`.
- `502` — the device/adapter failed (auth, timeout, switch rejected the command).
  Body carries the detail in `error` (or `errors` for batch ops like `vlan_batch`).

The error detail is always in the response **body** (`error` / `errors`), not just
the status line, so you can show the device's own message.

### `POST /api/devices/{id}/action`

Body is the action object; `type` selects the operation.

**Server power control** (`redfish`/`ilo`/`idrac`/`ibmc`, `cimc`, `cimc_redfish`):

```json
{ "type": "power_on" }
```
Supported `type` values (Redfish/CIMC-Redfish): `power_on`, `power_off`,
`power_cycle`, `graceful_shutdown`, `graceful_restart`. The legacy `cimc` adapter
(firmware ≤ 2.x) supports `power_on`, `power_off`, `power_cycle`, `hard_reset` but
**not** `graceful_shutdown`.

**KVM launch** (servers — prefer the dedicated endpoint below):
```json
{ "type": "kvm_launch" }
```

**Switch / SNMP** — port admin toggle (generic SNMP SET, works on any SNMP switch):
```json
{ "type": "port_admin", "port_id": "5", "enable": false }
```

**D-Link (`dlink`)** additionally supports, via SSH/CLI:
| `type` | params | effect |
|--------|--------|--------|
| `port_poe` | `port_id`, `enable` (bool) | enable/disable PoE on a port |
| `port_poe_limit` | `port_id`, `milliwatts` (int, default 15400) | set PoE power cap |
| `port_description` | `port_id`, `description` | set port label |
| `ssh_command` | `command` | run a raw CLI command (returns parsed output) |
| `vlan_create` | `vid`, `name` | create a VLAN |
| `vlan_delete` | `vid` | delete a VLAN (refuses VID 1) |
| `vlan_set_port` | `vid`, `port_id`, `mode` (`tagged`\|`untagged`\|`none`) | set membership |
| `vlan_batch` | `creates`, `renames`, `deletes`, `changes` | apply many VLAN edits atomically |

**HPE 1820 (`hpe1820`)** supports `port_admin`, `port_description`, `port_poe`,
`port_poe_limit`, `vlan_create`, `vlan_delete`, `vlan_set_port`, `vlan_batch`
(via the web UI rather than SSH; same param shapes for the VLAN/port ops).

### `POST /api/devices/{id}/port/{port_id}/action`

Convenience wrapper: identical to `/action` but injects `port_id` from the URL
into the action body. Use for per-port operations.

```bash
curl -sX POST http://homelab.lan:8080/api/devices/1/port/5/action \
  -H 'Authorization: Bearer hlm_...' -H 'Content-Type: application/json' \
  -d '{"type":"port_poe","enable":false}'
```

### `GET /api/devices/{id}/kvm.jnlp`

Servers only (`cimc`, `cimc_redfish`, `ibmc`). Returns a Java Web Start `.jnlp`
file (a download, not JSON) that launches the BMC's KVM console. `400` for other
adapter types, `502` if the BMC token mint fails. This is the supported way to get
a KVM session — don't build the JNLP yourself.

---

## Preflight (connectivity testing)

### `GET /api/adapter-requirements`

Static metadata: for every adapter type, the services it needs to reach.

```json
{
  "dlink": [
    { "service": "SNMPv2c", "transport": "snmp", "port": 161, "description": "Inventory + port stats", "required": true },
    { "service": "SSH",     "transport": "tcp",  "port": 22,  "description": "PoE/VLAN config (CLI-only)", "required": true }
  ],
  "...": []
}
```

### `POST /api/devices/preflight`

Actively test a **prospective** device's connectivity before creating it.

```json
{ "hostname": "10.0.0.2", "adapter_type": "dlink", "credentials": { "community": "public" }, "device_id": null }
```
Optional `device_id` merges form creds with that device's stored secrets (same
blank-keeps-secret rule as `PUT`) so you can test an edit without re-typing
passwords. Response:
```json
{
  "status": "ok",
  "results": [
    { "service": "SNMPv2c", "transport": "snmp", "port": 161, "required": true, "ok": true, "detail": "sysName=core-sw" },
    { "service": "SSH", "transport": "tcp", "port": 22, "required": true, "ok": true, "detail": "connected" }
  ]
}
```
`status` is `ok` / `partial` (an optional service failed) / `fail` (a required
service failed). Some transports (UDP/IPMI) report `skipped` — they can't be
probed cheaply.

### `POST /api/devices/{id}/preflight`

Same active test against an **already-saved** device using its stored decrypted
credentials (no body needed).

---

## API keys

| Method | Path | Body | Returns |
|--------|------|------|---------|
| `GET` | `/api/api-keys` | — | list of `{id, name, prefix, created_at, last_used_at}` (no secret) |
| `POST` | `/api/api-keys` | `{name?}` | `{id, name, prefix, key}` — **`key` shown once** |
| `DELETE` | `/api/api-keys/{id}` | — | `{ok: true}` (404 if not found) |

---

## Events (log)

### `GET /api/events`

Recent events, newest first. Query params: `device_id`, `event_type`,
`limit` (default 100, max 1000).

```json
[
  {
    "id": 412,
    "ts": "2026-06-01T10:40:00.000000Z",
    "device_id": 7,
    "device_name": "Rack UPS",
    "event_type": "ups_on_battery",
    "severity": "warning",
    "title": "Rack UPS on battery",
    "detail": "AC lost; 98% charge, 42 min runtime"
  }
]
```
Event types include `device_offline` / `device_online`, `ups_on_battery` /
`ups_low` / `ups_online`, and `action` (shutdown-rule executions). Events are
denormalised (`device_name` stored) so they survive device deletion.

---

## Notifications (per device)

A single Discord webhook + toggles per device. The config row is auto-created on
first GET.

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/devices/{id}/notifications` | returns the config |
| `PUT` | `/api/devices/{id}/notifications` | partial update |
| `POST` | `/api/devices/{id}/notifications/test` | sends a test Discord message (400 if no webhook, 502 if Discord rejects it) |

Config shape (GET / PUT body):
```json
{
  "device_id": 7,
  "webhook_url": "https://discord.com/api/webhooks/...",
  "enabled": true,
  "notify_offline": true,
  "notify_ups_state": true,
  "notify_action": true
}
```
`notify_ups_state` only applies to UPS devices.

---

## Shutdown rules (UPS outage orchestration)

When a UPS goes on battery, automatically run a power action on a **target**
device once a threshold is crossed. **This powers off real machines** — design is
conservative (once per outage, re-armed when mains returns).

Rules live under a UPS and target another device. The action passes through to the
target adapter's `execute_action`, so only targets whose adapter declares a
shutdown action (servers) are valid — switches/UPS can't be targets.

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/devices/{ups_id}/shutdown-rules` | list rules for this UPS (ordered by `priority`, then `id`) |
| `POST` | `/api/devices/{ups_id}/shutdown-rules` | create (201) |
| `PUT` | `/api/shutdown-rules/{rule_id}` | update (re-arms the rule) |
| `DELETE` | `/api/shutdown-rules/{rule_id}` | delete |
| `POST` | `/api/devices/{ups_id}/shutdown-rules/test` | dry-run the plan (sends nothing; see below) |

**Create body:**
```json
{
  "target_device_id": 3,
  "action": "graceful_shutdown",
  "trigger_charge_pct": 20,
  "trigger_runtime_sec": 300,
  "enabled": true,
  "priority": 100,
  "delay_after_sec": 0
}
```
- `action` — must be one the target supports (`graceful_shutdown` / `power_off`);
  an unsupported value falls back to the target's first supported action.
- `trigger_charge_pct` / `trigger_runtime_sec` — thresholds, **OR-combined**.
  Either, both, or neither (neither ⇒ fire as soon as on battery).
- `priority` — lower fires first during an outage (default `100`).
- `delay_after_sec` — wait after firing this rule before the next (default `0`,
  capped at 600 s at fire time).
- Rejections: self-target → `400`; target can't power off → `400`; duplicate rule
  for the same (UPS, target) → `409`.

**Dry run (`POST .../shutdown-rules/test`):** simulates a full outage — walks the
enabled rules in firing order and emits a `[Dry run]` event per rule (so Discord
notifications fire too) **without sending any action to a device or arming
anything**. Use it to validate the plan + notification wiring. Returns
`{"ok": true, "dry_run": true, "count": N, "plan": [{rule_id, priority, action,
target_id, target_name, delay_after_sec}, …]}`.

**Response (and list items):**
```json
{
  "id": 9,
  "ups_device_id": 7,
  "target_device_id": 3,
  "target_name": "Dell R640",
  "target_type": "server",
  "target_adapter": "idrac",
  "target_shutdown_actions": ["graceful_shutdown", "power_off"],
  "action": "graceful_shutdown",
  "trigger_charge_pct": 20,
  "trigger_runtime_sec": 300,
  "enabled": true,
  "priority": 100,
  "delay_after_sec": 0,
  "last_triggered_at": null
}
```
`last_triggered_at` is the once-per-outage guard; any `PUT` clears it (re-arms).

---

## WebSocket — `/api/ws`

Push channel for live UI updates. **Session-cookie auth only** (API keys do not
work; closes with code `1008` if the session is missing/invalid). On each poll
cycle the server broadcasts JSON messages (e.g. `device_updated` ticks) so the SPA
can refresh without polling. Intended for the browser SPA — for programmatic
polling, use `GET /api/devices` / `/cache` on an interval instead.

---

## Credential keys by adapter

Pass these inside the `credentials` object on create/update. Secret keys
(`password`, `ssh_password`, `web_password`, `snmp_auth_pass`, `snmp_priv_pass`)
are blanked on read and merged-not-overwritten on update.

| adapter | common credential keys |
|---------|------------------------|
| `snmp`, `dlink`, `hpe1820` | `community` (read, default `public`), `write_community` (default `private`), `port` (default 161); D-Link/HPE also: `ssh_username`/`ssh_password`/`ssh_port` (D-Link CLI), `web_username`/`web_password`/`web_scheme` (HPE web UI) |
| `redfish`/`ilo`/`idrac` | `username`, `password`, `port` (default 443) |
| `ibmc` | `username`, `password`; optional SNMPv3 enrichment: `snmp_user`, `snmp_auth_pass`, `snmp_priv_pass`, `snmp_port`, `snmp_auth_proto`, `snmp_priv_proto` |
| `cimc`, `cimc_redfish` | `username`, `password`; optional `ssh_username`/`ssh_password`/`ssh_port` (session reaper), `ipmi_username`/`ipmi_password`/`ipmi_port` (sensors) |
| `usbups` | none required (USB-local); optional `nominal_real_power` (W, default 1320), `low_charge_pct`, `low_runtime_sec`. `hostname` is just a label. |

---

## Quick reference (curl)

```bash
KEY=hlm_your_key_here
BASE=http://homelab.lan:8080

# List devices
curl -s "$BASE/api/devices" -H "Authorization: Bearer $KEY"

# Full cache for device 1
curl -s "$BASE/api/devices/1/cache" -H "Authorization: Bearer $KEY"

# UPS load + watts over the last 6 hours, charting-tool shape (flat array)
curl -s "$BASE/api/devices/7/graph?metrics=load_pct,watts&hours=6" \
  -H "Authorization: Bearer $KEY"

# Force a refresh
curl -sX POST "$BASE/api/devices/1/refresh" -H "Authorization: Bearer $KEY"

# Gracefully shut down a server
curl -sX POST "$BASE/api/devices/3/action" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d '{"type":"graceful_shutdown"}'

# Disable PoE on D-Link port 5
curl -sX POST "$BASE/api/devices/1/port/5/action" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d '{"type":"port_poe","enable":false}'
```

---

## Notes & gotchas

- **Reads are cached, not live** — `/devices` and `/cache` reflect the last poll.
  Use `/refresh` to force a fresh fetch.
- **Action failures use real status codes** — `400` (unsupported action) or `502`
  (device/adapter failed); the detail is in the body's `error`/`errors` field. A
  `200` always means success.
- **Timestamps are UTC with `Z`** — parse them as UTC (`new Date(...)`,
  `datetime.fromisoformat`, Grafana time column) and they'll be correct.
- **API keys ≠ WebSocket** — the WS is session-cookie only.
- **OpenAPI docs** — FastAPI's auto-generated Swagger UI (`/docs`) and schema
  (`/openapi.json`) are available, but the schema doesn't capture the per-adapter
  action vocabulary or the dynamic `credentials`/`action` shapes; this file is the
  authoritative reference for those.
- **Single user, no scoping** — every key has full admin access. Rotate by
  deleting and recreating.
