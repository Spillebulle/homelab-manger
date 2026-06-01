<p align="center">
  <img src="https://raw.githubusercontent.com/Spillebulle/homelab-manger/main/frontend/static/logo.png" alt="HomeLab Manger" width="120">
</p>

<h1 align="center">HomeLab Manger</h1>

<p align="center">
  Single-process FastAPI app for managing homelab gear — switches (D-Link, HPE, generic SNMP), servers (Cisco CIMC, Dell iDRAC, HPE iLO, Huawei iBMC via Redfish), and USB-connected UPSes — plus anything with an SNMP / SSH / Redfish / IPMI surface. JSON API + a static SPA in one binary.
</p>

<p align="center">
  <img src="https://img.shields.io/github/license/Spillebulle/homelab-manger?style=flat-square" alt="License">
  <img src="https://github.com/Spillebulle/homelab-manger/actions/workflows/docker.yml/badge.svg" alt="Build">
  <img src="https://img.shields.io/docker/pulls/spillebulle/homelab-manger?style=flat-square" alt="Docker pulls">
</p>

---

## Screenshots

### Dashboard
![Dashboard](https://raw.githubusercontent.com/Spillebulle/homelab-manger/main/docs/Dashboard.png)

### Switch — port view
![Switch ports](https://raw.githubusercontent.com/Spillebulle/homelab-manger/main/docs/Ports-switch.png)

### Server detail
![Server](https://raw.githubusercontent.com/Spillebulle/homelab-manger/main/docs/Server.png)

### UPS — power history graphs
![UPS graphs](https://raw.githubusercontent.com/Spillebulle/homelab-manger/main/docs/UPS-graphs.png)

---

## Features

- **Switches** — D-Link DGS-3120 (SNMP + SSH), HPE OfficeConnect 1820 (SNMP + web UI), and generic SNMP. Port status, PoE control, VLAN management, and connected-device discovery (FDB/ARP with OUI vendor lookup).
- **Servers / BMCs** — HP iLO, Dell iDRAC, Huawei iBMC (Redfish), and Cisco UCS C-series (CIMC XMLAPI/IPMI on ≤ 2.x, Redfish on 3.0+). Inventory, sensors, power draw, power actions, and one-click Java KVM launch.
- **UPS** — USB-connected UPSes via the standard HID Power Device class (no NUT needed). Live status, history graphs, and **outage orchestration**: automatically and gracefully shut down selected devices when the UPS goes on battery and a threshold is crossed.
- **Events & notifications** — an event log (offline/online, UPS state, shutdown actions) with optional per-device Discord webhooks.
- **JSON API** — everything the UI does, plus API keys and a charting-friendly `/graph` endpoint for Grafana / Metabase / etc. See [docs/API.md](docs/API.md).
- **One process** — FastAPI serving the JSON API and a static SPA (Tailwind + Alpine.js, no build step), backed by SQLite. Credentials are encrypted at rest; auth is a single-user cookie session.

---

> **Homelab use only.** Device credentials are encrypted at rest (Fernet), but the key lives next to the database, the app is single-user with no rate limiting, and HTTPS is opt-in — so it's still built for a trusted network. Don't expose it to anyone you don't trust.

## Install

The recommended way is the pre-built container — it includes every Python dependency, runs on amd64 *and* arm64, and is published for every tagged release (to both GHCR and Docker Hub).

### Option 1 — GitHub Container Registry (GHCR)

```bash
docker run -d --name homelab-manger \
  -p 8080:8080 \
  -e ADMIN_PASSWORD=pick-something \
  -v homelab-data:/data \
  --privileged -v /dev:/dev:ro \
  ghcr.io/spillebulle/homelab-manger:latest
```

### Option 2 — Docker Hub

```bash
docker run -d --name homelab-manger \
  -p 8080:8080 \
  -e ADMIN_PASSWORD=pick-something \
  -v homelab-data:/data \
  --privileged -v /dev:/dev:ro \
  spillebulle/homelab-manger:latest
```

> Both registries serve the same image. Pin a version (e.g. `:v0.5.7`) in production instead of `:latest`.
>
> **The `--privileged -v /dev:/dev:ro` line is only needed if you monitor a USB-connected UPS** (the `usbups` adapter) — it lets the container reach the UPS's `/dev/hidrawN` node, which changes when the UPS re-enumerates. Bind the **whole** `/dev` (not just `/dev/bus/usb`); read-only (`:ro`) is enough. Omit the line entirely for network-only devices (switches, servers, BMCs).

### Option 3 — Build the image locally

```bash
git clone https://github.com/Spillebulle/homelab-manger.git
cd homelab-manger
docker build -t homelab-manger .
docker run -d --name homelab-manger \
  -p 8080:8080 -e ADMIN_PASSWORD=pick-something -v homelab-data:/data \
  homelab-manger
```

### Option 4 — Run from source (no Docker)

```powershell
pip install -r requirements.txt
$env:ADMIN_PASSWORD = "pick-something"
$env:DB_PATH = "$PWD\homelab.db"   # default is /data/homelab.db on Linux
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8080
```

### First sign-in

Open <http://localhost:8080>. Username is `admin`. The password is whatever you set in `ADMIN_PASSWORD` on first start; if you didn't set it, the default is `changeme` and the app logs a warning. Change it from the key icon in the sidebar.

The `/data` volume holds the SQLite database, the session-cookie secret, and the credential-encryption key — keep it across restarts so users stay logged in, the admin password isn't reset, and stored device credentials stay decryptable.

## Configuration

| Env var | Purpose |
|---|---|
| `DB_PATH` | SQLite path. Default `/data/homelab.db`. |
| `ADMIN_USERNAME` | Initial admin username. Default `admin`. Only read on first start (when `auth_users` is empty). |
| `ADMIN_PASSWORD` | Initial admin password. Default `changeme` (with a startup warning). Only read on first start. |
| `SESSION_SECRET` | Cookie-signing secret. Auto-generated and persisted next to the DB if unset. |
| `CREDENTIAL_KEY` | Fernet key used to encrypt device credentials at rest. Auto-generated and persisted next to the DB if unset (changing/losing it makes existing credentials undecryptable). |
| `POLL_INTERVAL` | Default seconds between background polls. Default `60`; per-device overrides are set in the UI. |
| `METRICS_RETENTION_DAYS` | Days of time-series history kept for graphs. Default `30`; `0` = unbounded. |
| `PORT` | Port uvicorn listens on inside the container. Default `8080`. Pair with a matching `-p host:container` if you override. |

## API

Everything the web UI does is exposed over a JSON API, gated by either a cookie
session or an API key (`Authorization: Bearer hlm_...` / `X-API-Key`). Create keys
from the account area (the `</>` icon) or `POST /api/api-keys`.

See **[docs/API.md](docs/API.md)** for the full reference — authentication, every
endpoint, device action vocabulary, credential keys, and curl examples.

```bash
curl -s http://homelab.lan:8080/api/devices -H "Authorization: Bearer hlm_your_key"
```

For dashboards (Grafana, Metabase, …) point your charting tool at the
graph endpoint — a flat array of time-series points with proper UTC timestamps:

```bash
curl -s "http://homelab.lan:8080/api/devices/7/graph?metrics=watts,load_pct&hours=24" \
  -H "Authorization: Bearer hlm_your_key"
```

## Resetting the admin password

There's no "forgot password" flow. To reset:

```powershell
# Stop the app, then:
python -c "import sqlite3; sqlite3.connect(r'$PWD\homelab.db').execute('DELETE FROM auth_users').connection.commit()"
$env:ADMIN_PASSWORD = "new-password"
# Start the app — it'll re-bootstrap the admin user.
```

If you're running in Docker, attach to the volume and delete the row from the SQLite file the same way (or just remove the volume to start fresh).

## Project layout

```
backend/
  main.py          FastAPI routes (devices, actions, events, API keys, graph) + auth wiring
  auth.py          bcrypt password hashing, cookie sessions, API-key auth
  poller.py        Background asyncio poll loop (1 task per device) + outage orchestration
  models.py        SQLAlchemy models (devices, cache, metrics, events, shutdown rules, notifications, auth, API keys)
  adapters/        Per-vendor device drivers (snmp, dlink, hpe1820, cimc, cimc_redfish, redfish, usbups)
  events.py        Event log + Discord notification dispatch
  credentials_crypto.py   Fernet encryption of stored credentials
frontend/
  index.html       SPA (Tailwind + Alpine.js, no build step)
  login.html       Standalone login page
  static/          Logo + any other public static assets
docs/
  API.md           Full HTTP API reference
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
