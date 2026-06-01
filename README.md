<p align="center">
  <img src="https://raw.githubusercontent.com/Spillebulle/homelab-manger/main/frontend/static/logo.png" alt="HomeLab Manger" width="120">
</p>

<h1 align="center">HomeLab Manger</h1>

<p align="center">
  Single-process FastAPI app for managing homelab gear — switches (D-Link, generic SNMP), servers (Cisco CIMC, Dell iDRAC, HPE iLO, Huawei iBMC via Redfish), and anything else with an SNMP / SSH / Redfish / IPMI surface. JSON API + a static SPA in one binary.
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

---

> **Homelab use only.** Device credentials are stored as plaintext JSON in the SQLite DB. Don't deploy this anywhere reachable by anyone you don't trust.

## Install

The recommended way is the pre-built container — it includes every Python dependency, runs on amd64 *and* arm64, and is rebuilt on every push to `main`.

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

> Both registries serve the same image. Pin a version (e.g. `:v0.1.0`) in production instead of `:latest`.
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

The `/data` volume holds the SQLite database and the session-cookie secret — keep it across restarts so users stay logged in and the admin password isn't reset.

## Configuration

| Env var | Purpose |
|---|---|
| `DB_PATH` | SQLite path. Default `/data/homelab.db`. |
| `ADMIN_USERNAME` | Initial admin username. Default `admin`. Only read on first start (when `auth_users` is empty). |
| `ADMIN_PASSWORD` | Initial admin password. Default `changeme` (with a startup warning). Only read on first start. |
| `SESSION_SECRET` | Cookie-signing secret. Auto-generated and persisted next to the DB if unset. |
| `POLL_INTERVAL` | Seconds between background polls. Default `60`. |
| `PORT` | Port uvicorn listens on inside the container. Default `8080`. Pair with a matching `-p host:container` if you override. |

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
  main.py          FastAPI routes + auth wiring
  auth.py          bcrypt hashing, session bootstrap
  poller.py        Background asyncio poll loop, 1 task per device
  models.py        SQLAlchemy models (devices, device_cache, auth_users)
  adapters/        Per-vendor device drivers (snmp, dlink, cimc, redfish, …)
frontend/
  index.html       SPA (Tailwind + Alpine.js, no build step)
  login.html       Standalone login page
  static/          Logo + any other public static assets
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
