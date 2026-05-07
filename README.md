# HomeLab Manager

Single-process FastAPI app for managing homelab gear — switches (D-Link, generic SNMP), servers (Cisco CIMC, Dell iDRAC, HPE iLO, Huawei iBMC via Redfish), and anything else with an SNMP / SSH / Redfish / IPMI surface. JSON API + a static SPA in one binary.

> **Homelab use only.** Device credentials are stored as plaintext JSON in the SQLite DB. Don't deploy this anywhere it can be reached by anyone you don't trust.

## Run

```powershell
# Install
pip install -r requirements.txt

# First start — sets initial admin password
$env:ADMIN_PASSWORD = "pick-something"
$env:DB_PATH = "$PWD\homelab.db"   # default is /data/homelab.db (Linux/container)
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8080
```

Then open http://localhost:8080. Default username is `admin`. If you didn't set `ADMIN_PASSWORD` before the very first start, the password is `changeme` — change it from the sidebar key icon.

## Container

```bash
docker build -t homelab-manager .
docker run -d -p 8080:8080 \
  -e ADMIN_PASSWORD=pick-something \
  -v homelab-data:/data \
  homelab-manager
```

The `/data` volume holds the SQLite DB and the session-cookie secret, so restarts don't log you out and don't reset the admin password.

## Configuration

| Env var | Purpose |
|---|---|
| `DB_PATH` | SQLite path. Default `/data/homelab.db`. |
| `ADMIN_USERNAME` | Initial admin username. Default `admin`. Only read on first start (when `auth_users` is empty). |
| `ADMIN_PASSWORD` | Initial admin password. Default `changeme` (with a startup warning). Only read on first start. |
| `SESSION_SECRET` | Cookie-signing secret. Auto-generated and persisted next to the DB if unset. |
| `POLL_INTERVAL` | Seconds between background polls. Default `60`. |

## Resetting the admin password

There's no "forgot password" flow. To reset:

```powershell
# Stop the app, then:
python -c "import sqlite3; sqlite3.connect(r'$PWD\homelab.db').execute('DELETE FROM auth_users').connection.commit()"
$env:ADMIN_PASSWORD = "new-password"
# Start the app — it'll re-bootstrap the admin user.
```

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
```

See `CLAUDE.md` for the architectural deep-dive, vendor quirks (especially D-Link DGS-3120 and Cisco CIMC 2.0(9f)), and the things-that-look-wrong-but-aren't catalog.

## License

No license declared — treat as all-rights-reserved by default. Add a `LICENSE` file before sharing publicly.
