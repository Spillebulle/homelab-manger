"""Service publishing orchestration: DNS record → NPM proxy host → SSL cert.

`provision_service` runs as a fire-and-forget asyncio task (the HTTP handler
returns immediately; the SPA follows progress via the `service_updated`
WebSocket broadcasts and polling). Each step commits its own status so a
crash mid-pipeline leaves an accurate partial state, and re-running skips
steps already marked `ok` — retry is just "run it again".

Step order matters: the DNS record must exist before the certificate step,
because NPM's Let's Encrypt HTTP-01 challenge requires the fqdn to resolve
publicly. The proxy host is created WITHOUT a cert first, then the cert is
issued and attached — so a failed/slow issuance leaves a working HTTP proxy
behind instead of nothing. Cert issuance is retried a few times with a delay
to ride out DNS propagation to Namecheap's authoritative servers (usually
seconds, occasionally a minute or two).
"""
import asyncio
import logging

from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Integration, Service
from .services_namecheap import NamecheapClient
from .services_npm import NPMClient, NPMError

logger = logging.getLogger(__name__)

# Required config keys per integration (everything is a string; secrets are
# in INTEGRATION_SECRET_KEYS and get the blank-keeps-existing PUT treatment).
NPM_REQUIRED = ("base_url", "email", "password", "le_email")
NC_REQUIRED = ("api_user", "api_key", "username", "client_ip", "domain")
INTEGRATION_SECRET_KEYS = {"npm": {"password"}, "namecheap": {"api_key"}}

_CERT_ATTEMPTS = 3
_CERT_RETRY_DELAY = 25  # seconds between Let's Encrypt attempts (DNS propagation)

# Guards against double-provisioning the same service (e.g. create + an
# impatient retry click). In-memory is fine — single process.
_in_flight: set[int] = set()


def get_integration_config(db: Session, name: str) -> dict:
    row = db.query(Integration).filter(Integration.name == name).first()
    return dict(row.config or {}) if row else {}


def integration_configured(name: str, cfg: dict) -> bool:
    required = NPM_REQUIRED if name == "npm" else NC_REQUIRED
    return all(str(cfg.get(k) or "").strip() for k in required)


def npm_client(cfg: dict) -> NPMClient:
    return NPMClient(cfg["base_url"], cfg["email"], cfg["password"])


def nc_client(cfg: dict) -> NamecheapClient:
    return NamecheapClient(cfg["api_user"], cfg["api_key"], cfg["username"],
                           cfg["client_ip"])


def dns_record_plan(cfg: dict) -> tuple[str, str, int]:
    """(record_type, target, ttl) for new DNS records. Default: CNAME to the
    domain root — the root already resolves to the public IP, so every new
    subdomain follows it automatically (including if the IP ever changes)."""
    rtype = (cfg.get("record_type") or "CNAME").strip().upper()
    target = str(cfg.get("record_target") or "").strip() or cfg["domain"]
    try:
        ttl = max(60, int(cfg.get("ttl") or 300))
    except (TypeError, ValueError):
        ttl = 300
    return rtype, target, ttl


async def _broadcast(on_update, service_id: int) -> None:
    if on_update is None:
        return
    try:
        await on_update({"event": "service_updated", "service_id": service_id})
    except Exception as exc:
        logger.debug("service_updated broadcast failed: %s", exc)


def service_provisioning(service_id: int) -> bool:
    return service_id in _in_flight


async def provision_service(service_id: int, on_update=None) -> None:
    if service_id in _in_flight:
        return
    _in_flight.add(service_id)
    db = SessionLocal()
    try:
        svc = db.query(Service).filter(Service.id == service_id).first()
        if svc is None:
            return
        svc.state = "provisioning"
        db.commit()
        await _broadcast(on_update, service_id)

        npm_cfg = get_integration_config(db, "npm")
        nc_cfg = get_integration_config(db, "namecheap")
        fqdn = f"{svc.subdomain}.{svc.domain}"

        # ── Step 1: DNS record (Namecheap) ────────────────────────────────
        if svc.dns_status != "ok":
            if not integration_configured("namecheap", nc_cfg):
                svc.dns_status, svc.dns_detail = "error", "Namecheap integration is not configured"
            else:
                try:
                    rtype, target, ttl = dns_record_plan(nc_cfg)
                    outcome = await nc_client(nc_cfg).ensure_record(
                        svc.domain, svc.subdomain, rtype, target, ttl)
                    svc.dns_record_type, svc.dns_record_target = rtype, target
                    svc.dns_status = "ok"
                    svc.dns_detail = f"{rtype} {fqdn} → {target} ({outcome})"
                except Exception as exc:
                    svc.dns_status, svc.dns_detail = "error", str(exc)
                    logger.warning("SERVICE %s: DNS step failed: %s", fqdn, exc)
            db.commit()
            await _broadcast(on_update, service_id)

        # ── Step 2: proxy host (NPM), no cert yet ─────────────────────────
        npm = None
        if svc.npm_status != "ok":
            if not integration_configured("npm", npm_cfg):
                svc.npm_status, svc.npm_detail = "error", "NPM integration is not configured"
            else:
                try:
                    npm = npm_client(npm_cfg)
                    existing = await npm.find_proxy_host(fqdn)
                    if existing:
                        svc.npm_proxy_host_id = existing["id"]
                        svc.npm_detail = f"Adopted existing proxy host #{existing['id']}"
                        # The existing host may already carry a cert (manual setup).
                        if existing.get("certificate_id"):
                            svc.npm_certificate_id = existing["certificate_id"]
                            svc.cert_status = "ok"
                            svc.cert_detail = f"Certificate #{existing['certificate_id']} already attached"
                    else:
                        created = await npm.create_proxy_host(
                            fqdn, svc.forward_scheme, svc.forward_host,
                            svc.forward_port, bool(svc.websockets))
                        svc.npm_proxy_host_id = created["id"]
                        svc.npm_detail = (f"Proxy host #{created['id']}: {fqdn} → "
                                          f"{svc.forward_scheme}://{svc.forward_host}:{svc.forward_port}")
                    svc.npm_status = "ok"
                except Exception as exc:
                    svc.npm_status, svc.npm_detail = "error", str(exc)
                    logger.warning("SERVICE %s: NPM step failed: %s", fqdn, exc)
            db.commit()
            await _broadcast(on_update, service_id)

        # ── Step 3: Let's Encrypt cert, attached to the proxy host ────────
        # Requires both prior steps: the DNS record for the HTTP-01 challenge
        # to resolve, and the proxy host to attach the cert to.
        if svc.npm_status == "ok" and svc.dns_status == "ok" and svc.cert_status != "ok":
            try:
                if npm is None:
                    npm = npm_client(npm_cfg)
                cert = await npm.find_certificate(fqdn)
                if cert is None:
                    last_exc: Exception | None = None
                    for attempt in range(1, _CERT_ATTEMPTS + 1):
                        try:
                            cert = await npm.create_certificate(fqdn, npm_cfg["le_email"])
                            break
                        except NPMError as exc:
                            last_exc = exc
                            logger.warning("SERVICE %s: cert attempt %d/%d failed: %s",
                                           fqdn, attempt, _CERT_ATTEMPTS, exc)
                            if attempt < _CERT_ATTEMPTS:
                                await asyncio.sleep(_CERT_RETRY_DELAY)
                    if cert is None:
                        raise last_exc or NPMError("certificate creation failed")
                await npm.attach_certificate(
                    svc.npm_proxy_host_id, cert["id"], fqdn, svc.forward_scheme,
                    svc.forward_host, svc.forward_port, bool(svc.websockets))
                svc.npm_certificate_id = cert["id"]
                svc.cert_status = "ok"
                svc.cert_detail = f"Let's Encrypt certificate #{cert['id']} attached, HTTPS forced"
            except Exception as exc:
                svc.cert_status, svc.cert_detail = "error", str(exc)
                logger.warning("SERVICE %s: certificate step failed: %s", fqdn, exc)
            db.commit()
            await _broadcast(on_update, service_id)

        all_ok = (svc.dns_status == "ok" and svc.npm_status == "ok"
                  and svc.cert_status == "ok")
        svc.state = "active" if all_ok else "error"
        db.commit()
        logger.info("SERVICE %s: provisioning finished — %s (dns=%s npm=%s cert=%s)",
                    fqdn, svc.state, svc.dns_status, svc.npm_status, svc.cert_status)
        await _broadcast(on_update, service_id)
    except Exception:
        logger.exception("provision_service(%d) crashed", service_id)
    finally:
        db.close()
        _in_flight.discard(service_id)


async def deprovision_service(svc: Service, db: Session) -> list[str]:
    """Best-effort cleanup of everything provisioning created: proxy host,
    certificate, DNS record (only the exact record we wrote — type + target
    were snapshotted on the row at provision time). Returns a list of
    human-readable errors; empty means everything that existed was removed."""
    errors: list[str] = []
    npm_cfg = get_integration_config(db, "npm")
    nc_cfg = get_integration_config(db, "namecheap")

    if svc.npm_proxy_host_id is not None:
        if integration_configured("npm", npm_cfg):
            npm = npm_client(npm_cfg)
            try:
                await npm.delete_proxy_host(svc.npm_proxy_host_id)
            except Exception as exc:
                errors.append(f"NPM proxy host #{svc.npm_proxy_host_id}: {exc}")
            if svc.npm_certificate_id is not None:
                try:
                    await npm.delete_certificate(svc.npm_certificate_id)
                except Exception as exc:
                    errors.append(f"NPM certificate #{svc.npm_certificate_id}: {exc}")
        else:
            errors.append("NPM integration not configured — proxy host left in place")

    if svc.dns_status == "ok" and svc.dns_record_type:
        if integration_configured("namecheap", nc_cfg):
            try:
                await nc_client(nc_cfg).remove_record(
                    svc.domain, svc.subdomain, svc.dns_record_type,
                    svc.dns_record_target)
            except Exception as exc:
                errors.append(f"Namecheap DNS record: {exc}")
        else:
            errors.append("Namecheap integration not configured — DNS record left in place")

    return errors
