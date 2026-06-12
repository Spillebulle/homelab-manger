"""Service publishing orchestration: DNS record → NPM proxy host → SSL cert.

`provision_service` runs as a fire-and-forget asyncio task (the HTTP handler
returns immediately; the SPA follows progress via the `service_updated`
WebSocket broadcasts and polling). Each step commits its own status so a
crash mid-pipeline leaves an accurate partial state, and re-running skips
steps already marked `ok` - retry is just "run it again".

Step order matters: the DNS record must exist before the certificate step,
because NPM's Let's Encrypt HTTP-01 challenge requires the fqdn to resolve
publicly. The proxy host is created WITHOUT a cert first, then the cert is
issued and attached - so a failed/slow issuance leaves a working HTTP proxy
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
from .services_portainer import (
    PortainerClient, endpoint_host_ip, host_from_url, looks_like_ip,
)

logger = logging.getLogger(__name__)

# Required config keys per integration (everything is a string; secrets are
# in INTEGRATION_SECRET_KEYS and get the blank-keeps-existing PUT treatment).
NPM_REQUIRED = ("base_url", "email", "password", "le_email")
NC_REQUIRED = ("api_user", "api_key", "username", "client_ip", "domain")
PORTAINER_REQUIRED = ("base_url", "api_key")
INTEGRATION_REQUIRED = {"npm": NPM_REQUIRED, "namecheap": NC_REQUIRED,
                        "portainer": PORTAINER_REQUIRED}
INTEGRATION_SECRET_KEYS = {"npm": {"password"}, "namecheap": {"api_key"},
                           "portainer": {"api_key"}}

_CERT_ATTEMPTS = 3
_CERT_RETRY_DELAY = 25  # seconds between Let's Encrypt attempts (DNS propagation)

# Guards against double-provisioning the same service (e.g. create + an
# impatient retry click). In-memory is fine - single process.
_in_flight: set[int] = set()


def get_integration_config(db: Session, name: str) -> dict:
    row = db.query(Integration).filter(Integration.name == name).first()
    return dict(row.config or {}) if row else {}


def integration_configured(name: str, cfg: dict) -> bool:
    required = INTEGRATION_REQUIRED.get(name, ())
    return all(str(cfg.get(k) or "").strip() for k in required)


def npm_client(cfg: dict) -> NPMClient:
    return NPMClient(cfg["base_url"], cfg["email"], cfg["password"])


def nc_client(cfg: dict) -> NamecheapClient:
    return NamecheapClient(cfg["api_user"], cfg["api_key"], cfg["username"],
                           cfg["client_ip"])


def portainer_client(cfg: dict) -> PortainerClient:
    return PortainerClient(cfg["base_url"], cfg["api_key"])


def docker_host_ip(cfg: dict) -> str | None:
    """The LAN address NPM should forward to for containers on the LOCAL
    (socket) Portainer environment. Portainer's API doesn't expose the host
    machine's LAN IP, so the explicit `docker_host_ip` config is the source
    of truth. Fallback to the Portainer URL's host only when that host is an
    IP literal: a hostname there (reverse-proxied Portainer, mDNS name) is
    usually NOT what NPM should forward to, and a wrong suggestion is worse
    than none."""
    explicit = str(cfg.get("docker_host_ip") or "").strip()
    if explicit:
        return explicit
    url_host = host_from_url(cfg.get("base_url", ""))
    return url_host if looks_like_ip(url_host) else None


# NPM toggle groups, derived from the service row. SSL toggles are only
# meaningful once a certificate is attached (NPM rejects ssl_forced on a
# cert-less host), so they're applied by the cert step / settings sync, not
# at proxy-host creation.
def _npm_opts(svc: Service) -> dict:
    return {
        "allow_websocket_upgrade": bool(svc.websockets),
        "block_exploits": bool(svc.block_exploits),
        "caching_enabled": bool(svc.caching_enabled),
    }


def _ssl_opts(svc: Service) -> dict:
    return {
        "ssl_forced": bool(svc.ssl_forced),
        "http2_support": bool(svc.http2_support),
        "hsts_enabled": bool(svc.hsts_enabled),
        # NPM requires HSTS itself before subdomains can be on.
        "hsts_subdomains": bool(svc.hsts_subdomains and svc.hsts_enabled),
    }


async def list_portainer_containers(db: Session) -> list[dict]:
    """Containers across ALL Portainer environments (or just the configured
    `endpoint_id` when set), each annotated with its environment and that
    environment's Docker-host IP (from the endpoint's own URL - agent
    endpoints run on different machines). Suggested forward target per
    container: the endpoint's host IP + first published port when ports are
    published, else the container's first network IP + first exposed port
    (reachable only if NPM shares a Docker network with it)."""
    cfg = get_integration_config(db, "portainer")
    if not integration_configured("portainer", cfg):
        raise ValueError("Portainer integration is not configured")
    client = portainer_client(cfg)
    fallback_ip = docker_host_ip(cfg)
    try:
        only_endpoint = int(cfg.get("endpoint_id") or 0)
    except (TypeError, ValueError):
        only_endpoint = 0

    endpoints = await client.endpoints()
    if only_endpoint:
        endpoints = [e for e in endpoints if e.get("Id") == only_endpoint]
    if not endpoints:
        raise ValueError("No matching Portainer environments found")

    out: list[dict] = []
    for ep in endpoints:
        host_ip = endpoint_host_ip(ep, fallback_ip)
        try:
            containers = await client.containers(ep["Id"])
        except Exception as exc:
            # One offline environment shouldn't blank the whole dropdown.
            logger.warning("Portainer environment %s unreachable: %s", ep.get("Name"), exc)
            continue
        for c in containers:
            c["endpoint_id"] = ep["Id"]
            c["endpoint_name"] = ep.get("Name")
            c["host_ip"] = host_ip
            published = [p for p in c["ports"] if p.get("public")]
            if published:
                c["suggested_host"] = host_ip
                c["suggested_port"] = published[0]["public"]
            else:
                c["suggested_host"] = next(iter(c["networks"].values()), None)
                c["suggested_port"] = c["ports"][0]["private"] if c["ports"] else None
        out.extend(containers)
    out.sort(key=lambda c: c["name"].lower())
    return out


def match_container(containers: list[dict], forward_host: str,
                    forward_port: int) -> dict | None:
    """Best-effort guess of which container a forward target points at.
    Containers carry their own environment's `host_ip`, so the strongest
    signal is per-container: its Docker host's IP + a matching published
    port. Then a container network IP, then the container's name (NPM on the
    same Docker network resolves names)."""
    fh = str(forward_host or "").strip().lower()
    if not fh:
        return None
    for c in containers:
        if (c.get("host_ip") or "").lower() == fh and \
                any(p.get("public") == forward_port for p in c["ports"]):
            return c
    for c in containers:
        if fh in (ip.lower() for ip in c["networks"].values()):
            return c
    for c in containers:
        if fh == c["name"].lower():
            return c
    return None


async def find_portainer_match(db: Session, forward_host: str,
                               forward_port: int) -> tuple[str | None, int | None]:
    """(container_name, endpoint_id) guess for a forward target - used by NPM
    import to auto-link. Best-effort: any Portainer hiccup returns no match."""
    try:
        containers = await list_portainer_containers(db)
    except Exception as exc:
        logger.debug("Portainer match skipped: %s", exc)
        return None, None
    c = match_container(containers, forward_host, forward_port)
    return (c["name"], c["endpoint_id"]) if c else (None, None)


def dns_record_plan(cfg: dict) -> tuple[str, str, int]:
    """(record_type, target, ttl) for new DNS records. Default: CNAME to the
    domain root - the root already resolves to the public IP, so every new
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

        # ── Step 2: proxy host (NPM) ───────────────────────────────────────
        # Create/adopt when we don't hold a host id yet; otherwise push the
        # service's current settings (forward target + toggles) onto the
        # host. Running the sync on every pipeline pass is what makes "edit a
        # service" just be "update the row, re-run the pipeline".
        npm = None
        if not integration_configured("npm", npm_cfg):
            svc.npm_status, svc.npm_detail = "error", "NPM integration is not configured"
        else:
            npm = npm_client(npm_cfg)
            try:
                if svc.npm_proxy_host_id is not None:
                    overrides = {
                        "forward_scheme": svc.forward_scheme,
                        "forward_host": svc.forward_host,
                        "forward_port": int(svc.forward_port),
                        **_npm_opts(svc),
                    }
                    # SSL toggles only once a cert is attached - NPM rejects
                    # ssl_forced on a cert-less host. domain_names are NOT
                    # synced here (imported hosts may serve extra domains;
                    # renames handle domains in the PUT handler).
                    if svc.cert_status == "ok":
                        overrides.update(_ssl_opts(svc))
                    try:
                        await npm.update_proxy_host(svc.npm_proxy_host_id, overrides)
                        svc.npm_detail = f"Settings synced to proxy host #{svc.npm_proxy_host_id}"
                    except NPMError as exc:
                        if "404" not in str(exc):
                            raise
                        # Host was deleted behind our back - recreate below.
                        svc.npm_proxy_host_id = None
                if svc.npm_proxy_host_id is None:
                    existing = await npm.find_proxy_host(fqdn)
                    if existing:
                        svc.npm_proxy_host_id = existing["id"]
                        svc.npm_detail = f"Adopted existing proxy host #{existing['id']}"
                        # The existing host may already carry a cert (manual
                        # setup). Mark the step done but DON'T store the cert
                        # id - npm_certificate_id is "cert we created and may
                        # delete on cleanup", and a pre-existing cert can be
                        # shared (e.g. a wildcard) with other proxy hosts.
                        if existing.get("certificate_id"):
                            svc.cert_status = "ok"
                            svc.cert_detail = (f"Certificate #{existing['certificate_id']} "
                                               "already attached (pre-existing, left alone on delete)")
                    else:
                        created = await npm.create_proxy_host(
                            fqdn, svc.forward_scheme, svc.forward_host,
                            svc.forward_port, _npm_opts(svc))
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
                await npm.attach_certificate(svc.npm_proxy_host_id, cert["id"],
                                             _ssl_opts(svc))
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
        logger.info("SERVICE %s: provisioning finished - %s (dns=%s npm=%s cert=%s)",
                    fqdn, svc.state, svc.dns_status, svc.npm_status, svc.cert_status)
        await _broadcast(on_update, service_id)
    except Exception:
        logger.exception("provision_service(%d) crashed", service_id)
    finally:
        db.close()
        _in_flight.discard(service_id)


async def import_npm_host(db: Session, npm_proxy_host_id: int,
                          overrides: dict | None = None) -> Service:
    """Take an existing NPM proxy host under management as a Service row.
    `overrides` carries the user's edits from the import modal (name, forward
    target, toggles, Portainer link) and wins over the host's current values;
    the caller then runs the pipeline, whose sync step pushes any differences
    back to NPM (and issues a cert if the host doesn't have one).

    DNS is assumed pre-existing (`dns_record_type` stays NULL, so deleting
    the service later won't touch a record we didn't create). The host's
    pre-existing cert is honored but never owned (npm_certificate_id stays
    NULL - it could be shared, e.g. a wildcard).

    Raises ValueError with a user-facing message on anything invalid."""
    overrides = overrides or {}
    npm_cfg = get_integration_config(db, "npm")
    if not integration_configured("npm", npm_cfg):
        raise ValueError("Configure the Nginx Proxy Manager integration first")

    if db.query(Service).filter(Service.npm_proxy_host_id == npm_proxy_host_id).first():
        raise ValueError("That proxy host is already managed by a service")

    host = await npm_client(npm_cfg).get_proxy_host(npm_proxy_host_id)
    domains = host.get("domain_names") or []
    if not domains:
        raise ValueError("Proxy host has no domain names")
    fqdn = str(domains[0]).lower()
    if "." not in fqdn:
        raise ValueError(f"Can't derive subdomain/domain from {fqdn!r}")
    subdomain, domain = fqdn.split(".", 1)

    if db.query(Service).filter(Service.subdomain == subdomain,
                                Service.domain == domain).first():
        raise ValueError(f"A service for {fqdn} already exists")

    extra = f" (+{len(domains) - 1} more domain(s) on the same host)" if len(domains) > 1 else ""
    has_cert = bool(host.get("certificate_id"))

    # Portainer link: an explicit choice from the modal (including "none")
    # wins; otherwise best-effort auto-match by forward target.
    if "portainer_container" in overrides:
        container = (overrides.get("portainer_container") or "").strip() or None
        endpoint_id = overrides.get("portainer_endpoint_id") if container else None
    else:
        container, endpoint_id = await find_portainer_match(
            db, host.get("forward_host") or "", int(host.get("forward_port") or 0))

    def pick(key: str, host_value):
        return overrides[key] if key in overrides else host_value

    svc = Service(
        name=(str(pick("name", "")).strip() or subdomain),
        subdomain=subdomain,
        domain=domain,
        forward_scheme=pick("forward_scheme", host.get("forward_scheme") or "http"),
        forward_host=str(pick("forward_host", host.get("forward_host") or "")).strip(),
        forward_port=int(pick("forward_port", host.get("forward_port") or 80)),
        websockets=bool(pick("websockets", host.get("allow_websocket_upgrade"))),
        block_exploits=bool(pick("block_exploits", host.get("block_exploits"))),
        caching_enabled=bool(pick("caching_enabled", host.get("caching_enabled"))),
        ssl_forced=bool(pick("ssl_forced", host.get("ssl_forced") if has_cert else True)),
        http2_support=bool(pick("http2_support", host.get("http2_support") if has_cert else True)),
        hsts_enabled=bool(pick("hsts_enabled", host.get("hsts_enabled"))),
        hsts_subdomains=bool(pick("hsts_subdomains", host.get("hsts_subdomains"))),
        portainer_container=container,
        portainer_endpoint_id=endpoint_id,
        npm_proxy_host_id=npm_proxy_host_id,
        npm_status="ok",
        npm_detail=f"Imported existing proxy host #{npm_proxy_host_id}{extra}",
        dns_status="ok",
        dns_detail="Pre-existing DNS (not created by this app - left alone on delete)",
        cert_status="ok" if has_cert else "pending",
        cert_detail=(f"Certificate #{host['certificate_id']} attached "
                     "(pre-existing, left alone on delete)") if has_cert
                    else "No certificate attached yet",
        state="pending",
    )
    db.add(svc)
    db.commit()
    db.refresh(svc)
    logger.info("SERVICE %s: imported from NPM proxy host #%d", fqdn, npm_proxy_host_id)
    return svc


async def deprovision_service(svc: Service, db: Session) -> list[str]:
    """Best-effort cleanup of everything provisioning created: proxy host,
    certificate, DNS record (only the exact record we wrote - type + target
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
            errors.append("NPM integration not configured - proxy host left in place")

    if svc.dns_status == "ok" and svc.dns_record_type:
        if integration_configured("namecheap", nc_cfg):
            try:
                await nc_client(nc_cfg).remove_record(
                    svc.domain, svc.subdomain, svc.dns_record_type,
                    svc.dns_record_target)
            except Exception as exc:
                errors.append(f"Namecheap DNS record: {exc}")
        else:
            errors.append("Namecheap integration not configured - DNS record left in place")

    return errors
