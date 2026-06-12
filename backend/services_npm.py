"""Async client for the Nginx Proxy Manager REST API.

This is the same API NPM's own web UI uses (there is no separate "public"
API): authenticate with the admin email/password at POST /api/tokens, then
send the JWT as a Bearer token. Instances are short-lived (one per request /
provisioning run), so token expiry (default 1 day) isn't handled — a fresh
client gets a fresh token.

Certificate creation (`create_certificate`) blocks server-side while NPM runs
certbot's HTTP-01 challenge — typically 15-60 s — hence the long per-call
timeout. A failure there usually means the DNS record hasn't propagated to
Namecheap's authoritative servers yet or port 80 isn't reachable from the
internet; the provisioning pipeline retries with a delay for the former.
"""
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_CERT_TIMEOUT = 300.0  # certbot HTTP-01 round-trip happens inside this call


class NPMError(Exception):
    """Any NPM API failure, with a human-readable message."""


def _err_detail(resp: httpx.Response) -> str:
    """Pull the message out of NPM's error envelope ({"error": {"message"}})
    with fallbacks for the other shapes it occasionally returns."""
    try:
        data = resp.json()
        if isinstance(data, dict):
            err = data.get("error")
            if isinstance(err, dict) and err.get("message"):
                return str(err["message"])
            if data.get("message"):
                return str(data["message"])
            if data.get("detail"):
                return str(data["detail"])
    except Exception:
        pass
    return f"HTTP {resp.status_code}"


class NPMClient:
    def __init__(self, base_url: str, email: str, password: str, timeout: float = 30.0):
        self.base_url = (base_url or "").rstrip("/")
        self.email = email
        self.password = password
        self.timeout = timeout
        self._token: str | None = None

    async def _login(self) -> None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as c:
                r = await c.post(f"{self.base_url}/api/tokens",
                                 json={"identity": self.email, "secret": self.password})
        except httpx.HTTPError as exc:
            raise NPMError(f"Cannot reach NPM at {self.base_url}: {exc}") from exc
        if r.status_code != 200:
            raise NPMError(f"NPM login failed: {_err_detail(r)}")
        token = r.json().get("token")
        if not token:
            raise NPMError("NPM login returned no token")
        self._token = token

    async def _request(self, method: str, path: str, json_body: Any = None,
                       timeout: float | None = None) -> Any:
        if self._token is None:
            await self._login()
        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout or self.timeout) as c:
                r = await c.request(method, f"{self.base_url}/api{path}",
                                    json=json_body,
                                    headers={"Authorization": f"Bearer {self._token}"})
        except httpx.HTTPError as exc:
            raise NPMError(f"NPM request failed ({method} {path}): {exc}") from exc
        if r.status_code >= 400:
            raise NPMError(f"NPM {method} {path}: {_err_detail(r)}")
        if r.status_code == 204 or not r.content:
            return None
        return r.json()

    # ── probes ────────────────────────────────────────────────────────────

    async def test(self) -> dict:
        """Login + list proxy hosts. The cheapest call that proves both the
        credentials and the API path are right."""
        hosts = await self.list_proxy_hosts()
        return {"ok": True, "detail": f"Connected — {len(hosts)} proxy host(s) configured"}

    # ── proxy hosts ───────────────────────────────────────────────────────

    async def list_proxy_hosts(self) -> list[dict]:
        return await self._request("GET", "/nginx/proxy-hosts") or []

    async def find_proxy_host(self, fqdn: str) -> dict | None:
        """Find an existing proxy host serving `fqdn` — used to adopt a host
        left over from a partially-failed earlier provisioning run instead of
        erroring on the duplicate-domain conflict NPM would raise."""
        for h in await self.list_proxy_hosts():
            if fqdn in (h.get("domain_names") or []):
                return h
        return None

    def _proxy_host_payload(self, fqdn: str, scheme: str, host: str, port: int,
                            websockets: bool, certificate_id: int = 0) -> dict:
        return {
            "domain_names": [fqdn],
            "forward_scheme": scheme,
            "forward_host": host,
            "forward_port": int(port),
            "certificate_id": certificate_id,
            "ssl_forced": bool(certificate_id),
            "http2_support": bool(certificate_id),
            "hsts_enabled": False,
            "hsts_subdomains": False,
            "allow_websocket_upgrade": bool(websockets),
            "block_exploits": True,
            "caching_enabled": False,
            "access_list_id": 0,
            "advanced_config": "",
            "meta": {"letsencrypt_agree": False, "dns_challenge": False},
            "locations": [],
        }

    async def create_proxy_host(self, fqdn: str, scheme: str, host: str, port: int,
                                websockets: bool) -> dict:
        """Create the proxy host WITHOUT a certificate. SSL is attached as a
        separate step so a slow/failed Let's Encrypt issuance doesn't take the
        whole proxy host down with it — HTTP keeps working and the cert step
        can be retried."""
        return await self._request(
            "POST", "/nginx/proxy-hosts",
            self._proxy_host_payload(fqdn, scheme, host, port, websockets))

    async def get_proxy_host(self, proxy_host_id: int) -> dict:
        return await self._request("GET", f"/nginx/proxy-hosts/{proxy_host_id}")

    # The PUT-able subset of a proxy-host object. A GET response additionally
    # carries read-only fields (id, created_on, owner, expanded certificate,
    # nginx status in meta, …) that NPM's schema validation rejects on PUT.
    _EDITABLE_HOST_KEYS = (
        "domain_names", "forward_scheme", "forward_host", "forward_port",
        "access_list_id", "certificate_id", "ssl_forced", "http2_support",
        "hsts_enabled", "hsts_subdomains", "allow_websocket_upgrade",
        "block_exploits", "caching_enabled", "advanced_config", "locations",
        "enabled",
    )
    _EDITABLE_META_KEYS = ("letsencrypt_agree", "letsencrypt_email", "dns_challenge")

    async def attach_certificate(self, proxy_host_id: int, certificate_id: int) -> dict:
        """GET-modify-PUT: flip only the SSL fields and send everything else
        back unchanged. Rebuilding the payload from scratch here would wipe
        custom advanced_config / locations / access lists on hosts that were
        adopted or imported rather than created by us."""
        current = await self.get_proxy_host(proxy_host_id)
        payload = {k: current[k] for k in self._EDITABLE_HOST_KEYS
                   if k in current and current[k] is not None}
        meta = current.get("meta") or {}
        payload["meta"] = {k: meta[k] for k in self._EDITABLE_META_KEYS if k in meta}
        payload.update({"certificate_id": certificate_id,
                        "ssl_forced": True, "http2_support": True})
        return await self._request("PUT", f"/nginx/proxy-hosts/{proxy_host_id}", payload)

    async def delete_proxy_host(self, proxy_host_id: int) -> None:
        try:
            await self._request("DELETE", f"/nginx/proxy-hosts/{proxy_host_id}")
        except NPMError as exc:
            # Already gone is fine — cleanup is idempotent.
            if "404" in str(exc):
                return
            raise

    # ── certificates ──────────────────────────────────────────────────────

    async def list_certificates(self) -> list[dict]:
        return await self._request("GET", "/nginx/certificates") or []

    async def find_certificate(self, fqdn: str) -> dict | None:
        """An existing Let's Encrypt cert covering exactly this fqdn (adopt
        instead of re-issuing — LE rate-limits duplicate certificates)."""
        for cert in await self.list_certificates():
            if cert.get("provider") == "letsencrypt" and \
                    fqdn in (cert.get("domain_names") or []):
                return cert
        return None

    async def create_certificate(self, fqdn: str, le_email: str) -> dict:
        return await self._request(
            "POST", "/nginx/certificates",
            {
                "domain_names": [fqdn],
                "provider": "letsencrypt",
                "meta": {
                    "letsencrypt_email": le_email,
                    "letsencrypt_agree": True,
                    "dns_challenge": False,
                },
            },
            timeout=_CERT_TIMEOUT,
        )

    async def delete_certificate(self, certificate_id: int) -> None:
        try:
            await self._request("DELETE", f"/nginx/certificates/{certificate_id}")
        except NPMError as exc:
            if "404" in str(exc):
                return
            raise
