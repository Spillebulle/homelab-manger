"""Read-only async client for the Portainer API.

Used by the Services feature to suggest forward targets (container → host
IP + published port) and to show container state next to linked services.
Nothing is ever written to Portainer — the link is display/navigation only.

Auth is an API key (Portainer: user menu → My account → Access tokens) sent
as `X-API-Key`. Container listings go through Portainer's Docker proxy
(`/api/endpoints/{id}/docker/...`), which speaks the plain Docker Engine API.
"""
import logging
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)


class PortainerError(Exception):
    """Any Portainer API failure, with a human-readable message."""


class PortainerClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0):
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    async def _get(self, path: str, params: dict | None = None):
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as c:
                r = await c.get(f"{self.base_url}/api{path}", params=params,
                                headers={"X-API-Key": self.api_key})
        except httpx.HTTPError as exc:
            raise PortainerError(f"Cannot reach Portainer at {self.base_url}: {exc}") from exc
        if r.status_code == 401:
            raise PortainerError("Portainer rejected the API key (401)")
        if r.status_code >= 400:
            detail = ""
            try:
                detail = (r.json() or {}).get("message") or ""
            except Exception:
                pass
            raise PortainerError(f"Portainer GET {path}: HTTP {r.status_code}"
                                 + (f" — {detail}" if detail else ""))
        return r.json()

    async def endpoints(self) -> list[dict]:
        """Portainer environments ('endpoints'). Most homelabs have one."""
        return await self._get("/endpoints") or []

    async def first_endpoint_id(self) -> int:
        eps = await self.endpoints()
        if not eps:
            raise PortainerError("Portainer has no environments (endpoints)")
        return eps[0]["Id"]

    async def containers(self, endpoint_id: int) -> list[dict]:
        """Normalized container list for one environment:
        {name, state, image, ports: [{private, public, ip}], networks: {name: ip}}"""
        raw = await self._get(f"/endpoints/{endpoint_id}/docker/containers/json",
                              params={"all": "true"}) or []
        out = []
        for c in raw:
            names = c.get("Names") or []
            name = (names[0] if names else c.get("Id", ""))[:].lstrip("/")
            ports = []
            seen = set()
            for p in c.get("Ports") or []:
                key = (p.get("PrivatePort"), p.get("PublicPort"))
                if key in seen:
                    continue  # docker reports v4+v6 bindings separately
                seen.add(key)
                ports.append({
                    "private": p.get("PrivatePort"),
                    "public": p.get("PublicPort"),
                    "ip": p.get("IP") or None,
                })
            networks = {}
            for net_name, net in ((c.get("NetworkSettings") or {}).get("Networks") or {}).items():
                if net.get("IPAddress"):
                    networks[net_name] = net["IPAddress"]
            out.append({
                "id": c.get("Id"),
                "name": name,
                "state": c.get("State"),       # running | exited | …
                "status": c.get("Status"),     # human text, e.g. "Up 3 days"
                "image": c.get("Image"),
                "ports": ports,
                "networks": networks,
            })
        out.sort(key=lambda c: c["name"].lower())
        return out

    async def test(self) -> dict:
        eps = await self.endpoints()
        names = ", ".join(e.get("Name", "?") for e in eps) or "none"
        return {"ok": True, "detail": f"Connected — {len(eps)} environment(s): {names}"}


def host_from_url(base_url: str) -> str | None:
    """The bare host of the Portainer URL — used as the default Docker-host
    IP for forward targets when `docker_host_ip` isn't configured (Portainer
    usually runs on the Docker host itself)."""
    try:
        host = urlsplit(base_url).hostname
        return host or None
    except ValueError:
        return None


def endpoint_host_ip(endpoint: dict, fallback: str | None) -> str | None:
    """The Docker host's address for one Portainer environment, derived from
    the endpoint's own URL: agent/remote endpoints look like
    `tcp://192.168.1.20:9001` → that host is where the containers' published
    ports live. Local socket endpoints (`unix://`, `npipe://`, or blank) have
    no host in the URL, so they fall back to the configured `docker_host_ip`
    (or the Portainer URL's host — for the local endpoint, Portainer runs on
    that same machine)."""
    url = str(endpoint.get("URL") or "")
    if url.startswith("tcp://"):
        host = host_from_url(url)
        if host and host not in ("localhost", "127.0.0.1"):
            return host
    return fallback
