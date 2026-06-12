"""Async client for the Namecheap XML API (DNS host records only).

The dangerous quirk this module is built around: Namecheap has NO
"add one record" call. `namecheap.domains.dns.setHosts` REPLACES the entire
host-record set for the domain in one shot, so every mutation here is a
read-modify-write - and a bug (or a truncated read) could wipe every DNS
record on the domain. Hence the guard rails:

- A write NEVER happens unless the preceding `getHosts` returned a clean
  Status="OK" response with `IsUsingOurDNS=true`. Any doubt → exception, no
  write.
- `EmailType` from the getHosts response is passed back on setHosts.
  Omitting it silently resets the domain's email-forwarding mode - a known
  Namecheap footgun.
- `remove_record` only writes when it actually matched something, and only
  removes the exact (name, type[, address]) it was told to.

Other constraints inherited from the API itself: requests must come from a
whitelisted source IP (the `client_ip` param is asserted by Namecheap against
the actual source address), and API access must be enabled on the account.
Both produce in-band errors that surface here as NamecheapError with
Namecheap's own message text.
"""
import logging
import xml.etree.ElementTree as ET

import httpx

logger = logging.getLogger(__name__)

API_URL = "https://api.namecheap.com/xml.response"


class NamecheapError(Exception):
    """Any Namecheap API failure, with Namecheap's message where available."""


def split_domain(domain: str) -> tuple[str, str]:
    """'example.co.uk' → ('example', 'co.uk'). Namecheap addresses domains as
    SLD + TLD where TLD is everything after the first label."""
    parts = (domain or "").strip(".").split(".", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise NamecheapError(f"Invalid domain: {domain!r}")
    return parts[0], parts[1]


class NamecheapClient:
    def __init__(self, api_user: str, api_key: str, username: str, client_ip: str,
                 timeout: float = 30.0):
        self.api_user = api_user
        self.api_key = api_key
        self.username = username
        self.client_ip = client_ip
        self.timeout = timeout

    def _base_params(self, command: str, domain: str) -> dict:
        sld, tld = split_domain(domain)
        return {
            "ApiUser": self.api_user,
            "ApiKey": self.api_key,
            "UserName": self.username,
            "ClientIp": self.client_ip,
            "Command": command,
            "SLD": sld,
            "TLD": tld,
        }

    async def _call(self, params: dict) -> ET.Element:
        """POST (form-encoded - setHosts param lists get long) and parse the
        XML envelope, raising on Status="ERROR" with Namecheap's message."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.post(API_URL, data=params)
        except httpx.HTTPError as exc:
            raise NamecheapError(f"Cannot reach Namecheap API: {exc}") from exc
        if r.status_code != 200:
            raise NamecheapError(f"Namecheap API returned HTTP {r.status_code}")
        try:
            root = ET.fromstring(r.text)
        except ET.ParseError as exc:
            raise NamecheapError(f"Namecheap returned unparsable XML: {exc}") from exc
        if (root.get("Status") or "").upper() != "OK":
            msgs = [(e.text or "").strip() for e in root.findall(".//{*}Error")]
            raise NamecheapError("; ".join(m for m in msgs if m) or "Namecheap API error")
        return root

    # ── reads ─────────────────────────────────────────────────────────────

    async def get_hosts(self, domain: str) -> dict:
        """All host records for the domain. Raises (→ no later write can
        happen) unless the response is clean and the domain actually uses
        Namecheap's DNS - records set elsewhere can't be managed here."""
        root = await self._call(self._base_params("namecheap.domains.dns.getHosts", domain))
        result = root.find(".//{*}DomainDNSGetHostsResult")
        if result is None:
            raise NamecheapError("Namecheap getHosts returned no result element")
        if (result.get("IsUsingOurDNS") or "").lower() != "true":
            raise NamecheapError(
                f"{domain} is not using Namecheap's DNS servers - "
                "records can't be managed via this API")
        hosts = []
        for h in result.findall("{*}host"):
            hosts.append({
                "name": h.get("Name") or "",
                "type": (h.get("Type") or "").upper(),
                "address": h.get("Address") or "",
                "mx_pref": h.get("MXPref") or "10",
                "ttl": h.get("TTL") or "1799",
            })
        return {"hosts": hosts, "email_type": result.get("EmailType") or None}

    # ── writes (read-modify-write; full replace under the hood) ──────────

    async def _set_hosts(self, domain: str, hosts: list[dict], email_type: str | None) -> None:
        params = self._base_params("namecheap.domains.dns.setHosts", domain)
        if email_type:
            params["EmailType"] = email_type
        for i, h in enumerate(hosts, 1):
            params[f"HostName{i}"] = h["name"]
            params[f"RecordType{i}"] = h["type"]
            params[f"Address{i}"] = h["address"]
            params[f"TTL{i}"] = str(h.get("ttl") or "1799")
            if h["type"] == "MX":
                params[f"MXPref{i}"] = str(h.get("mx_pref") or "10")
        root = await self._call(params)
        result = root.find(".//{*}DomainDNSSetHostsResult")
        if result is None or (result.get("IsSuccess") or "").lower() != "true":
            raise NamecheapError("Namecheap setHosts did not report success")

    async def ensure_record(self, domain: str, host: str, rtype: str, address: str,
                            ttl: int = 300) -> str:
        """Idempotent add. Returns 'created' or 'exists'. Refuses (raises) on
        conflicts rather than overwriting - a same-name record pointing
        somewhere else is the user's to resolve, not ours to clobber."""
        rtype = rtype.upper()
        host_l = host.lower()
        data = await self.get_hosts(domain)
        hosts = data["hosts"]

        same_name = [h for h in hosts if h["name"].lower() == host_l]
        for h in same_name:
            if h["type"] == rtype and h["address"].rstrip(".") == address.rstrip("."):
                return "exists"
        if same_name:
            # CNAME can't coexist with anything at the same name (and vice
            # versa), and a same-name+type record with a different target is
            # a conflict either way.
            conflicts = ", ".join(f"{h['type']} → {h['address']}" for h in same_name)
            raise NamecheapError(
                f"A DNS record for '{host}.{domain}' already exists ({conflicts}) - "
                "remove it in Namecheap or pick another subdomain")

        hosts.append({"name": host, "type": rtype, "address": address,
                      "mx_pref": "10", "ttl": str(ttl)})
        await self._set_hosts(domain, hosts, data["email_type"])
        return "created"

    async def remove_record(self, domain: str, host: str, rtype: str,
                            address: str | None = None) -> bool:
        """Remove the exact record(s) matching (name, type[, address]).
        Returns False without writing anything when nothing matched."""
        rtype = rtype.upper()
        host_l = host.lower()
        data = await self.get_hosts(domain)

        def matches(h: dict) -> bool:
            if h["name"].lower() != host_l or h["type"] != rtype:
                return False
            if address is not None and h["address"].rstrip(".") != address.rstrip("."):
                return False
            return True

        remaining = [h for h in data["hosts"] if not matches(h)]
        if len(remaining) == len(data["hosts"]):
            return False  # nothing matched → don't touch the zone at all
        await self._set_hosts(domain, remaining, data["email_type"])
        return True
