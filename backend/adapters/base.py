import asyncio
import socket
from abc import ABC, abstractmethod
from typing import Any


# Shape of a single entry in BaseAdapter.REQUIREMENTS / a preflight result.
# Keep this informal — duck-typed dicts are easier to render in the SPA than
# Pydantic models, and the data crosses the wire as JSON anyway.
#
# Required keys:
#   service      str   — display name, e.g. "SNMPv2c", "SSH", "HTTPS (Redfish)"
#   transport    str   — "tcp" | "udp" | "snmp" | "snmpv3" | "redfish" | "xmlapi"
#                        Drives which preflight test runs. New transports
#                        need a branch in BaseAdapter.preflight.
#   port         int   — TCP/UDP port to test. Adapters that take a configurable
#                        port should derive this from credentials at instance
#                        time and override `requirements()`.
#   description  str   — Why this service matters; surfaced in the tooltip.
#   required     bool  — If False, a failed test renders as a warning, not an
#                        error. Use False for optional services the adapter
#                        falls back away from (e.g. CIMC SSH reaper, iBMC SNMP
#                        enrichment).


class BaseAdapter(ABC):
    # Class-level requirements. Most adapters override `requirements()` so the
    # port reflects the credential overrides; this class attr is the fallback.
    REQUIREMENTS: list[dict] = []

    def __init__(self, hostname: str, credentials: dict):
        self.hostname = hostname
        self.credentials = credentials
        # Set by get_adapter() after construction. Defaults to None for
        # adapters built directly (e.g. unit tests, preflight endpoint).
        self.adapter_type: str | None = None

    @abstractmethod
    def get_supported_cache_keys(self) -> list[str]:
        """Return the list of cache keys this adapter can populate."""

    @abstractmethod
    async def fetch(self, cache_key: str) -> Any:
        """Fetch fresh data for the given cache key."""

    @abstractmethod
    async def execute_action(self, action: dict) -> dict:
        """Execute a device action. action dict must contain 'type'."""

    async def close(self) -> None:
        """Release any per-instance resources (e.g. open Redfish sessions).
        Called by the poller after a fetch cycle. Default no-op."""

    # ── Service requirements + preflight ─────────────────────────────────────
    #
    # The add-device UI uses these to (a) render a tooltip listing the
    # services this adapter relies on and (b) actively test each service when
    # the user clicks "Test connection" or after saving. Every new adapter
    # MUST populate REQUIREMENTS (or override `requirements()`); otherwise
    # the preflight endpoint just returns "no checks defined" and the user
    # has no way to validate connectivity before relying on the device.

    def requirements(self) -> list[dict]:
        """Return the per-instance requirements list. Override when the port
        depends on credentials (HTTPS port, SSH port, etc.)."""
        return list(self.REQUIREMENTS)

    async def preflight(self) -> list[dict]:
        """Run each requirement and return one result per service.

        Each result merges the requirement dict with:
          ok      bool — true if the test passed
          detail  str  — short human-readable explanation (failure reason or
                         "connected", "responded", etc.)
          skipped bool — present and True if the test was not run (e.g. UDP
                         probe with no app-layer protocol available)

        Override per adapter when a deeper check is materially better than
        the generic TCP/SNMP probe — e.g. CIMC's `aaaLogin` is the only way
        to distinguish "BMC up" from "BMC up and XMLAPI working"."""
        results: list[dict] = []
        for req in self.requirements():
            results.append(await self._run_one_preflight(req))
        return results

    async def _run_one_preflight(self, req: dict) -> dict:
        """Dispatch a single requirement to its test by transport. Catches
        all exceptions so one failing probe doesn't tank the rest of the
        report — the UI needs the full grid to point at the right fix."""
        transport = (req.get("transport") or "").lower()
        try:
            if transport == "tcp":
                ok, detail = await self._probe_tcp(req["port"])
            elif transport in ("udp", "ipmi"):
                # Pure UDP reachability isn't testable without an app-layer
                # protocol (no SYN/ACK handshake to wait for). Mark as
                # "unverified" rather than guessing — the SPA renders that
                # state distinct from pass/fail.
                return {**req, "ok": None, "skipped": True,
                        "detail": "UDP — reachability not testable without app protocol"}
            elif transport in ("snmp", "snmpv2", "snmpv2c"):
                ok, detail = await self._probe_snmp_v2(req)
            elif transport == "snmpv3":
                ok, detail = await self._probe_snmp_v3(req)
            elif transport == "redfish":
                ok, detail = await self._probe_redfish(req)
            elif transport == "xmlapi":
                ok, detail = await self._probe_cimc_xmlapi(req)
            elif transport == "http":
                ok, detail = await self._probe_http(req)
            else:
                return {**req, "ok": None, "skipped": True,
                        "detail": f"unknown transport {transport!r}"}
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        return {**req, "ok": ok, "detail": detail}

    # ── Generic probes ───────────────────────────────────────────────────────

    async def _probe_tcp(self, port: int, timeout: float = 3.0) -> tuple[bool, str]:
        """Try a TCP connect — fastest is-it-up check. Doesn't validate auth
        or protocol; that's the job of higher-level probes."""
        def _connect() -> tuple[bool, str]:
            try:
                with socket.create_connection((self.hostname, int(port)), timeout=timeout):
                    return True, f"TCP connect to :{port} succeeded"
            except (socket.timeout, TimeoutError):
                return False, f"TCP connect to :{port} timed out after {timeout:.0f}s"
            except ConnectionRefusedError:
                return False, f"TCP connect to :{port} refused — service not listening"
            except OSError as exc:
                return False, f"TCP connect to :{port} failed: {exc}"
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _connect)

    async def _probe_http(self, req: dict) -> tuple[bool, str]:
        """TCP-only probe for plain-HTTP services. We don't issue a real GET
        because some smart-managed devices (HPE 1820) return 404 for `/` and
        require the user to be on a login page — that's a false negative for
        "is the web UI reachable?"."""
        return await self._probe_tcp(int(req["port"]))

    async def _probe_snmp_v2(self, req: dict) -> tuple[bool, str]:
        """Real SNMP get of sysName. Verifies host reachability AND community
        validity in one round trip — the most useful single check.

        Some agents (e.g. HPE OfficeConnect 1820 with default configuration)
        do not populate `sysName` and return an empty string. That isn't a
        failure: if we got back a successful GetResponse at all, the
        community was accepted and the agent is reachable, which is what
        this probe is supposed to verify. Empty value → degrade to a
        success with a note, never to a hard fail."""
        # Local import: snmp.py imports base.py, so a module-level import
        # would be a cycle.
        from .snmp import _get, _SYS_NAME
        community = (self.credentials.get("community") or "public")
        port = int(req["port"])
        try:
            val = await asyncio.wait_for(
                _get(self.hostname, community, _SYS_NAME, port),
                timeout=4.0,
            )
        except asyncio.TimeoutError:
            return False, "SNMP get sysName timed out — host unreachable or community rejected"
        except Exception as exc:
            return False, f"SNMP error: {type(exc).__name__}: {exc}"
        if val is None:
            return False, "SNMP returned no value — host unreachable or community rejected"
        if val == b"" or val == "":
            return True, "SNMP responded (sysName not configured on device — community accepted)"
        return True, f"SNMP responded: sysName={val!s}"

    async def _probe_snmp_v3(self, req: dict) -> tuple[bool, str]:
        """SNMPv3 get via pysnmp. Used by Huawei iBMC for OEM enrichment."""
        try:
            from pysnmp.hlapi.v3arch import asyncio as ps
        except Exception:
            return False, "pysnmp not installed — cannot test SNMPv3"
        user      = self.credentials.get("snmp_user") or self.credentials.get("username")
        auth_pass = self.credentials.get("snmp_auth_pass") or self.credentials.get("password")
        priv_pass = self.credentials.get("snmp_priv_pass") or self.credentials.get("password")
        if not (user and auth_pass and priv_pass):
            return False, "no SNMPv3 credentials configured"
        port = int(req.get("port", self.credentials.get("snmp_port", 161)))
        try:
            engine = ps.SnmpEngine()
            usm    = ps.UsmUserData(user, auth_pass, priv_pass,
                                    authProtocol=ps.USM_AUTH_HMAC96_SHA,
                                    privProtocol=ps.USM_PRIV_CFB128_AES)
            transport = await ps.UdpTransportTarget.create((self.hostname, port),
                                                           timeout=3, retries=1)
            it = ps.get_cmd(engine, usm, transport, ps.ContextData(),
                            ps.ObjectType(ps.ObjectIdentity("1.3.6.1.2.1.1.5.0")))
            err_ind, err_stat, _err_idx, _vbs = await asyncio.wait_for(it, timeout=5.0)
            try:
                engine.close_dispatcher()
            except Exception:
                pass
            if err_ind:
                return False, f"SNMPv3 error: {err_ind}"
            if err_stat:
                return False, f"SNMPv3 status: {err_stat.prettyPrint()}"
            return True, "SNMPv3 responded"
        except asyncio.TimeoutError:
            return False, "SNMPv3 timed out"
        except Exception as exc:
            return False, f"SNMPv3 error: {type(exc).__name__}: {exc}"

    async def _probe_redfish(self, req: dict) -> tuple[bool, str]:
        """GET /redfish/v1/ with Basic Auth. Validates both reachability and
        that the user has read access to the service root."""
        import httpx
        port = int(req.get("port", self.credentials.get("port", 443)))
        username = self.credentials.get("username")
        password = self.credentials.get("password") or ""
        if not username:
            return False, "no Redfish username configured"
        url = f"https://{self.hostname}:{port}/redfish/v1/"
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0,
                                         auth=(username, password)) as c:
                r = await c.get(url)
        except httpx.TimeoutException:
            return False, f"Redfish GET / timed out — BMC unreachable on :{port}"
        except httpx.HTTPError as exc:
            return False, f"Redfish transport error: {exc}"
        # Some Redfish stacks (iBMC) reject Basic and only allow session auth;
        # surface that explicitly so the user knows the BMC is reachable.
        if r.status_code == 401:
            return False, "Redfish reachable but auth rejected (HTTP 401) — wrong creds, or BMC requires session-token (try anyway, the adapter will fall back)"
        if r.status_code >= 400:
            return False, f"Redfish returned HTTP {r.status_code}"
        return True, "Redfish service root reachable"

    async def _probe_cimc_xmlapi(self, req: dict) -> tuple[bool, str]:
        """Real aaaLogin against the CIMC XMLAPI endpoint. Burns one of the
        BMC's session slots briefly but is the only way to distinguish
        "HTTPS up" from "XMLAPI working with these credentials"."""
        import httpx
        import xml.etree.ElementTree as ET
        port = int(req.get("port", self.credentials.get("port", 443)))
        username = self.credentials.get("username")
        password = self.credentials.get("password") or ""
        if not username:
            return False, "no CIMC username configured"
        # Reuse the legacy SSL context — 2.0(9f) ships a 1024-bit RSA cert
        # that modern OpenSSL refuses under default SECLEVEL.
        from .cimc import _legacy_ssl_context
        ctx = _legacy_ssl_context()
        url = f"https://{self.hostname}:{port}/nuova"
        body = f'<aaaLogin inName="{username}" inPassword="{password}"/>'
        try:
            async with httpx.AsyncClient(verify=ctx, timeout=10) as c:
                r = await c.post(url, content=body,
                                 headers={"Content-Type": "application/xml"})
                r.raise_for_status()
                root = ET.fromstring(r.text)
                cookie = root.get("outCookie")
                err    = root.get("errorDescr") or ""
                # Best-effort cleanup so we don't hold the session slot.
                if cookie:
                    try:
                        await c.post(url,
                                     content=f'<aaaLogout inCookie="{cookie}"/>',
                                     headers={"Content-Type": "application/xml"})
                    except Exception:
                        pass
        except httpx.TimeoutException:
            return False, f"CIMC XMLAPI timed out on :{port}"
        except httpx.HTTPError as exc:
            return False, f"CIMC XMLAPI transport error: {exc}"
        except ET.ParseError as exc:
            return False, f"CIMC XMLAPI returned non-XML response: {exc}"
        if cookie:
            return True, "CIMC XMLAPI accepted aaaLogin"
        return False, f"CIMC XMLAPI rejected login: {err or 'no cookie returned'}"
