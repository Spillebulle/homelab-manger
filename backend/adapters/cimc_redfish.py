"""
Cisco CIMC adapter for firmware 3.0+ — uses Redfish where it's available
and falls back to the XMLAPI for inventory data Redfish 1.0 on this
firmware doesn't expose (DIMM details, PCIe inventory, full disk info,
network adapter details).

The big win over the legacy XMLAPI-only CIMCAdapter is that sensors and
live power data come from Redfish in a single GET each, instead of a
25-75 s IPMI-over-LAN subprocess walk per poll cycle. BIOS version, BMC
firmware version, and the BMC's own management IP also become available
because Redfish exposes them — the legacy adapter has no equivalent.

Tested against CIMC 3.0(4r) on a UCS C22 M3S. RedfishVersion advertised
is 1.0.0; on this firmware the following endpoints are missing (404):
    /Systems/{sid}/Memory          → fall back to XMLAPI memoryUnit
    /Systems/{sid}/Storage         → fall back to XMLAPI storageLocalDisk
    /Systems/{sid}/PCIeDevices     → fall back to XMLAPI pciEquipSlot

EthernetInterfaces *exist* but only carry MAC + name — no link state,
speed, or parent NIC model — so we still pull the network view via
XMLAPI. Newer CIMC firmwares will likely add these endpoints; when they
do, override the relevant `_*_via_xmlapi` helpers to prefer Redfish.

Cisco's Redfish 1.0 stack returns most numeric fields as JSON strings
("208", "33.0", "8800") rather than numbers. Helpers in this module
coerce on read; keep that in mind if you add a new field — bare
arithmetic on a `Reading` value will TypeError otherwise.
"""
import asyncio
import re
from typing import Any
import httpx
from .cimc import CIMCAdapter


def _to_float(value: Any) -> float | None:
    """Coerce Cisco's stringified numerics; tolerate 'N/A' and similar."""
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f


def _to_int(value: Any) -> int | None:
    f = _to_float(value)
    return int(f) if f is not None else None


class CIMCRedfishAdapter(CIMCAdapter):
    """CIMC adapter that prefers Redfish for status/sensors/power, keeps
    XMLAPI only where Redfish 1.0 on 3.0(4r) is too thin. Inherits the
    XMLAPI plumbing (login, _resolve_class, the post-poll session reaper)
    and the KVM JNLP flow from the legacy adapter unchanged."""

    def __init__(self, hostname: str, credentials: dict):
        super().__init__(hostname, credentials)
        self.base = f"https://{hostname}:{self.port}"
        # Redfish session token — minted lazily on first 401 against Basic
        # auth (CIMC accepts Basic on 3.0(4r), but we keep the fallback so
        # firmware revs that tighten this up still work).
        self._rf_token: str | None = None
        self._rf_session_path: str | None = None
        # System ID is the serial number on Cisco's implementation
        # (e.g. "WZP1712005B"). Discovered from /redfish/v1/Systems on
        # first call and cached for the adapter instance.
        self._rf_system_id: str | None = None
        self._rf_system_cache: dict | None = None
        # Serialize XMLAPI logins. _hardware_hybrid runs memory + pcie
        # XMLAPI fetches in parallel; without this lock both coroutines
        # see `_cookie is None`, both POST aaaLogin, and we leak a session
        # into CIMC's 4-slot cap on every poll. The legacy CIMCAdapter has
        # the same latent race but masks it with the post-poll SSH reaper.
        self._xml_login_lock = asyncio.Lock()
        # Same race exists for Redfish — every Basic-Auth GET on Cisco's
        # 1.0.0 stack is *very* slow (observed ~2.8s/GET on a C22 M3,
        # 3.0(4r)) and parallel requests appear to interfere with each
        # other. Eager-login once and reuse the X-Auth-Token; serialise
        # the login itself so concurrent first calls don't burn session
        # slots like the XMLAPI side does.
        self._rf_login_lock = asyncio.Lock()

    # ── XMLAPI login (lock-protected) ─────────────────────────────────────────

    async def _login(self) -> str:
        async with self._xml_login_lock:
            # Re-check inside the lock — the coroutine that won the race
            # already populated _cookie; the loser should reuse it.
            if self._cookie:
                return self._cookie
            return await super()._login()

    async def _resolve_class(self, class_id: str, hierarchical: bool = False) -> list[dict]:
        """Override the parent to ensure the cookie is captured *after*
        login, not at call time. Without this, parallel calls
        (`asyncio.gather(_resolve_class(A), _resolve_class(B))`) each read
        `self._cookie` synchronously while it's still None, bake `cookie=""`
        into both XML bodies, then post both — CIMC mints a fresh session
        for every empty-cookie POST and we burn through the 4-slot cap on
        every poll. Login here before building the body so the wire
        request always carries a real cookie."""
        if not self._cookie:
            await self._login()
        return await super()._resolve_class(class_id, hierarchical)

    # ── Redfish helpers ───────────────────────────────────────────────────────

    async def _rf_request(self, method: str, path: str, **kwargs) -> dict:
        headers = kwargs.pop("headers", {}) or {}
        headers.setdefault("Accept", "application/json")
        await self._ensure_rf_session()
        headers["X-Auth-Token"] = self._rf_token

        async with httpx.AsyncClient(verify=self._ssl_ctx, timeout=15) as c:
            r = await c.request(method, f"{self.base}{path}", headers=headers, **kwargs)

        # Token expired or session culled by the BMC — mint a fresh one once.
        if r.status_code == 401:
            self._rf_token = None
            self._rf_session_path = None
            await self._ensure_rf_session()
            headers["X-Auth-Token"] = self._rf_token
            async with httpx.AsyncClient(verify=self._ssl_ctx, timeout=15) as c:
                r = await c.request(method, f"{self.base}{path}", headers=headers, **kwargs)

        r.raise_for_status()
        return r.json() if r.content else {}

    async def _rf_get(self, path: str) -> dict:
        return await self._rf_request("GET", path)

    async def _ensure_rf_session(self) -> None:
        """Eager-login once per adapter instance; serialise so parallel
        first calls reuse a single session instead of burning slots."""
        if self._rf_token:
            return
        async with self._rf_login_lock:
            if self._rf_token:
                return
            await self._rf_login()

    async def _rf_login(self) -> None:
        """Mint an X-Auth-Token via SessionService. CIMC 3.0(4r) does not
        emit a `Location` header — we read the session URI from the
        response body's `@odata.id` instead so close() can DELETE it."""
        async with httpx.AsyncClient(verify=self._ssl_ctx, timeout=15) as c:
            r = await c.post(
                f"{self.base}/redfish/v1/SessionService/Sessions",
                json={"UserName": self.username, "Password": self.password},
                headers={"Content-Type": "application/json"},
            )
            r.raise_for_status()
            self._rf_token = r.headers.get("X-Auth-Token")
            location = r.headers.get("Location")
            if location:
                if location.startswith("http"):
                    location = "/" + location.split("/", 3)[-1].lstrip("/")
                self._rf_session_path = location
            else:
                # Cisco's body shape: {"@odata.id": "/redfish/v1/SessionService/Sessions/104", ...}
                try:
                    self._rf_session_path = (r.json() or {}).get("@odata.id")
                except Exception:
                    self._rf_session_path = None

    async def _rf_logout(self) -> None:
        if not (self._rf_token and self._rf_session_path):
            return
        try:
            async with httpx.AsyncClient(verify=self._ssl_ctx, timeout=8) as c:
                await c.delete(
                    f"{self.base}{self._rf_session_path}",
                    headers={"X-Auth-Token": self._rf_token},
                )
        except Exception:
            pass
        self._rf_token = None
        self._rf_session_path = None

    async def _rf_system(self) -> dict:
        if self._rf_system_cache is not None:
            return self._rf_system_cache
        if self._rf_system_id is None:
            idx = await self._rf_get("/redfish/v1/Systems")
            members = idx.get("Members") or []
            if not members:
                raise RuntimeError("CIMC Redfish: no Systems members")
            uri = members[0]["@odata.id"]
            self._rf_system_id = uri.rsplit("/", 1)[-1]
        self._rf_system_cache = await self._rf_get(f"/redfish/v1/Systems/{self._rf_system_id}")
        return self._rf_system_cache

    async def _rf_first_manager(self) -> dict | None:
        try:
            idx = await self._rf_get("/redfish/v1/Managers")
        except Exception:
            return None
        for m in (idx.get("Members") or []):
            try:
                return await self._rf_get(m["@odata.id"])
            except Exception:
                continue
        return None

    async def _rf_first_bmc_ipv4(self, mgr: dict) -> str | None:
        eth_url = (mgr.get("EthernetInterfaces") or {}).get("@odata.id")
        if not eth_url:
            return None
        try:
            eth_idx = await self._rf_get(eth_url)
        except Exception:
            return None
        for em in (eth_idx.get("Members") or []):
            try:
                iface = await self._rf_get(em["@odata.id"])
            except Exception:
                continue
            # Standard Redfish: list of {Address, ...}. Cisco 1.0.0 quirk:
            # a single dict instead of a list. Normalize both shapes.
            ipv4 = iface.get("IPv4Addresses")
            entries: list[dict]
            if isinstance(ipv4, list):
                entries = [e for e in ipv4 if isinstance(e, dict)]
            elif isinstance(ipv4, dict):
                entries = [ipv4]
            else:
                entries = []
            for entry in entries:
                addr = (entry.get("Address") or "").strip()
                if addr and not addr.startswith(("0.", "169.254.", "127.")):
                    return addr
        return None

    # ── close() ───────────────────────────────────────────────────────────────

    async def close(self) -> None:
        # Tear down the Redfish session first (cheap, no SSH), then run the
        # XMLAPI cleanup the legacy adapter does (logout + SSH-based reaper
        # to free other XMLAPI slots). Ordering doesn't matter functionally
        # since they hit different auth backends, but doing Redfish first
        # keeps SSH the long-pole rather than serialising it behind logout.
        await self._rf_logout()
        await super().close()

    # ── fetch dispatch ────────────────────────────────────────────────────────

    async def fetch(self, cache_key: str) -> Any:
        if cache_key == "status":   return await self._status_via_redfish()
        if cache_key == "hardware": return await self._hardware_hybrid()
        if cache_key == "storage":  return await super()._storage()
        if cache_key == "network":  return await super()._network()
        if cache_key == "power":    return await self._power_via_redfish()
        if cache_key == "sensors":  return await self._sensors_via_redfish()
        raise ValueError(f"Unknown cache key: {cache_key!r}")

    # ── status ────────────────────────────────────────────────────────────────

    async def _status_via_redfish(self) -> dict:
        try:
            sys = await self._rf_system()
        except Exception as e:
            return {"online": False, "error": f"Redfish: {e}"}

        bmc_firmware = ""
        bmc_ip = ""
        try:
            mgr = await self._rf_first_manager()
            if mgr:
                bmc_firmware = mgr.get("FirmwareVersion", "") or ""
                bmc_ip = (await self._rf_first_bmc_ipv4(mgr)) or ""
        except Exception:
            pass

        proc_summary = sys.get("ProcessorSummary") or {}
        mem_summary = sys.get("MemorySummary") or {}
        # MemorySummary.TotalSystemMemoryGiB → MB to match the legacy field.
        total_gib = _to_float(mem_summary.get("TotalSystemMemoryGiB"))
        total_mb = int(total_gib * 1024) if total_gib is not None else None

        return {
            "online":         True,
            "manufacturer":   sys.get("Manufacturer", ""),
            "model":          sys.get("Model", ""),
            "serial":         sys.get("SerialNumber", ""),
            "uuid":           sys.get("UUID", ""),
            "hostname":       sys.get("HostName", ""),
            "powerState":     sys.get("PowerState", ""),
            # Mirror the legacy adapter's adminPower/operPower so the
            # frontend's existing CIMC view doesn't need a special case.
            "adminPower":     "up" if sys.get("PowerState") == "On" else "down",
            "operPower":      "on" if sys.get("PowerState") == "On" else "off",
            "health":         (sys.get("Status") or {}).get("Health", ""),
            "biosVersion":    sys.get("BiosVersion", ""),
            "bmcIp":          bmc_ip,
            "bmcFirmware":    bmc_firmware,
            "totalMemoryMB":  total_mb,
            "numCpus":        proc_summary.get("Count"),
            "cpuModel":       proc_summary.get("Model", ""),
        }

    # ── hardware (hybrid) ─────────────────────────────────────────────────────

    async def _hardware_hybrid(self) -> dict:
        """CPU info comes from Redfish (richer than XMLAPI's processorUnit
        on 3.0(4r) — gets ProcessorId and Description). DIMM and PCIe
        inventory still come from XMLAPI because Redfish 1.0 on this
        firmware doesn't expose /Memory or /PCIeDevices."""
        cpu_task = self._cpus_via_redfish()
        mem_task = self._memory_via_xmlapi()
        pci_task = self._pcie_via_xmlapi()
        cpus, memory, pcie = await asyncio.gather(cpu_task, mem_task, pci_task,
                                                  return_exceptions=True)
        if isinstance(cpus, Exception):   cpus = []
        if isinstance(memory, Exception): memory = []
        if isinstance(pcie, Exception):   pcie = []
        return {"cpus": cpus, "memory": memory, "pcie": pcie}

    async def _cpus_via_redfish(self) -> list[dict]:
        sys = await self._rf_system()
        proc_uri = (sys.get("Processors") or {}).get("@odata.id")
        if not proc_uri:
            return []
        col = await self._rf_get(proc_uri)
        members = col.get("Members") or []
        results = await asyncio.gather(
            *[self._rf_get(m["@odata.id"]) for m in members],
            return_exceptions=True,
        )
        out: list[dict] = []
        for cpu in results:
            if isinstance(cpu, Exception):
                continue
            if (cpu.get("Status") or {}).get("State") not in (None, "Enabled", "Optimal"):
                continue
            out.append({
                "id":       cpu.get("Id") or cpu.get("Name"),
                "model":    (cpu.get("Model") or "").strip() or None,
                "vendor":   cpu.get("Manufacturer"),
                "cores":    _to_int(cpu.get("TotalCores")),
                "threads":  _to_int(cpu.get("TotalThreads")),
                "speedMHz": _to_int(cpu.get("MaxSpeedMHz")),
                "arch":     cpu.get("ProcessorArchitecture"),
                "stepping": (cpu.get("ProcessorId") or {}).get("Step"),
                "socket":   cpu.get("Socket"),
                "description": cpu.get("Description"),
                "health":   (cpu.get("Status") or {}).get("Health"),
            })
        return out

    async def _memory_via_xmlapi(self) -> list[dict]:
        rows = await self._resolve_class("memoryUnit")
        return [
            {
                "id":         r.get("id"),
                "location":   r.get("location"),
                "capacityMB": r.get("capacity"),
                "speedMHz":   r.get("clock"),
                "type":       r.get("type"),
                "bank":       r.get("bank"),
                "serial":     r.get("serial"),
            }
            for r in rows if r.get("presence") == "equipped"
        ]

    async def _pcie_via_xmlapi(self) -> list[dict]:
        rows = await self._resolve_class("pciEquipSlot")
        return [
            {
                "id":      r.get("id"),
                "model":   r.get("model"),
                "vendor":  r.get("vendor"),
                "class":   r.get("pciClass"),
                "dn":      r.get("dn"),
            }
            for r in rows if r.get("model")
        ]

    # ── power ─────────────────────────────────────────────────────────────────

    async def _power_via_redfish(self) -> dict:
        try:
            chassis = await self._rf_get("/redfish/v1/Chassis/1/Power")
        except Exception as e:
            return {"error": f"Redfish: {e}", "psus": [], "budget": {}}

        psus: list[dict] = []
        for p in chassis.get("PowerSupplies") or []:
            psus.append({
                "id":               str(p.get("MemberID") or p.get("Name") or ""),
                "name":             p.get("Name"),
                "model":            p.get("Model"),
                "manufacturer":     p.get("Manufacturer"),
                "serial":           p.get("SerialNumber"),
                "partNumber":       p.get("PartNumber"),
                "firmwareVersion":  p.get("FirmwareVersion"),
                "powerSupplyType":  p.get("PowerSupplyType"),
                "lineInputVoltage": _to_float(p.get("LineInputVoltage")),
                "maxOutputWatts":   _to_int(p.get("PowerCapacityWatts")),
                "lastOutputWatts":  _to_float(p.get("LastPowerOutputWatts")),
                "operState":        ((p.get("Status") or {}).get("State")
                                     or (p.get("Status") or {}).get("state")),
                "health":           (p.get("Status") or {}).get("Health"),
            })

        # PowerControl can be a dict (Cisco 1.0) or a list (later spec). Cover
        # both. Latest reading lives on `PowerConsumedWatts`.
        pc = chassis.get("PowerControl")
        consumed: float | None = None
        if isinstance(pc, dict):
            consumed = _to_float(pc.get("PowerConsumedWatts"))
        elif isinstance(pc, list) and pc:
            consumed = _to_float(pc[0].get("PowerConsumedWatts"))

        out: dict = {"psus": psus, "budget": {}}
        if consumed is not None:
            out["totalWatts"] = consumed
            # Mirror the legacy budget shape so the frontend's "Total Draw"
            # card has something to read even when the firmware doesn't
            # report a configured budget.
            out["budget"] = {"consumedWatts": consumed}
        return out

    # ── sensors ───────────────────────────────────────────────────────────────

    # Names come from the Cisco SDR (e.g. "FAN1_TACH1", "P1_TEMP_SENS",
    # "CPU1_VCORE"), which match the IPMI labels the legacy adapter
    # produced — so the frontend renderer needs no changes.
    _RPM_NAME_RE = re.compile(r"^(.*?)_TACH\d+$", re.IGNORECASE)

    async def _sensors_via_redfish(self) -> dict:
        thermal_task = self._rf_get("/redfish/v1/Chassis/1/Thermal")
        power_task   = self._rf_get("/redfish/v1/Chassis/1/Power")
        thermal, power = await asyncio.gather(thermal_task, power_task,
                                              return_exceptions=True)

        temps: list[dict] = []
        fans:  list[dict] = []
        volts: list[dict] = []

        if not isinstance(thermal, Exception):
            for t in thermal.get("Temperatures") or []:
                if (t.get("Status") or {}).get("State") != "Enabled":
                    continue
                c = _to_float(t.get("ReadingCelsius"))
                if c is None or c <= 0:
                    # Cisco emits "0.0" for unpopulated CPU sockets — same
                    # filter the legacy XMLAPI path used.
                    continue
                temps.append({
                    "name":    t.get("Name"),
                    "celsius": c,
                    "reading": c,
                    "units":   "°C",
                    "health":  (t.get("Status") or {}).get("Health"),
                    "upperCritical":   _to_float(t.get("UpperThresholdCritical")),
                    "upperNonCritical":_to_float(t.get("UpperThresholdNonCritical")),
                })

            for f in thermal.get("Fans") or []:
                if (f.get("Status") or {}).get("State") != "Enabled":
                    continue
                rpm = _to_int(f.get("ReadingRPM") or f.get("Reading"))
                name = f.get("FanName") or f.get("Name") or "Fan"
                fans.append({
                    "name":    name,
                    "reading": rpm,
                    "units":   f.get("ReadingUnits", "RPM"),
                    "health":  (f.get("Status") or {}).get("Health"),
                })

        if not isinstance(power, Exception):
            for v in power.get("Voltages") or []:
                if (v.get("Status") or {}).get("State") != "Enabled":
                    continue
                vv = _to_float(v.get("ReadingVolts"))
                if vv is None:
                    continue
                volts.append({
                    "name":    v.get("Name"),
                    "reading": vv,
                    "units":   "V",
                    "health":  (v.get("Status") or {}).get("Health"),
                })

        return {
            "source":       "redfish",
            "temperatures": temps,
            "fans":         fans,
            "voltages":     volts,
        }

    # ── actions ───────────────────────────────────────────────────────────────

    _RF_RESET_TYPES = {
        "power_on":          "On",
        "power_off":         "ForceOff",
        "power_cycle":       "ForceRestart",
        "hard_reset":        "ForceRestart",
        "graceful_shutdown": "GracefulShutdown",
        "graceful_restart":  "GracefulRestart",
    }

    async def execute_action(self, action: dict) -> dict:
        atype = action.get("type")
        if atype in self._RF_RESET_TYPES:
            try:
                sys = await self._rf_system()
            except Exception as e:
                return {"error": f"Redfish: {e}"}
            target = (
                ((sys.get("Actions") or {}).get("#ComputerSystem.Reset") or {}).get("target")
                or f"/redfish/v1/Systems/{self._rf_system_id}/Actions/ComputerSystem.Reset"
            )
            try:
                await self._rf_request(
                    "POST", target,
                    json={"ResetType": self._RF_RESET_TYPES[atype]},
                    headers={"Content-Type": "application/json"},
                )
                return {"ok": True}
            except Exception as e:
                return {"error": f"Redfish: {e}"}
        # KVM JNLP minting still goes through XMLAPI — Redfish 1.0 on
        # 3.0(4r) doesn't surface a kvm.jnlp action. The XMLAPI flow is
        # inherited from CIMCAdapter unchanged. main.py rewrites the JAR
        # URLs in the response to point at our /api/cimc-kvm-proxy
        # endpoint, because CIMC 3.0+ returns 403 on every HEAD against
        # /software/* and JWS HEAD-validates cached JARs regardless of
        # the JNLP <update> element.
        if atype == "kvm_launch":
            return await self._kvm_jnlp()
        return {"error": f"Unsupported action: {atype!r}"}
