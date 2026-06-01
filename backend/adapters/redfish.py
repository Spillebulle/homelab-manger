"""
Generic Redfish adapter — supports:
  HP iLO 5+ (full Redfish 1.6+)
  Dell iDRAC 8+ (Redfish 1.0+)
  Huawei iBMC (Redfish 1.0+)

For HP iLO 4 only the /status key works (no full Redfish on that version).
"""
import asyncio
import re
from typing import Any
import httpx
from .base import BaseAdapter


# pysnmp 7.x leaks when SnmpEngine() is built repeatedly — and the Huawei
# enrichment path used to build ~4 per poll cycle, per iBMC device (one each in
# _huawei_enrich / _huawei_enrich_power / _huawei_pcie_cards /
# _huawei_chassis_model). Each engine drags in a large MIB/config datastore that
# close_dispatcher() doesn't fully reclaim, AND leaves a UDP transport registered
# on the event loop that the loop keeps servicing forever. The observed symptom
# was a container creeping to multi-GB RAM and one core pinned at 100%, getting
# "slower and slower" as orphaned transports accumulated. Fix: build exactly one
# engine/USM/transport per (host, port, USM identity) and reuse it for the life
# of the process — never close the dispatcher. The poller and every HTTP handler
# share uvicorn's single event loop, so a cached transport stays bound to a live
# loop. Keyed including the secrets so a credential change rebuilds cleanly (the
# stale engine leaks once, which is acceptable for a rare event).
_SNMP_SETUP_CACHE: dict[tuple, tuple] = {}


class RedfishAdapter(BaseAdapter):
    # Redfish exposes both a graceful (GracefulShutdown) and a forced (ForceOff)
    # power-down — see _RESET_TYPES — so both are valid UPS-shutdown targets.
    SHUTDOWN_ACTIONS = ["graceful_shutdown", "power_off"]

    # One adapter class serves redfish / ilo / idrac / ibmc. The base requirement
    # is HTTPS on the configured port. Huawei iBMC gets an extra SNMPv3 hint
    # added at runtime — see `requirements()` — because Redfish 1.0 there
    # doesn't expose CPU model / DIMM type / PCIe inventory and we backfill
    # via the Huawei MIB.
    REQUIREMENTS = [
        {
            "service": "HTTPS (Redfish)",
            "transport": "redfish",
            "port": 443,
            "description": "BMC Redfish service root + Systems/Chassis subtrees",
            "required": True,
        },
    ]

    # iBMC-specific extension surfaced when the user picks the `ibmc` adapter
    # type. We can't introspect manufacturer from credentials alone, so the
    # endpoint layer pre-injects this when adapter_type=='ibmc'.
    IBMC_EXTRA_REQUIREMENTS = [
        {
            "service": "SNMPv3",
            "transport": "snmpv3",
            "port": 161,
            "description": "Backfills CPU model, DIMM type, PCIe inventory not exposed via Redfish 1.0.2",
            "required": False,
        },
    ]

    def requirements(self) -> list[dict]:
        port = int(self.credentials.get("port") or 443)
        out = [{**r, "port": port} for r in self.REQUIREMENTS]
        if self.adapter_type == "ibmc":
            snmp_port = int(self.credentials.get("snmp_port") or 161)
            out += [{**r, "port": snmp_port} for r in self.IBMC_EXTRA_REQUIREMENTS]
        return out

    def __init__(self, hostname: str, credentials: dict):
        super().__init__(hostname, credentials)
        self.username = credentials.get("username", "admin")
        self.password = credentials.get("password", "")
        self.port     = int(credentials.get("port", 443))
        self.base     = f"https://{hostname}:{self.port}"
        # Some vendors use /redfish/v1/Systems/System.Embedded.1 (Dell), or /1 (HP/Huawei)
        self.system_id = credentials.get("system_id", "1")
        # Filled lazily when Basic Auth gets a 401 (Huawei iBMC rejects Basic).
        self._auth_token: str | None = None
        self._session_uri: str | None = None
        # System object cache — vendors disagree on subcollection paths, so we
        # fetch the System once and follow @odata.id links instead of guessing.
        self._system_cache: dict | None = None
        # Huawei iBMC corrupts response bodies under concurrent fan-out — see
        # _members(). Set to a Semaphore(1) once we know the box is a Huawei.
        self._members_sem: asyncio.Semaphore | None = None

    def get_supported_cache_keys(self) -> list[str]:
        return ["status", "hardware", "storage", "network", "power", "sensors"]

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    async def _login(self) -> None:
        """POST to SessionService for an X-Auth-Token. Required for Huawei iBMC.
        Save the Location header so close() can DELETE the session — Huawei
        enforces a low concurrent-session limit (~4) and will reject new logins
        with `SessionLimitExceeded` if we leak."""
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            r = await c.post(
                f"{self.base}/redfish/v1/SessionService/Sessions",
                json={"UserName": self.username, "Password": self.password},
                headers={"Content-Type": "application/json"},
            )
            r.raise_for_status()
            self._auth_token  = r.headers.get("X-Auth-Token")
            self._session_uri = r.headers.get("Location")

    async def close(self) -> None:
        if not (self._auth_token and self._session_uri):
            return
        # Location can be a full URL or an absolute path; keep just the path.
        path = self._session_uri
        if path.startswith("http"):
            path = path.split("/", 3)[-1]
            if not path.startswith("/"):
                path = "/" + path
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                await c.delete(
                    f"{self.base}{path}",
                    headers={"X-Auth-Token": self._auth_token},
                )
        except Exception:
            pass  # best-effort; session will time out on its own
        self._auth_token = None
        self._session_uri = None

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        headers = kwargs.pop("headers", {}) or {}
        headers.setdefault("Accept", "application/json")

        if self._auth_token:
            headers["X-Auth-Token"] = self._auth_token
            auth = None
        else:
            auth = (self.username, self.password)

        async with httpx.AsyncClient(verify=False, timeout=15, auth=auth) as c:
            r = await c.request(method, f"{self.base}{path}", headers=headers, **kwargs)

        # Basic Auth rejected → fall back to session auth, retry once.
        if r.status_code == 401 and not self._auth_token:
            await self._login()
            headers["X-Auth-Token"] = self._auth_token
            async with httpx.AsyncClient(verify=False, timeout=15) as c:
                r = await c.request(method, f"{self.base}{path}", headers=headers, **kwargs)

        r.raise_for_status()
        return r.json() if r.content else {}

    async def _get(self, path: str) -> dict:
        return await self._request("GET", path)

    async def _post(self, path: str, data: dict) -> dict:
        return await self._request("POST", path, json=data,
                                   headers={"Content-Type": "application/json"})

    async def _members(self, collection: dict) -> list[dict]:
        # Huawei iBMC mis-routes concurrent Redfish responses (e.g. DIMM010's
        # GET returns DIMM030's JSON body) at any fan-out > 1, with no
        # deterministic ceiling — caps of 2, 4, and 8 all scramble in some
        # trials. Serialise on Huawei; everywhere else stays full-parallel.
        sem = self._members_sem
        if sem is None:
            tasks = [self._get(m["@odata.id"]) for m in collection.get("Members", [])]
        else:
            async def _gated(uri: str):
                async with sem:
                    return await self._get(uri)
            tasks = [_gated(m["@odata.id"]) for m in collection.get("Members", [])]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]

    async def _system(self, sid: str) -> dict:
        if self._system_cache is None:
            self._system_cache = await self._get(f"/redfish/v1/Systems/{sid}")
            if (self._system_cache.get("Manufacturer") or "").lower().startswith("huawei"):
                self._members_sem = asyncio.Semaphore(1)
        return self._system_cache

    # ── fetch implementations ─────────────────────────────────────────────────

    async def fetch(self, cache_key: str) -> Any:
        sid = self.system_id
        if cache_key == "status":   return await self._status(sid)
        if cache_key == "hardware": return await self._hardware(sid)
        if cache_key == "storage":  return await self._storage(sid)
        if cache_key == "network":  return await self._network(sid)
        if cache_key == "power":    return await self._power()
        if cache_key == "sensors":  return await self._sensors()
        raise ValueError(f"Unknown cache key: {cache_key!r}")

    async def _status(self, sid: str) -> dict:
        s = await self._get(f"/redfish/v1/Systems/{sid}")
        manufacturer = s.get("Manufacturer", "")
        model        = s.get("Model", "")

        # Manager / BMC enrichment — firmware version and management IP. Best-
        # effort: any failure leaves the field null.
        bmc_firmware = ""
        bmc_ip       = ""
        try:
            mgr = await self._first_manager()
            if mgr:
                bmc_firmware = mgr.get("FirmwareVersion", "") or ""
                bmc_ip = await self._first_bmc_ipv4(mgr) or ""
        except Exception:
            pass

        # Huawei System.Model is the marketing/configuration name (e.g.
        # "FusionStorage File/Object Node"); the real hardware platform comes
        # from the private MIB. Only swap in the SNMP value when present and
        # non-trivial (the OID returns "0" or empty on some firmwares).
        if manufacturer.lower().startswith("huawei"):
            try:
                real = await self._huawei_chassis_model()
                if real and real != "0":
                    model = real
            except Exception:
                pass

        return {
            "online":       True,
            "manufacturer": manufacturer,
            "model":        model,
            "hostname":     s.get("HostName", ""),
            "serial":       s.get("SerialNumber", ""),
            "powerState":   s.get("PowerState", ""),
            "health":       s.get("Status", {}).get("Health", ""),
            "bmcIp":        bmc_ip,
            "bmcFirmware":  bmc_firmware,
            "biosVersion":  s.get("BiosVersion", ""),
            "uuid":         s.get("UUID", ""),
        }

    async def _first_manager(self) -> dict | None:
        """Return the first Manager (BMC) object, or None if absent."""
        idx = await self._get("/redfish/v1/Managers")
        for member in (idx.get("Members") or []):
            url = member.get("@odata.id")
            if url:
                return await self._get(url)
        return None

    async def _first_bmc_ipv4(self, mgr: dict) -> str | None:
        """Walk Manager.EthernetInterfaces for the first non-link-local IPv4."""
        eth_url = (mgr.get("EthernetInterfaces") or {}).get("@odata.id")
        if not eth_url:
            return None
        eth_idx = await self._get(eth_url)
        for em in (eth_idx.get("Members") or []):
            url = em.get("@odata.id")
            if not url:
                continue
            iface = await self._get(url)
            for entry in (iface.get("IPv4Addresses") or []):
                addr = entry.get("Address") or ""
                if addr and not addr.startswith(("0.", "169.254.", "127.")):
                    return addr
        return None

    async def _huawei_chassis_model(self) -> str | None:
        """SNMPv3 GET on hwSysModelType for the actual hardware platform.
        Reuses the same auth setup as _huawei_enrich (iBMC's local user
        doubles as the SNMPv3 USM user)."""
        snmp = await self._huawei_snmp_setup()
        if not snmp:
            return None
        engine, usm, transport, ps = snmp
        try:
            it = ps.get_cmd(
                engine, usm, transport, ps.ContextData(),
                ps.ObjectType(ps.ObjectIdentity(self._HUAWEI_CHASSIS_MODEL_OID)),
            )
            err_ind, err_stat, _err_idx, vbs = await it
            if err_ind or err_stat:
                return None
            for _name, value in vbs:
                s = str(value).strip()
                return s or None
        except Exception:
            return None
        return None

    # Huawei iBMC (Redfish 1.0.2) leaves Processor.Model as the literal stub
    # "Central Processor" and exposes no Description and no Oem extension. The
    # only identifier it provides is a raw CPUID dump in ProcessorID (note the
    # all-caps "ID" — non-spec; the standard field is "ProcessorId"). When the
    # Model field is unusable we decode that dump into a microarch codename.
    _GENERIC_CPU_MODEL = {"", "central processor", "cpu", "processor"}

    # Intel family 6 model -> microarch codename. Trimmed to anything plausibly
    # alive in a homelab BMC (Nehalem onward). Source: Intel SDM Vol. 4.
    _INTEL_F6_MICROARCH = {
        0x1A: "Nehalem-EP", 0x1E: "Nehalem", 0x1F: "Nehalem", 0x2E: "Nehalem-EX",
        0x25: "Westmere", 0x2C: "Westmere-EP", 0x2F: "Westmere-EX",
        0x2A: "Sandy Bridge", 0x2D: "Sandy Bridge-EP",
        0x3A: "Ivy Bridge", 0x3E: "Ivy Bridge-EP",
        0x3C: "Haswell", 0x3F: "Haswell-EP", 0x45: "Haswell", 0x46: "Haswell",
        0x3D: "Broadwell", 0x47: "Broadwell-H", 0x4F: "Broadwell-EP", 0x56: "Broadwell-DE",
        0x4E: "Skylake", 0x5E: "Skylake", 0x55: "Skylake-SP",
        0x66: "Cannon Lake",
        0x6A: "Ice Lake-SP", 0x6C: "Ice Lake-D", 0x7D: "Ice Lake", 0x7E: "Ice Lake",
        0x8C: "Tiger Lake", 0x8D: "Tiger Lake-H",
        0x8E: "Kaby/Coffee Lake", 0x9E: "Kaby/Coffee Lake",
        0xA5: "Comet Lake", 0xA6: "Comet Lake", 0xA7: "Rocket Lake",
        0x97: "Alder Lake", 0x9A: "Alder Lake", 0xBA: "Raptor Lake", 0xBF: "Raptor Lake",
        0x8F: "Sapphire Rapids", 0xCF: "Emerald Rapids",
        0xAA: "Meteor Lake", 0xAD: "Granite Rapids", 0xAE: "Granite Rapids",
        0xC6: "Sierra Forest",
    }
    _AMD_FAMILY_MICROARCH = {
        0x15: "Bulldozer/Piledriver", 0x16: "Jaguar/Puma",
        0x17: "Zen/Zen+/Zen 2", 0x19: "Zen 3/Zen 4", 0x1A: "Zen 5",
    }

    @classmethod
    def _decode_cpuid(cls, regs: str, manufacturer: str | None) -> str | None:
        # IdentificationRegisters is 8 little-endian bytes: EAX (0..3) and
        # EDX (4..7) from CPUID leaf 1. We only need EAX for family/model.
        parts = re.split(r"[-:\s]+", (regs or "").strip())
        try:
            b = [int(p, 16) for p in parts[:4]]
        except ValueError:
            return None
        if len(b) < 4:
            return None
        eax = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)
        base_model  = (eax >> 4)  & 0xF
        base_family = (eax >> 8)  & 0xF
        ext_model   = (eax >> 16) & 0xF
        ext_family  = (eax >> 20) & 0xFF
        family = base_family + (ext_family if base_family == 0xF else 0)
        model  = (ext_model << 4) | base_model if base_family in (0x6, 0xF) else base_model
        vendor = (manufacturer or "").lower()
        if "intel" in vendor:
            arch = cls._INTEL_F6_MICROARCH.get(model) if family == 0x6 else None
            return f"Intel {arch}" if arch else f"Intel (family {family:#x}, model {model:#x})"
        if "amd" in vendor or "advanced micro" in vendor:
            arch = cls._AMD_FAMILY_MICROARCH.get(family)
            return f"AMD {arch}" if arch else f"AMD (family {family:#x}, model {model:#x})"
        return f"family {family:#x}, model {model:#x}"

    @classmethod
    def _cpu_model(cls, cpu: dict) -> str | None:
        for candidate in (cpu.get("Model"), cpu.get("Description")):
            s = (candidate or "").strip()
            if s and s.lower() not in cls._GENERIC_CPU_MODEL:
                return s
        pid = cpu.get("ProcessorID") or cpu.get("ProcessorId") or {}
        regs = pid.get("IdentificationRegisters") or pid.get("VendorId")
        if regs:
            decoded = cls._decode_cpuid(regs, cpu.get("Manufacturer"))
            if decoded:
                return decoded
        return (cpu.get("Model") or "").strip() or None

    # Huawei Server MIB:
    #   .15.50.1.4.{cpuIdx}      hwCPUInfoModelName  e.g. "Intel(R) Xeon(R) ..."
    #   .16.50.1.10.{memIdx}     hwMemoryInfoLocation slot name e.g. "DIMM000",
    #                                                  or "0" for an empty/absent slot
    #   .16.50.1.11.{memIdx}     hwMemoryInfoType     e.g. "DDR4"
    # (Neighbouring .15.50.1.7.x is a *status* int, not a name — don't use it.)
    _HUAWEI_CPU_MODEL_OID    = "1.3.6.1.4.1.2011.2.235.1.1.15.50.1.4"
    _HUAWEI_MEM_SLOT_OID     = "1.3.6.1.4.1.2011.2.235.1.1.16.50.1.10"
    _HUAWEI_MEM_TYPE_OID     = "1.3.6.1.4.1.2011.2.235.1.1.16.50.1.11"
    # System.Model on iBMC carries the marketing string (e.g. "FusionStorage
    # File/Object Node"). The actual hardware platform (e.g. "5288 V3") lives
    # on hwSysModelType in the private MIB.
    _HUAWEI_CHASSIS_MODEL_OID = "1.3.6.1.4.1.2011.2.235.1.1.1.6.0"

    # PCIe card inventory at .19.50.1.X. Discovered by walking on a
    # FusionStorage 5288 V3:
    #   .19.50.1.2.X  hwPCIeCardManufacturer  e.g. "Huawei"
    #   .19.50.1.3.X  hwPCIeCardBoardId       Huawei internal code, e.g. "BC11HGSE"
    #   .19.50.1.4.X  hwPCIeCardSerialNumber  e.g. "022BJKCNJ6004468"
    #   .19.50.1.9.X  hwPCIeCardName          friendly name when present, else
    #                                          falls back to the system marketing
    #                                          string (e.g. "FusionStorage File/
    #                                          Object Node") for embedded NICs
    # Use Col 9 when meaningful, fall back to Col 3 (BoardId) when it's empty
    # or matches the system-level marketing name.
    _HUAWEI_PCIE_BASE        = "1.3.6.1.4.1.2011.2.235.1.1.19.50.1"
    _HUAWEI_PCIE_MFG_OID     = _HUAWEI_PCIE_BASE + ".2"
    _HUAWEI_PCIE_BOARDID_OID = _HUAWEI_PCIE_BASE + ".3"
    _HUAWEI_PCIE_SERIAL_OID  = _HUAWEI_PCIE_BASE + ".4"
    _HUAWEI_PCIE_NAME_OID    = _HUAWEI_PCIE_BASE + ".9"
    # PSU subtree (.6.50). Discovered by walking the Huawei MIB on a
    # FusionStorage node; col 4 = model name, col 6 = rated W, col 8 = live
    # input watts, col 13 = "PS1"/"PS2". No output-watts column exists on
    # this firmware — only input. Sum of col 8 across PSUs ≈
    # PowerControl[0].PowerConsumedWatts (~6W of measurement noise).
    _HUAWEI_PSU_INPUT_OID    = "1.3.6.1.4.1.2011.2.235.1.1.6.50.1.8"

    async def _huawei_snmp_setup(self):
        """Build (engine, usm, transport, pysnmp-module) for SNMPv3 against
        this iBMC. Returns None if creds aren't sufficient, pysnmp isn't
        installed, or the transport can't be created. Defaults to reusing the
        Redfish username/password (iBMC's local user typically doubles as the
        SNMPv3 USM user). Per-device overrides via snmp_user / snmp_auth_pass /
        snmp_priv_pass / snmp_port / snmp_auth_proto / snmp_priv_proto."""
        user      = self.credentials.get("snmp_user") or self.username
        auth_pass = self.credentials.get("snmp_auth_pass") or self.password
        priv_pass = self.credentials.get("snmp_priv_pass") or self.password
        port      = int(self.credentials.get("snmp_port", 161))
        if not (user and auth_pass and priv_pass):
            return None
        try:
            from pysnmp.hlapi.v3arch import asyncio as ps
        except Exception:
            return None
        auth_map = {
            "sha": ps.USM_AUTH_HMAC96_SHA, "sha1": ps.USM_AUTH_HMAC96_SHA,
            "md5": ps.USM_AUTH_HMAC96_MD5,
            "sha224": ps.USM_AUTH_HMAC128_SHA224, "sha256": ps.USM_AUTH_HMAC192_SHA256,
            "sha384": ps.USM_AUTH_HMAC256_SHA384, "sha512": ps.USM_AUTH_HMAC384_SHA512,
        }
        priv_map = {
            "aes": ps.USM_PRIV_CFB128_AES, "aes128": ps.USM_PRIV_CFB128_AES,
            "aes192": ps.USM_PRIV_CFB192_AES, "aes256": ps.USM_PRIV_CFB256_AES,
            "des": ps.USM_PRIV_CBC56_DES,
        }
        auth_name  = str(self.credentials.get("snmp_auth_proto", "sha")).lower()
        priv_name  = str(self.credentials.get("snmp_priv_proto", "aes")).lower()
        auth_proto = auth_map.get(auth_name, ps.USM_AUTH_HMAC96_SHA)
        priv_proto = priv_map.get(priv_name, ps.USM_PRIV_CFB128_AES)

        # Reuse a cached engine/USM/transport if we've built one for this exact
        # identity — see _SNMP_SETUP_CACHE comment at module level. This is the
        # whole point of the fix: one engine for the life of the process instead
        # of one per poll.
        cache_key = (self.hostname, port, user, auth_pass, priv_pass, auth_name, priv_name)
        cached = _SNMP_SETUP_CACHE.get(cache_key)
        if cached is not None:
            engine, usm, transport = cached
            return engine, usm, transport, ps
        try:
            engine    = ps.SnmpEngine()
            usm       = ps.UsmUserData(user, auth_pass, priv_pass,
                                       authProtocol=auth_proto, privProtocol=priv_proto)
            transport = await ps.UdpTransportTarget.create((self.hostname, port), timeout=4, retries=1)
        except Exception:
            return None
        _SNMP_SETUP_CACHE[cache_key] = (engine, usm, transport)
        return engine, usm, transport, ps

    async def _huawei_enrich(self, cpus: list[dict], memory: list[dict]) -> None:
        """Overlay vendor SNMP data onto the Redfish-derived CPU/memory dicts.
        Best-effort: any failure (no creds, timeout, etc.) leaves the existing
        Redfish/CPUID values in place."""
        setup = await self._huawei_snmp_setup()
        if not setup:
            return
        engine, usm, transport, ps = setup
        try:
            cpu_ids = [c["id"] for c in cpus if c.get("id")]
            snmp_cpus, snmp_mem = await asyncio.gather(
                self._snmp_cpu_models(engine, usm, transport, ps, cpu_ids),
                self._snmp_memory_fields(engine, usm, transport, ps),
                return_exceptions=True,
            )
            if isinstance(snmp_cpus, dict):
                for c in cpus:
                    if (m := snmp_cpus.get(c.get("id"))):
                        c["model"] = m
            if isinstance(snmp_mem, dict):
                for m in memory:
                    rid = m.get("id") or m.get("name") or ""
                    # Redfish ID is e.g. "mainboardDIMM000"; SNMP keys by the
                    # bare slot suffix "DIMM000". Match by suffix.
                    for slot, fields in snmp_mem.items():
                        if rid.endswith(slot):
                            if fields.get("type"):     m["type"] = fields["type"]
                            if fields.get("location"): m["location"] = fields["location"]
                            break
        finally:
            # Intentionally do NOT close_dispatcher(): the engine/transport are
            # cached and reused across poll cycles by _huawei_snmp_setup. Closing
            # would break the next reuse, and the old per-poll create+close cycle
            # was the leak itself (pysnmp 7.x: unbounded RAM growth + a pinned
            # CPU core from orphaned asyncio transports).
            pass

    @staticmethod
    async def _snmp_cpu_models(engine, usm, transport, ps, cpu_ids: list[str]) -> dict[str, str]:
        if not cpu_ids:
            return {}
        ctx = ps.ContextData()
        tasks = [
            ps.get_cmd(engine, usm, transport, ctx,
                       ps.ObjectType(ps.ObjectIdentity(f"{RedfishAdapter._HUAWEI_CPU_MODEL_OID}.{cid}")))
            for cid in cpu_ids
        ]
        out: dict[str, str] = {}
        for cid, (errInd, errStat, _i, vbs) in zip(cpu_ids, await asyncio.gather(*tasks, return_exceptions=False)):
            if errInd or errStat:
                continue
            for _name, val in vbs:
                s = val.prettyPrint().strip()
                if s and not s.startswith("No Such"):
                    out[cid] = s
        return out

    async def _huawei_enrich_power(self, supplies: list[dict]) -> None:
        """Overlay live input wattage onto each PSU dict from the Huawei
        server MIB. iBMC Redfish 1.0.2 returns null for `LastPowerOutputWatts`,
        `PowerOutputWatts`, and `Oem.Huawei.PowerOutputWatts` on this
        firmware, so SNMP is the only path for per-PSU power. Per-PSU
        *output* watts aren't exposed on the MIB either; only `inputWatts`
        is populated. The chassis total stays in `consumedWatts` from the
        Redfish PowerControl block."""
        setup = await self._huawei_snmp_setup()
        if not setup:
            return
        engine, usm, transport, ps = setup
        try:
            ctx = ps.ContextData()
            powers: dict[str, str] = {}
            async for errInd, errStat, _i, vbs in ps.walk_cmd(
                engine, usm, transport, ctx,
                ps.ObjectType(ps.ObjectIdentity(self._HUAWEI_PSU_INPUT_OID)),
                lexicographicMode=False,
            ):
                if errInd or errStat:
                    break
                for name, val in vbs:
                    idx = str(name).rsplit(".", 1)[-1]
                    powers[idx] = val.prettyPrint().strip()
            # Map by ordinal: SNMP row 1 → Redfish supplies[0], etc. iBMC
            # returns bays in stable order so this matches without a
            # name-based join.
            for i, supply in enumerate(supplies):
                raw = powers.get(str(i + 1))
                if raw is None:
                    continue
                try:
                    supply["inputWatts"] = float(raw)
                except (TypeError, ValueError):
                    pass
        finally:
            # Intentionally do NOT close_dispatcher(): the engine/transport are
            # cached and reused across poll cycles by _huawei_snmp_setup. Closing
            # would break the next reuse, and the old per-poll create+close cycle
            # was the leak itself (pysnmp 7.x: unbounded RAM growth + a pinned
            # CPU core from orphaned asyncio transports).
            pass

    async def _huawei_pcie_cards(self) -> list[dict]:
        """Walk the Huawei PCIe inventory table and return a list of
        `{id, manufacturer, model, boardId, serial, class}` dicts. The system
        marketing name (e.g. "FusionStorage File/Object Node") is filtered out
        of `model` and replaced by the Huawei BoardId — embedded NICs that
        don't carry a friendly name fall back to that. Best-effort: returns
        [] on any SNMP failure."""
        setup = await self._huawei_snmp_setup()
        if not setup:
            return []
        engine, usm, transport, ps = setup
        # System marketing name leaks into the per-card "Name" column for
        # cards that have no proper friendly label. We compare against the
        # Redfish System.Model so we know to drop it.
        sys_model = (self._system_cache or {}).get("Model", "") or ""
        try:
            mfg, board_id, serial, name = await asyncio.gather(
                self._snmp_walk_column(engine, usm, transport, ps, self._HUAWEI_PCIE_MFG_OID),
                self._snmp_walk_column(engine, usm, transport, ps, self._HUAWEI_PCIE_BOARDID_OID),
                self._snmp_walk_column(engine, usm, transport, ps, self._HUAWEI_PCIE_SERIAL_OID),
                self._snmp_walk_column(engine, usm, transport, ps, self._HUAWEI_PCIE_NAME_OID),
                return_exceptions=True,
            )
        finally:
            # Intentionally do NOT close_dispatcher(): the engine/transport are
            # cached and reused across poll cycles by _huawei_snmp_setup. Closing
            # would break the next reuse, and the old per-poll create+close cycle
            # was the leak itself (pysnmp 7.x: unbounded RAM growth + a pinned
            # CPU core from orphaned asyncio transports).
            pass

        def _safe(d):
            return d if isinstance(d, dict) else {}

        mfg, board_id, serial, name = _safe(mfg), _safe(board_id), _safe(serial), _safe(name)
        all_indices = sorted(set(mfg) | set(board_id) | set(serial) | set(name), key=lambda x: int(x) if x.isdigit() else 9999)

        out: list[dict] = []
        for idx in all_indices:
            bid = (board_id.get(idx) or "").strip()
            raw_name = (name.get(idx) or "").strip()
            # Drop system-marketing-name fallbacks; use BoardId in their place.
            if raw_name and raw_name == sys_model:
                raw_name = ""
            model = raw_name or bid
            if not model:
                continue
            out.append({
                "id":            idx,
                "manufacturer":  (mfg.get(idx) or "").strip() or None,
                "model":         model,
                "boardId":       bid or None,
                "serial":        (serial.get(idx) or "").strip() or None,
                "class":         self._classify_pcie_card(bid, raw_name),
            })
        return out

    @staticmethod
    async def _snmp_walk_column(engine, usm, transport, ps, oid: str) -> dict[str, str]:
        """Walk a single SNMP column, return {row-index: stringified-value}."""
        out: dict[str, str] = {}
        async for errInd, errStat, _i, vbs in ps.walk_cmd(
            engine, usm, transport, ps.ContextData(),
            ps.ObjectType(ps.ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if errInd or errStat:
                break
            for name, val in vbs:
                idx = str(name).rsplit(".", 1)[-1]
                out[idx] = val.prettyPrint().strip()
        return out

    @staticmethod
    def _classify_pcie_card(board_id: str, model: str) -> str | None:
        """Heuristic card classifier used to populate the Class column.
        Pattern-matches Huawei BoardId prefixes (BC1x = NIC, BC5x/BC6x = RAID,
        BC8x = GPU) and falls back to scanning the friendly model string for
        common keywords."""
        bid = (board_id or "").upper()
        mdl = (model or "").upper()
        if any(s in mdl for s in ("RAID", "MEGARAID", "HBA", "SR430", "SR440", "SR130", "SR150", "SR160")):
            return "RAID"
        if any(s in mdl for s in ("ETHERNET", "GBASE", "10GE", "25GE", "40GE", "100GE", "NIC")):
            return "Network"
        if "GPU" in mdl or "TESLA" in mdl or "INFINIBAND" in mdl:
            return "GPU/Accel"
        if bid.startswith("BC1") or bid.startswith("BC2"):
            return "Network"
        if bid.startswith("BC5") or bid.startswith("BC6"):
            return "RAID"
        if bid.startswith("BC8"):
            return "GPU/Accel"
        return None

    @staticmethod
    async def _snmp_memory_fields(engine, usm, transport, ps) -> dict[str, dict]:
        async def _walk(oid: str) -> dict[str, str]:
            out: dict[str, str] = {}
            async for errInd, errStat, _i, vbs in ps.walk_cmd(
                engine, usm, transport, ps.ContextData(),
                ps.ObjectType(ps.ObjectIdentity(oid)),
                lexicographicMode=False,
            ):
                if errInd or errStat:
                    break
                for name, val in vbs:
                    idx = str(name).rsplit(".", 1)[-1]
                    out[idx] = val.prettyPrint().strip()
            return out

        slots, types = await asyncio.gather(
            _walk(RedfishAdapter._HUAWEI_MEM_SLOT_OID),
            _walk(RedfishAdapter._HUAWEI_MEM_TYPE_OID),
        )
        result: dict[str, dict] = {}
        for idx, slot in slots.items():
            # iBMC fills unpopulated slots with "0" — skip those.
            if not slot or slot == "0":
                continue
            result[slot] = {"location": slot, "type": types.get(idx) or None}
        return result

    async def _hardware(self, sid: str) -> dict:
        sys = await self._system(sid)
        proc_uri = (sys.get("Processors") or {}).get("@odata.id") or f"/redfish/v1/Systems/{sid}/Processors"
        mem_uri  = (sys.get("Memory")     or {}).get("@odata.id") or f"/redfish/v1/Systems/{sid}/Memory"
        proc_col, mem_col = await asyncio.gather(
            self._get(proc_uri),
            self._get(mem_uri),
            return_exceptions=True,
        )

        cpus = []
        if not isinstance(proc_col, Exception):
            for cpu in await self._members(proc_col):
                cpus.append({
                    "id":         cpu.get("Id"),
                    "model":      self._cpu_model(cpu),
                    "manufacturer":cpu.get("Manufacturer"),
                    "totalCores": cpu.get("TotalCores"),
                    "totalThreads":cpu.get("TotalThreads"),
                    "maxSpeedMHz":cpu.get("MaxSpeedMHz"),
                    "arch":       cpu.get("ProcessorArchitecture"),
                    "health":     cpu.get("Status", {}).get("Health"),
                })

        memory = []
        if not isinstance(mem_col, Exception):
            for dimm in await self._members(mem_col):
                if dimm.get("Status", {}).get("State") == "Enabled":
                    memory.append({
                        "id":          dimm.get("Id"),
                        "name":        dimm.get("Name"),
                        "capacityMiB": dimm.get("CapacityMiB"),
                        "speedMHz":    dimm.get("OperatingSpeedMhz"),
                        "type":        dimm.get("MemoryDeviceType"),
                        "manufacturer":dimm.get("Manufacturer"),
                        "serial":      dimm.get("SerialNumber"),
                        "partNumber":  dimm.get("PartNumber"),
                    })

        # Huawei iBMC's Redfish 1.0 schema is so thin that CPU model strings,
        # DIMM type, and DIMM slot location are all missing. Overlay them from
        # the Huawei Server MIB over SNMPv3. Gated on the System Manufacturer
        # to avoid per-poll SNMP timeouts on iLO / iDRAC.
        pcie: list[dict] = []
        if (sys.get("Manufacturer") or "").lower().startswith("huawei"):
            await self._huawei_enrich(cpus, memory)
            # iBMC Redfish 1.0.2 has no PCIeDevices endpoint at all. The
            # Huawei MIB has the inventory; surface it here so the Hardware
            # tab's PCIe sub-tab is populated.
            try:
                pcie = await self._huawei_pcie_cards()
            except Exception:
                pcie = []

        return {"cpus": cpus, "memory": memory, "pcie": pcie}

    async def _storage(self, sid: str) -> dict:
        # Huawei iBMC reports this collection at /Systems/{sid}/Storages (with
        # an 's'), not the standard /Storage. Follow the link from the System
        # object so we don't hardcode either spelling.
        sys = await self._system(sid)
        storage_uri = (sys.get("Storage") or {}).get("@odata.id") or f"/redfish/v1/Systems/{sid}/Storage"
        try:
            col = await self._get(storage_uri)
        except Exception as e:
            return {"error": str(e)}

        controllers: list[dict] = []
        disks: list[dict] = []

        for ctrl in await self._members(col):
            controllers.append({
                "id":     ctrl.get("Id"),
                "name":   ctrl.get("Name"),
                "health": ctrl.get("Status", {}).get("Health"),
            })
            drive_refs = ctrl.get("Drives", [])
            drive_tasks = [self._get(ref["@odata.id"]) for ref in drive_refs]
            drive_results = await asyncio.gather(*drive_tasks, return_exceptions=True)
            for dr in drive_results:
                if isinstance(dr, Exception):
                    continue
                cap = dr.get("CapacityBytes") or 0
                disks.append({
                    "id":               dr.get("Id"),
                    "name":             dr.get("Name"),
                    "model":            dr.get("Model"),
                    "manufacturer":     dr.get("Manufacturer"),
                    "serial":           dr.get("SerialNumber"),
                    "capacityBytes":    cap,
                    "capacityGB":       round(cap / 1e9, 1),
                    "mediaType":        dr.get("MediaType"),
                    "protocol":         dr.get("Protocol"),
                    "health":           dr.get("Status", {}).get("Health"),
                    "rotationRPM":      dr.get("RotationSpeedRPM"),
                    "failurePredicted": dr.get("FailurePredicted", False),
                })

        # Huawei iBMC's StorageController collection has no Manufacturer or
        # Model on this firmware — the controller name is the literal
        # "Storage", which is useless in the UI. Pull the actual RAID card
        # model from the PCIe MIB and inject it as the controller's `model`
        # field. The frontend renders `c.model || c.name`, so this surfaces
        # without further changes.
        if (sys.get("Manufacturer") or "").lower().startswith("huawei") and controllers:
            try:
                cards = await self._huawei_pcie_cards()
            except Exception:
                cards = []
            raid = next((c for c in cards if c.get("class") == "RAID"), None)
            if raid:
                for ctrl in controllers:
                    nm = (ctrl.get("name") or "").strip().lower()
                    if not ctrl.get("model") and nm in ("", "storage"):
                        ctrl["model"]        = raid["model"]
                        ctrl["manufacturer"] = raid.get("manufacturer")
                        ctrl["boardId"]      = raid.get("boardId")

        return {"controllers": controllers, "disks": disks}

    async def _network(self, sid: str) -> dict:
        # Huawei iBMC exposes only EthernetInterfaces (no NetworkInterfaces);
        # HP/Dell expose both. Follow whichever the System object advertises.
        sys = await self._system(sid)
        uri = (
            (sys.get("NetworkInterfaces") or {}).get("@odata.id")
            or (sys.get("EthernetInterfaces") or {}).get("@odata.id")
        )
        if not uri:
            return {"adapters": []}
        try:
            col = await self._get(uri)
            adapters = []
            for n in await self._members(col):
                adapters.append({
                    "id":     n.get("Id"),
                    "name":   n.get("Name"),
                    "mac":    n.get("PermanentMACAddress") or n.get("MACAddress"),
                    "speed":  n.get("SpeedMbps"),
                    "health": n.get("Status", {}).get("Health"),
                    "link":   n.get("LinkStatus"), # <-- Add this line
                })
            return {"adapters": adapters}
        except Exception as e:
            return {"error": str(e)}

    async def _power(self) -> dict:
        try:
            chassis = await self._get("/redfish/v1/Chassis/1/Power")
        except Exception as e:
            return {"error": str(e)}

        supplies = []
        for p in chassis.get("PowerSupplies", []):
            # 1. Try standard modern Redfish
            watts = p.get("LastPowerOutputWatts")
            
            # 2. Try older Redfish standard (common on iBMC)
            if watts is None:
                watts = p.get("PowerOutputWatts")
            
            # 3. Try Huawei OEM custom extensions
            if watts is None:
                oem = p.get("Oem", {})
                if isinstance(oem, dict):
                    huawei_oem = oem.get("Huawei", {})
                    if isinstance(huawei_oem, dict):
                        watts = huawei_oem.get("PowerOutputWatts")

            supplies.append({
                "name":                p.get("Name"),
                "model":               p.get("Model"),
                "manufacturer":        p.get("Manufacturer"),
                "powerSupplyType":     p.get("PowerSupplyType"),
                "firmwareVersion":     p.get("FirmwareVersion"),
                "lineInputVoltage":    p.get("LineInputVoltage"),
                "serial":              p.get("SerialNumber"),
                "lastOutputWatts":     watts,
                "capacityWatts":       p.get("PowerCapacityWatts"),
                "health":              p.get("Status", {}).get("Health"),
                "state":               p.get("Status", {}).get("State"),
            })

        consumed = None
        for ctrl in chassis.get("PowerControl", []):
            consumed = ctrl.get("PowerConsumedWatts")

        # Huawei iBMC: Redfish 1.0.2 doesn't populate per-PSU watts. Pull
        # them from the Huawei server MIB instead. Gated on Manufacturer to
        # avoid SNMP timeouts on iLO / iDRAC. Relies on `_status` having
        # already populated `_system_cache`; the poller's fetch order
        # (status → ... → power) guarantees that.
        sys_cache = self._system_cache or {}
        if (sys_cache.get("Manufacturer") or "").lower().startswith("huawei"):
            await self._huawei_enrich_power(supplies)

        return {"supplies": supplies, "consumedWatts": consumed}

    async def _sensors(self) -> dict:
        try:
            thermal = await self._get("/redfish/v1/Chassis/1/Thermal")
        except Exception as e:
            return {"error": str(e)}

        temps = []
        for t in thermal.get("Temperatures", []):
            # Must be enabled
            if t.get("Status", {}).get("State") != "Enabled":
                continue
            
            celsius = t.get("ReadingCelsius")
            
            # Sanity check: Filter out iBMC junk values (-59, -60, 0) 
            # that indicate an unpopulated socket or powered-off state
            if celsius is None or celsius <= 0:
                continue

            temps.append({
                "name":        t.get("Name"),
                "celsius":     celsius,
                "fatalLimit":  t.get("UpperThresholdFatal"),
                "health":      t.get("Status", {}).get("Health"),
            })

        fans = [
            {
                "name":    f.get("Name"),
                "reading": f.get("Reading"),
                "units":   f.get("ReadingUnits", "RPM"),
                "health":  f.get("Status", {}).get("Health"),
            }
            for f in thermal.get("Fans", [])
            if f.get("Status", {}).get("State") == "Enabled"
        ]

        return {"temperatures": temps, "fans": fans}

    # ── actions ───────────────────────────────────────────────────────────────

    _RESET_TYPES = {
        "power_on":          "On",
        "power_off":         "ForceOff",
        "power_cycle":       "ForceRestart",
        "graceful_shutdown": "GracefulShutdown",
        "graceful_restart":  "GracefulRestart",
    }

    async def execute_action(self, action: dict) -> dict:
        atype = action.get("type")
        if atype in self._RESET_TYPES:
            sid = self.system_id
            try:
                await self._post(
                    f"/redfish/v1/Systems/{sid}/Actions/ComputerSystem.Reset",
                    {"ResetType": self._RESET_TYPES[atype]},
                )
                return {"ok": True}
            except Exception as e:
                return {"error": str(e)}

        if atype == "kvm_launch":
            # Currently only iBMC supports JNLP via this adapter
            return await self.get_ibmc_jnlp()

        return {"error": f"Unsupported action: {atype!r}"}

    async def get_ibmc_jnlp(self) -> dict:
        """
        Robust JNLP fetcher with support for multiple iBMC firmware generations.
        Tries modern Redfish-adjacent login first, falls back to legacy PHP-based login.
        For legacy login, uses a 'hybrid' approach: requests tokens via DirectKVM+IsKvmApp=1
        and injects them into the JNLP template fetched via IsKvmApp=0.
        """
        import logging
        logger = logging.getLogger(__name__)

        paths = ["/bmc/pages/remote/kvm.php", "/kvmvmm.asp", "/remoteconsole"]
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/javascript, */*",
            "X-Requested-With": "XMLHttpRequest"
        }

        async with httpx.AsyncClient(verify=False, timeout=15, headers=headers, follow_redirects=True) as client:
            # --- Attempt 1: Modern iBMC Login (/UI/rest/login) ---
            login_url = f"{self.base}/UI/rest/login"
            client.headers.update({"Referer": f"{self.base}/login.html"})

            try:
                r = await client.post(login_url, json={"UserName": self.username, "Password": self.password})
                if r.status_code == 200:
                    csrf_token = r.headers.get("X-CSRF-Token") or r.headers.get("CSRFToken")
                    if not csrf_token:
                        try:
                            data = r.json()
                            csrf_token = data.get("csrfToken") or data.get("token")
                        except Exception as exc:
                            logger.debug("iBMC modern login: CSRF JSON parse failed: %s", exc)

                    if csrf_token:
                        logger.info("iBMC Login successful via modern API")
                        return await self._fetch_jnlp_with_token(client, csrf_token, paths)
            except Exception as e:
                logger.debug(f"Modern iBMC login attempt failed: {e}")

            # --- Attempt 2: Legacy iBMC Login Hybrid (DirectKVM + IsKvmApp=1) ---
            login_url = f"{self.base}/bmc/php/processparameter.php"
            client.headers.update({"Referer": f"{self.base}/index.php"})

            # First hit index to ensure cookies are initialized
            await client.get(f"{self.base}/index.php")

            try:
                # DirectKVM with IsKvmApp=1 returns the actual auth tokens in JSON
                login_payload = {
                    "user_name": self.username,
                    "check_pwd": self.password,
                    "logtype": "0",
                    "func": "DirectKVM",
                    "IsKvmApp": "1"
                }
                r = await client.post(login_url, data=login_payload)
                if r.status_code == 200:
                    resp = r.json()
                    # Extract the authorized tokens
                    tokens = {
                        "vv": str(resp['VerifyValue'][0]),
                        "dk": resp['Decrykey'][0],
                        "pr": str(resp['Privilege'][0])
                    }

                    r_token = await client.post(f"{self.base}/bmc/php/gettoken.php")
                    csrf_token = r_token.text.strip()
                    if csrf_token:
                        logger.info("iBMC Login successful via legacy PHP API (Hybrid DirectKVM)")
                        return await self._fetch_jnlp_with_token(client, csrf_token, paths, inject_tokens=tokens)
            except Exception as e:
                logger.debug(f"Legacy Hybrid DirectKVM attempt failed: {e}")

            # --- Attempt 3: Legacy iBMC Login Fallback (AddSession) ---
            try:
                login_payload["func"] = "AddSession"
                login_payload["IsKvmApp"] = "0"
                r = await client.post(login_url, data=login_payload)
                if r.status_code == 200:
                    r_token = await client.post(f"{self.base}/bmc/php/gettoken.php")
                    csrf_token = r_token.text.strip()
                    if csrf_token:
                        logger.info("iBMC Login successful via legacy PHP API (AddSession)")
                        return await self._fetch_jnlp_with_token(client, csrf_token, paths)
            except Exception as e:
                logger.error(f"Legacy AddSession attempt failed: {e}")

            return {"error": "Authentication failed for all known iBMC login methods."}

    async def _fetch_jnlp_with_token(self, client: httpx.AsyncClient, token: str, paths: list[str], inject_tokens: dict = None) -> dict:
        """Helper to try multiple JNLP paths with a valid CSRF token."""
        client.headers.update({
            "X-CSRF-Token": token,
            "Accept": "application/x-java-jnlp-file, */*",
            "Referer": f"{self.base}/index.html"
        })

        last_err = "No paths attempted"
        for path in paths:
            try:
                r = await client.get(f"{self.base}{path}")
                if r.status_code == 200:
                    content = r.text.strip()
                    if content.startswith("<?xml") or "<jnlp" in content:
                        if inject_tokens:
                            import re
                            vv = inject_tokens["vv"]
                            dk = inject_tokens["dk"]
                            pr = inject_tokens["pr"]
                            content = re.sub(r'name="verifyValue" value="[^"]*"', f'name="verifyValue" value="{vv}"', content)
                            content = re.sub(r'name="mmVerifyValue" value="[^"]*"', f'name="mmVerifyValue" value="{vv}"', content)
                            content = re.sub(r'name="decrykey" value="[^"]*"', f'name="decrykey" value="{dk}"', content)
                            content = re.sub(r'name="privilege" value="[^"]*"', f'name="privilege" value="{pr}"', content)
                        return {"jnlp": content}
                    last_err = f"Path {path} returned HTML instead of JNLP XML."
                else:
                    last_err = f"Path {path} returned HTTP {r.status_code}"
            except Exception as e:
                last_err = str(e)

        return {"error": f"JNLP fetch failed: {last_err}"}