"""
Cisco CIMC (Integrated Management Controller) adapter.
Uses the NuovaAPI XML interface at https://<host>/nuova.
Tested against CIMC 2.0(9f) on UCS C-series M2/M3 servers.
"""
import asyncio
import json
import re
import ssl
import sys
import time
import xml.etree.ElementTree as ET
from typing import Any
import httpx
from .base import BaseAdapter


def _legacy_ssl_context() -> ssl.SSLContext:
    """CIMC 2.0(9f) ships with a 1024-bit RSA self-signed cert. Modern OpenSSL
    rejects that under its default SECLEVEL=2, raising
    `SSLV3_ALERT_HANDSHAKE_FAILURE` even with `verify=False` (verify only skips
    cert *validation*, not key-size policy). Drop to SECLEVEL=1 to keep TLS 1.2
    + a weak cert acceptable; further drop to 0 only if a particular firmware
    can't even do that."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    return ctx


class CIMCAdapter(BaseAdapter):
    def __init__(self, hostname: str, credentials: dict):
        super().__init__(hostname, credentials)
        self.username = credentials.get("username", "admin")
        self.password = credentials.get("password", "")
        self.port     = int(credentials.get("port", 443))
        self.url      = f"https://{hostname}:{self.port}/nuova"
        self._cookie: str | None = None
        self._ssl_ctx = _legacy_ssl_context()
        # IPMI SDR walk cached per adapter instance — `_sensors` and `_power`
        # both consume it, no point paying ~25s subprocess + retry twice.
        self._ipmi_walked: bool = False
        self._ipmi_readings: list[dict] | None = None
        self._ipmi_err: str | None = None

    def get_supported_cache_keys(self) -> list[str]:
        return ["status", "hardware", "storage", "network", "power", "sensors"]

    # ── XML API helpers ───────────────────────────────────────────────────────

    # CIMC's XML backend periodically replies with "XML API backend server
    # communication failed. Internal error, please retry." Its message tells
    # us to retry, and that's safe for *post-login* calls where we already
    # hold a cookie. We do **not** retry aaaLogin itself — empirically each
    # failed login still consumes one of CIMC's 4 concurrent-session slots,
    # so retrying burns through the cap in a single poll.
    _TRANSIENT_ERROR_FRAGMENTS = ("xml api backend",)

    async def _post_xml_once(self, body: str) -> ET.Element:
        async with httpx.AsyncClient(verify=self._ssl_ctx, timeout=15) as c:
            r = await c.post(self.url, content=body, headers={"Content-Type": "application/xml"})
            r.raise_for_status()
        return ET.fromstring(r.text)

    async def _post_xml(self, body: str) -> ET.Element:
        """POST with retry on transient backend errors. Caller must already
        hold a cookie — DO NOT use this for aaaLogin (see _login)."""
        delay = 0.5
        root: ET.Element | None = None
        for attempt in range(3):
            root = await self._post_xml_once(body)
            descr = (root.get("errorDescr") or "").lower()
            if any(frag in descr for frag in self._TRANSIENT_ERROR_FRAGMENTS) and attempt < 2:
                await asyncio.sleep(delay)
                delay *= 2
                continue
            return root
        return root

    async def _login(self) -> str:
        xml = f'<aaaLogin inName="{self.username}" inPassword="{self.password}"/>'
        root = await self._post_xml_once(xml)
        cookie = root.get("outCookie")
        if not cookie:
            descr = root.get("errorDescr", "")
            raise RuntimeError(f"CIMC login failed: {descr}")
        self._cookie = cookie
        return cookie

    async def close(self) -> None:
        # Free our own slot first via aaaLogout, then SSH in and terminate
        # every other XMLAPI session. Doing it after each poll (instead of
        # before the next one) means the next login sees a clean slate and
        # the "Maximum sessions reached" error never surfaces in the UI.
        # SSH runs on a separate session pool so it always lets us in.
        if self._cookie:
            try:
                await self._post_xml_once(
                    f'<aaaLogout cookie="{self._cookie}" inCookie="{self._cookie}"/>'
                )
            except Exception:
                pass
            self._cookie = None
        try:
            await self._ssh_clear_xmlapi_sessions()
        except Exception:
            pass

    # ── SSH-based session reaper ──────────────────────────────────────────────

    # Block header: "ID 401:" — output of `show user-session detail` at the
    # top-level prompt. The block then carries indented "Type: xmlapi" / "CLI"
    # lines until the next ID block (or EOF).
    _CIMC_SESSION_ID_RE = re.compile(r"^\s*ID\s+(\d+)\s*:\s*$")
    _CIMC_TYPE_RE       = re.compile(r"^\s*Type\s*:\s*(\S+)", re.IGNORECASE)
    # Trailing prompt (e.g. "lin-pancake-01-management# "). We wait for this to
    # show up before sending commands — CIMC's SSH sometimes opens the channel
    # before the prompt is printed and an early `send` gets dropped.
    _CIMC_PROMPT_RE     = re.compile(r"#\s*$")

    async def _ssh_clear_xmlapi_sessions(self) -> int:
        """SSH into the CIMC, terminate every XMLAPI user-session, return the
        count cleared. Returns -1 on SSH error (no creds, refused, auth, etc.).
        Used as recovery when XMLAPI login hits 'Max sessions'.

        Command flow (CIMC 2.0(9f) — `scope user-mgmt` does *not* exist on
        this firmware):
            show user-session detail        → enumerate sessions
            scope user-session <id>; terminate  → kill one (must `top` between IDs)

        Reuses the BMC's username/password by default — homelab CIMCs share
        one local admin account between XMLAPI and CLI. Override per-device
        with credentials keys ssh_username / ssh_password / ssh_port."""
        username = self.credentials.get("ssh_username") or self.username
        password = self.credentials.get("ssh_password") or self.password
        ssh_port = int(self.credentials.get("ssh_port", 22))
        if not (username and password):
            return -1

        loop = asyncio.get_event_loop()

        def _drain(channel, quiet_ms: int = 250, hard_ms: int = 1500,
                   wait_for_prompt: bool = False) -> str:
            """Read until either: the prompt appears (when wait_for_prompt),
            N ms of silence elapses, or the hard timeout fires. Returns
            whatever was read decoded as UTF-8."""
            buf = b""
            start = time.time()
            last = start
            while (time.time() - start) * 1000 < hard_ms:
                if channel.recv_ready():
                    buf += channel.recv(32768)
                    last = time.time()
                    if wait_for_prompt:
                        text = buf.decode("utf-8", errors="replace")
                        if CIMCAdapter._CIMC_PROMPT_RE.search(text.rstrip()):
                            break
                elif (time.time() - last) * 1000 >= quiet_ms:
                    if not wait_for_prompt:
                        break
                    # Still waiting on prompt — keep going until hard_ms.
                    time.sleep(0.05)
                else:
                    time.sleep(0.05)
            return buf.decode("utf-8", errors="replace")

        def _do() -> int:
            import socket as _socket
            import paramiko
            transport = None
            try:
                sock = _socket.create_connection((self.hostname, ssh_port), timeout=8)
                transport = paramiko.Transport(sock)
                transport.start_client(timeout=8)
                transport.auth_password(username, password)
                channel = transport.open_session()
                channel.get_pty(term="vt100", width=200, height=2000)
                channel.invoke_shell()
                # CIMC sometimes returns an empty initial buffer — wait for
                # the prompt explicitly so the next `send` doesn't race.
                _drain(channel, quiet_ms=400, hard_ms=8000, wait_for_prompt=True)

                channel.send("show user-session detail\n")
                output = _drain(channel, quiet_ms=600, hard_ms=10000, wait_for_prompt=True)

                # Parse blocks. Each block starts with `ID N:` and includes a
                # `Type: ...` line. We collect IDs whose Type is xmlapi.
                xmlapi_ids: list[str] = []
                current_id: str | None = None
                for line in output.splitlines():
                    m_id = CIMCAdapter._CIMC_SESSION_ID_RE.match(line)
                    if m_id:
                        current_id = m_id.group(1)
                        continue
                    if current_id is None:
                        continue
                    m_t = CIMCAdapter._CIMC_TYPE_RE.match(line)
                    if m_t:
                        if m_t.group(1).lower().startswith("xml"):
                            xmlapi_ids.append(current_id)
                        current_id = None  # done with this block

                # De-dupe while preserving order.
                seen: set[str] = set()
                unique_ids = [x for x in xmlapi_ids if not (x in seen or seen.add(x))]

                count = 0
                for sid in unique_ids:
                    channel.send("top\n"); _drain(channel)
                    channel.send(f"scope user-session {sid}\n"); _drain(channel)
                    channel.send("terminate\n"); _drain(channel, quiet_ms=400, hard_ms=2500)
                    count += 1

                channel.send("top\n"); _drain(channel)
                channel.send("exit\n")
                return count
            except Exception:
                return -1
            finally:
                if transport is not None:
                    transport.close()

        return await loop.run_in_executor(None, _do)

    async def _xml(self, xml: str) -> ET.Element:
        if not self._cookie:
            await self._login()
        root = await self._post_xml(xml)
        if root.get("errorCode") == "552":  # session expired
            self._cookie = None
            await self._login()
            xml_refreshed = xml.replace(f'cookie="{root.get("cookie", "")}"',
                                        f'cookie="{self._cookie}"')
            root = await self._post_xml(xml_refreshed)
        return root

    async def _resolve_class(self, class_id: str, hierarchical: bool = False) -> list[dict]:
        hier = "true" if hierarchical else "false"
        xml  = f'<configResolveClass cookie="{self._cookie or ""}" classId="{class_id}" inHierarchical="{hier}"/>'
        root = await self._xml(xml)
        out_configs = root.find("outConfigs")
        if out_configs is None:
            return []
        return [dict(elem.attrib) for elem in out_configs]

    async def _conf_mo(self, dn: str, inner_xml: str) -> dict:
        xml = (
            f'<configConfMo cookie="{self._cookie or ""}" dn="{dn}" inHierarchical="false">'
            f"<inConfig>{inner_xml}</inConfig></configConfMo>"
        )
        root = await self._xml(xml)
        if root.get("errorCode"):
            return {"error": f"CIMC {root.get('errorCode')}: {root.get('errorDescr')}"}
        return {"ok": True}

    # ── fetch implementations ─────────────────────────────────────────────────

    async def fetch(self, cache_key: str) -> Any:
        if cache_key == "status":   return await self._status()
        if cache_key == "hardware": return await self._hardware()
        if cache_key == "storage":  return await self._storage()
        if cache_key == "network":  return await self._network()
        if cache_key == "power":    return await self._power()
        if cache_key == "sensors":  return await self._sensors()
        raise ValueError(f"Unknown cache key: {cache_key!r}")

    async def _status(self) -> dict:
        units = await self._resolve_class("computeRackUnit")
        if not units:
            return {"online": False}
        u = units[0]
        return {
            "online":          True,
            "model":           u.get("model", ""),
            "serial":          u.get("serial", ""),
            "uuid":            u.get("uuid", ""),
            "adminPower":      u.get("adminPower", ""),
            "operPower":       u.get("operPower", ""),
            "totalMemoryMB":   u.get("totalMemory", ""),
            "numCpus":         u.get("numOfCpus", ""),
            "numCores":        u.get("numOfCores", ""),
            "numThreads":      u.get("numOfThreads", ""),
            "availMemoryMB":   u.get("availableMemory", ""),
        }

    async def _hardware(self) -> dict:
        cpu_rows, mem_rows, pci_rows = await asyncio.gather(
            self._resolve_class("processorUnit"),
            self._resolve_class("memoryUnit"),
            self._resolve_class("pciEquipSlot"),
        )

        cpus = [
            {
                "id":      r.get("id"),
                "model":   r.get("model"),
                "vendor":  r.get("vendor"),
                "cores":   r.get("cores"),
                "threads": r.get("threads"),
                "speedMHz":r.get("speed"),
                "arch":    r.get("arch"),
                "stepping":r.get("stepping"),
            }
            for r in cpu_rows if r.get("presence") == "equipped"
        ]

        memory = [
            {
                "id":         r.get("id"),
                "location":   r.get("location"),
                "capacityMB": r.get("capacity"),
                "speedMHz":   r.get("clock"),
                "type":       r.get("type"),
                "bank":       r.get("bank"),
                "serial":     r.get("serial"),
            }
            for r in mem_rows if r.get("presence") == "equipped"
        ]

        pcie = [
            {
                "id":      r.get("id"),
                "model":   r.get("model"),
                "vendor":  r.get("vendor"),
                "class":   r.get("pciClass"),
                "dn":      r.get("dn"),
            }
            for r in pci_rows if r.get("model")
        ]

        return {"cpus": cpus, "memory": memory, "pcie": pcie}

    async def _storage(self) -> dict:
        disk_rows, ctrl_rows = await asyncio.gather(
            self._resolve_class("storageLocalDisk"),
            self._resolve_class("storageController"),
        )

        disks = [
            {
                "id":            r.get("id"),
                "dn":            r.get("dn"),
                "model":         r.get("model"),
                "vendor":        r.get("vendor"),
                "serial":        r.get("serialNumber"),
                "coercedSizeMB": r.get("coercedSizeBytes"),
                "rawSizeMB":     r.get("rawSize"),
                "mediaType":     r.get("mediaType"),      # HDD / SSD
                "interface":     r.get("interfaceType"),  # SAS / SATA
                "state":         r.get("diskState"),
                "health":        r.get("health"),
                "linkSpeed":     r.get("linkSpeed"),
                "firmware":      r.get("firmware"),
            }
            for r in disk_rows
        ]

        controllers = [
            {
                "id":       r.get("id"),
                "model":    r.get("model"),
                "vendor":   r.get("vendor"),
                "type":     r.get("type"),
                "firmware": r.get("firmwareVersion"),
                "raid":     r.get("raidSupport"),
                "pciSlot":  r.get("pcieSlot"),
            }
            for r in ctrl_rows if r.get("presence") == "equipped"
        ]

        return {"disks": disks, "controllers": controllers}

    async def _network(self) -> dict:
        nic_rows  = await self._resolve_class("networkAdapterUnit")
        port_rows = await self._resolve_class("networkAdapterEthIf")

        adapters = []
        for port in port_rows:
            port_dn = port.get("dn", "")
            port_id = port.get("id", "Unknown")
            
            # Find the parent physical NIC to grab the hardware model name
            parent_model = "CIMC Network Adapter"
            for nic in nic_rows:
                nic_dn = nic.get("dn", "")
                if nic_dn and port_dn.startswith(nic_dn):
                    parent_model = nic.get("model", parent_model)
                    break
            
            # CIMC usually uses 'operState' instead of 'LinkStatus'
            oper = port.get("operState", "").lower()
            link_status = "LinkUp" if oper in ("up", "link-up", "operable") else "LinkDown"

            adapters.append({
                "id": port_id,
                "name": f"Port {port_id}",
                "model": parent_model,
                "mac": port.get("mac"),
                "link": link_status,
                "health": port.get("operState")  # Optional: exposes state to the top right of the card
            })

        # By omitting the "ports" list here, the frontend table will naturally hide itself
        return {"adapters": adapters}

    # IPMI sensors that give us live power. POWER_USAGE is the system's
    # total draw (matches PSU{n}_PIN summed across active PSUs); per-PSU
    # values come from PSU{n}_PIN (input from the wall) and PSU{n}_POUT
    # (DC output to the system). Sensors with value=None mean the bay is
    # empty / no AC connected on that side.
    _IPMI_PSU_RE = re.compile(r"^PSU(\d+)_(P(?:IN|OUT))$", re.IGNORECASE)

    async def _power(self) -> dict:
        psu_rows, budget_rows = await asyncio.gather(
            self._resolve_class("equipmentPsu"),
            self._resolve_class("computePowerBudget"),
        )

        psus = [
            {
                "id":             r.get("id"),
                "model":          r.get("model"),
                "serial":         r.get("serial"),
                "maxOutputWatts": r.get("maxOutput"),
                "operState":      r.get("operState"),
                "thermal":        r.get("thermal"),
            }
            for r in psu_rows if r.get("presence") == "equipped"
        ]

        budget: dict = {}
        if budget_rows:
            b = budget_rows[0]
            budget = {
                "budgetWatts":   b.get("powerBudget"),
                "consumedWatts": b.get("powerConsumed"),
                "profileType":   b.get("profileType"),
            }

        out: dict = {"psus": psus, "budget": budget}
        await self._enrich_power_with_ipmi(out)
        return out

    async def _enrich_power_with_ipmi(self, power: dict) -> None:
        readings, _ = await self._ipmi_walk_cached()
        if not readings:
            return

        per_psu: dict[str, dict] = {}
        total: float | None = None
        for r in readings:
            if r.get("unavailable") or r.get("value") is None:
                continue
            name = (r.get("name") or "").upper()
            value = r["value"]
            if name == "POWER_USAGE":
                if isinstance(value, (int, float)):
                    total = float(value)
                continue
            m = self._IPMI_PSU_RE.match(name)
            if not m:
                continue
            idx, kind = m.group(1), m.group(2).upper()
            field = "lastOutputWatts" if kind == "POUT" else "inputWatts"
            v = round(value, 1) if isinstance(value, float) else value
            per_psu.setdefault(idx, {})[field] = v

        for psu in power["psus"]:
            extras = per_psu.get(str(psu.get("id")))
            if extras:
                psu.update(extras)

        if total is not None:
            power["totalWatts"] = round(total, 1) if isinstance(total, float) else total

    # pyghmi.constants.Health → frontend healthColor() keys.
    _IPMI_HEALTH_MAP = {0: "OK", 1: "Warning", 2: "Critical", 4: "Critical", 8: "Unknown"}

    async def _sensors(self) -> dict:
        """IPMI is the primary source on CIMC 2.0(9f). XMLAPI's `equipmentFan`
        / `equipmentFanStats` always reports speed=0 on this firmware (RPM
        telemetry isn't wired through), and `computeMbTempStats` only exposes
        CPU temps. IPMI's full SDR adds fan RPMs, PSU/inlet/exhaust temps,
        voltages, and currents. Falls back to a reshaped XMLAPI view if
        IPMI-over-LAN is disabled or pyghmi isn't installed — the user still
        sees CPU temps and fan presence/state, just no RPMs."""
        ipmi, ipmi_err = await self._sensors_via_ipmi()
        if ipmi is not None:
            return ipmi
        xml = await self._sensors_via_xmlapi()
        if ipmi_err:
            xml["ipmi_error"] = ipmi_err
        return xml

    # Inline script for the IPMI subprocess. We run pyghmi in a *subprocess*
    # rather than `run_in_executor` because pyghmi spawns a daemon keepalive
    # thread for its RMCP+ session, and that thread doesn't play well with
    # asyncio's ThreadPoolExecutor — every other call dies mid-SDR-walk with
    # `IpmiException: Session no longer connected`. A subprocess gives pyghmi
    # its own clean process with its own event loop and exits cleanly.
    # `Session no longer connected` shows up mid-walk if the BMC is under
    # XMLAPI load at the same time, so we retry up to 3 times with backoff
    # before giving up. Each attempt creates a fresh Command (and therefore
    # a fresh RMCP+ session) since the prior one is unrecoverable.
    _IPMI_WORKER_SCRIPT = r"""
import json, sys, time, traceback
from pyghmi.ipmi import command as ipmi_command
host, user, pw, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
last_err = None
last_tb  = None
for attempt in range(3):
    try:
        cmd = ipmi_command.Command(bmc=host, userid=user, password=pw, port=port)
        out = []
        for r in cmd.get_sensor_data():
            out.append({
                "name": r.name, "value": r.value, "units": r.units, "type": r.type,
                "states": list(r.states) if r.states else [],
                "health_code": r.health,
                "unavailable": bool(getattr(r, "unavailable", False)),
            })
        print(json.dumps({"ok": True, "readings": out, "attempts": attempt + 1}))
        sys.exit(0)
    except Exception as e:
        last_err = f"{type(e).__name__}: {e}"
        last_tb  = traceback.format_exc()
        time.sleep(1.5 * (attempt + 1))
print(json.dumps({"ok": False, "error": last_err or "unknown", "tb": last_tb or "", "attempts": 3}))
"""

    async def _ipmi_walk_cached(self) -> tuple[list[dict] | None, str | None]:
        """Walk the BMC's SDR via the pyghmi subprocess worker, cache the
        result on the adapter instance. Both `_sensors` and `_power` consume
        the readings; one walk per poll cycle is enough.

        Use stdlib subprocess inside run_in_executor rather than asyncio's
        create_subprocess_exec — on Windows the ProactorEventLoop's pipe
        inheritance breaks pyghmi's RMCP+ session reliably with `Session no
        longer connected` mid-walk, even though the same subprocess command
        invoked synchronously works perfectly. stdlib `subprocess.run` does
        the right thing."""
        if self._ipmi_walked:
            return self._ipmi_readings, self._ipmi_err
        self._ipmi_walked = True

        username  = self.credentials.get("ipmi_username") or self.username
        password  = self.credentials.get("ipmi_password") or self.password
        ipmi_port = int(self.credentials.get("ipmi_port", 623))
        if not (username and password):
            self._ipmi_err = "no IPMI credentials"
            return None, self._ipmi_err

        import subprocess  # noqa: PLC0415

        def _run_worker() -> tuple[int, str, str]:
            try:
                r = subprocess.run(
                    [sys.executable or "python", "-c", self._IPMI_WORKER_SCRIPT,
                     self.hostname, username, password, str(ipmi_port)],
                    capture_output=True, text=True, timeout=75,
                )
                return r.returncode, r.stdout, r.stderr
            except FileNotFoundError:
                return -1, "", "python interpreter not on PATH"
            except subprocess.TimeoutExpired:
                return -2, "", "IPMI worker exceeded 75s timeout"

        loop = asyncio.get_event_loop()
        rc, stdout, stderr = await loop.run_in_executor(None, _run_worker)

        if rc == -1:
            self._ipmi_err = "python interpreter not on PATH for IPMI subprocess"
            return None, self._ipmi_err
        if rc == -2:
            self._ipmi_err = f"IPMI timeout (>75s) at {self.hostname}:{ipmi_port}"
            return None, self._ipmi_err
        if rc != 0:
            self._ipmi_err = f"IPMI worker exit {rc}: {(stderr or '').strip()[:300] or '(no stderr)'}"
            return None, self._ipmi_err

        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as e:
            self._ipmi_err = f"IPMI worker JSON decode failed: {e}"
            return None, self._ipmi_err
        if not payload.get("ok"):
            err = payload.get("error") or "unknown IPMI worker error"
            tb = payload.get("tb", "")
            if tb:
                err = f"{err} | tb-tail: {tb.strip().splitlines()[-3:]}"
            self._ipmi_err = err
            return None, self._ipmi_err

        self._ipmi_readings = payload["readings"]
        return self._ipmi_readings, None

    async def _sensors_via_ipmi(self) -> tuple[dict | None, str | None]:
        """Returns (data, None) on success or (None, reason) on failure so the
        caller can surface why we fell back."""
        readings, err = await self._ipmi_walk_cached()
        if readings is None:
            return None, err

        def _round(x):
            return round(x, 3) if isinstance(x, float) else x

        temps: list[dict] = []
        fans:  list[dict] = []
        volts: list[dict] = []
        for r in readings:
            if r["unavailable"] or r["value"] is None:
                continue
            health = self._IPMI_HEALTH_MAP.get(r["health_code"], "Unknown")
            value = _round(r["value"])
            entry = {
                "name":    r["name"],
                "reading": value,
                "units":   r["units"],
                "health":  health,
            }
            rtype = (r["type"] or "").lower()
            if "temperature" in rtype:
                entry["celsius"] = value
                temps.append(entry)
            elif "fan" in rtype:
                fans.append(entry)
            elif "voltage" in rtype:
                volts.append(entry)

        return {
            "source":       "ipmi",
            "temperatures": temps,
            "fans":         fans,
            "voltages":     volts,
        }, None

    async def _sensors_via_xmlapi(self) -> dict:
        temp_stats, cpu_env, fan_rows = await asyncio.gather(
            self._resolve_class("computeMbTempStats"),
            self._resolve_class("processorEnvStats"),
            self._resolve_class("equipmentFan"),
        )

        temps: list[dict] = []

        def _push_temp(name: str, raw: Any) -> None:
            try:
                c = float(raw)
            except (TypeError, ValueError):
                return
            # Add space before uppercase letter only when preceded by lowercase
            # or digit, so "ambientTemp" → "ambient Temp" but pre-spaced
            # "CPU1 Temp" stays "CPU1 Temp" (don't shred existing labels).
            label = re.sub(r"(?<=[a-z0-9])([A-Z])", r" \1", name).strip()
            temps.append({"name": label, "celsius": c, "reading": c, "units": "°C", "health": "OK"})

        if temp_stats:
            for k, v in temp_stats[0].items():
                if "temp" in k.lower() and k not in ("dn", "rn", "status"):
                    _push_temp(k, v)
        for env in cpu_env:
            cpu_id = env.get("id") or env.get("dn", "").split("/")[-2].split("-")[-1]
            t = env.get("temperature")
            if t and t != "not-applicable":
                _push_temp(f"CPU{cpu_id} Temp", t)

        fans: list[dict] = []
        for r in fan_rows:
            if r.get("presence") != "equipped":
                continue
            fid = r.get("id", "?")
            mod = r.get("module", "?")
            label = f"Module {mod} / Fan {fid}" if mod != "?" else f"Fan {fid}"
            fans.append({
                "name":    label,
                "reading": None,    # RPM not exposed on 2.0(9f)
                "units":   "RPM",
                "health":  r.get("operability") or r.get("operState"),
            })

        return {"source": "xmlapi", "temperatures": temps, "fans": fans, "voltages": []}


    # ── actions ───────────────────────────────────────────────────────────────

    async def execute_action(self, action: dict) -> dict:
        atype = action.get("type")
        power_map = {
            "power_on":    "up",
            "power_off":   "down",
            "power_cycle": "cycle-immediate",
            "hard_reset":  "hard-reset-immediate",
        }
        if atype in power_map:
            await self._login()
            inner = f'<computeRackUnit adminPower="{power_map[atype]}" dn="sys/rack-unit-1"/>'
            return await self._conf_mo("sys/rack-unit-1", inner)
        if atype == "kvm_launch":
            return await self._kvm_jnlp()
        return {"error": f"Unsupported action: {atype!r}"}

    async def _kvm_jnlp(self) -> dict:
        """Mint a pair of one-shot KVM auth tokens via XMLAPI, then pull the
        firmware-generated JNLP from CIMC's own `/kvm.jnlp` endpoint. Returning
        the JNLP body lets the HTTP layer stream it as a file download which
        the user opens with `javaws` to launch the Cisco KVM viewer.

        Why we delegate JNLP construction to CIMC instead of building it
        locally: the `com.cisco.kvm.KVMLaunch` argument list and `kvm.jar`
        path differ across firmware revisions. CIMC knows its own format;
        we don't have to track it. The endpoint is unauthenticated — the
        tokens themselves are the auth, so a query-string GET is enough."""
        await self._login()
        root = await self._post_xml(f'<aaaGetComputeAuthTokens cookie="{self._cookie}"/>')
        if root.get("errorCode"):
            return {"error": f"CIMC {root.get('errorCode')}: {root.get('errorDescr')}"}
        out_tokens = root.get("outTokens") or ""
        parts = out_tokens.split(",")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            return {"error": f"CIMC did not return KVM tokens (outTokens={out_tokens!r})"}
        t1, t2 = parts[0], parts[1]
        params = {
            "cimcAddr":      self.hostname,
            "cimcName":      "",
            "cimcKVMPort":   "2068",
            "cimcKVMUriEnc": "0",
            "useSOL":        "0",
            "tkn1":          t1,
            "tkn2":          t2,
        }
        try:
            async with httpx.AsyncClient(verify=self._ssl_ctx, timeout=15) as c:
                r = await c.get(f"https://{self.hostname}:{self.port}/kvm.jnlp", params=params)
                r.raise_for_status()
        except httpx.HTTPError as e:
            return {"error": f"Failed to fetch /kvm.jnlp from CIMC: {e}"}
        body = r.text or ""
        if "<jnlp" not in body.lower():
            snippet = body[:200].replace("\n", " ")
            return {"error": f"CIMC returned non-JNLP body for /kvm.jnlp: {snippet!r}"}
        return {"jnlp": body}
