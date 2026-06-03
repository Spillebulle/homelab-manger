"""
D-Link adapter — extends generic SNMP with:
  - D-Link private MIB for per-port PoE power consumption (DGS-3120 series)
  - Entity MIB (RFC 4133) to filter virtual interfaces and detect combo ports
  - SSH interactive shell for configuration commands
"""
import asyncio
import logging
import re
import time
from typing import Any
from .snmp import SNMPAdapter, _walk, _safe_int

logger = logging.getLogger(__name__)

# D-Link enterprise OIDs for DGS-3120 PoE (1.3.6.1.4.1.171.12.18.x)
_DLINK_POE_POWER      = "1.3.6.1.4.1.171.12.18.2.1.1.12"  # milliwatts consumed per port
_DLINK_POE_VOLTAGE    = "1.3.6.1.4.1.171.12.18.2.1.1.13"  # millivolts
_DLINK_POE_CURRENT    = "1.3.6.1.4.1.171.12.18.2.1.1.14"  # milliamps
_DLINK_POE_MAX_POWER  = "1.3.6.1.4.1.171.12.18.2.1.1.8"   # max milliwatts configured

# D-Link private environment MIB — current chassis temperature in °C, indexed
# per stack unit (swDevEnvTemperatureCurrent). The standard ENTITY-SENSOR-MIB
# (1.3.6.1.2.1.99) is EMPTY on DGS-3120 R4.x, so this is the only temperature
# source. Confirmed on a real DGS-3120-48PC (col .2 = current, .3 = high
# threshold, .4 = low threshold). These switches expose NO total-power-draw
# counter anywhere (verified: empty ENTITY-SENSOR-MIB + empty PoE main
# consumption), only PoE delivered and this temperature.
_DLINK_TEMP_CURRENT   = "1.3.6.1.4.1.171.12.11.1.8.1.2"

# Entity MIB — entPhysicalName. DGS-3120 firmware names physical ports "Port N",
# including SFP cages with no module inserted (which are absent from IF-MIB).
_ENT_PHYSICAL_NAME    = "1.3.6.1.2.1.47.1.1.1.1.7"
_PORT_NAME_RE         = re.compile(r"^Port\s+(\d+)$")

# DGS-3120 ifDescr format: "D-Link DGS-3120-48PC R4.00.015 Port 1 on Unit 1"
_IFDESCR_PORT_RE      = re.compile(r"\bPort\s+(\d+)\b(?:\s+on\s+Unit\s+(\d+))?")

# DGS-3120 firmware lies about ipAddressOrigin via SNMP — it always returns 2
# (manual) regardless of how the address was actually acquired. The CLI's
# `show ipif` output ("IPv4 Address: 192.168.0.16/24 (DHCP)") is authoritative.
_IPIF_DHCP_RE = re.compile(r"IPv4\s+Address\s*:\s*\S+\s*\((DHCP|Manual)\)", re.IGNORECASE)

# DGS-3120 `show poe ports` output is 3 lines per port:
#   1:5    Enabled   Low       15400(Class 0)
#          2         1700      535                 33
#          ON   : 802.3af-compliant PD was detected
# `search` (not `match`) so any leading garbage from the PTY is tolerated.
_POE_LINE1_RE = re.compile(r"(\d+):(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\(Class\s+(\d+)\)")
_POE_LINE2_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")
_POE_LINE3_RE = re.compile(r"\s*(\w+)\s*:\s*(.+?)\s*$")

# vt100 CSI escape sequences (cursor moves, clears, colors). The DGS-3120
# emits these mixed into command output when paramiko requests a vt100 PTY.
_ANSI_CSI_RE = re.compile(r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]")


def _last(oid: str) -> str:
    return oid.rsplit(".", 1)[-1]


def _read_quiet(channel, quiet_ms: int = 600, timeout: int = 10) -> str:
    """Read from a paramiko channel until N ms of silence or hard timeout.
    DGS-3120 emits each command's output in one or two bursts followed by the
    prompt; once it stops producing data we're at the prompt."""
    buf = ""
    deadline = time.time() + timeout
    last_data = time.time()
    while time.time() < deadline:
        if channel.recv_ready():
            buf += channel.recv(8192).decode("utf-8", errors="replace")
            last_data = time.time()
        else:
            if (time.time() - last_data) * 1000 >= quiet_ms:
                break
            time.sleep(0.05)
    return buf


class DLinkAdapter(SNMPAdapter):
    REQUIREMENTS = [
        {
            "service": "SNMPv2c",
            "transport": "snmp",
            "port": 161,
            "description": "Inventory, port stats, MAC table, ARP",
            "required": True,
        },
        {
            "service": "SSH",
            "transport": "tcp",
            "port": 22,
            "description": "PoE status, VLAN config, DHCP/manual IP detection (CLI-only on DGS-3120 R4.x)",
            "required": True,
        },
    ]

    def requirements(self) -> list[dict]:
        snmp_port = int(self.credentials.get("port") or 161)
        ssh_port  = int(self.credentials.get("ssh_port") or 22)
        return [
            {**self.REQUIREMENTS[0], "port": snmp_port},
            {**self.REQUIREMENTS[1], "port": ssh_port},
        ]

    def get_supported_cache_keys(self) -> list[str]:
        return ["status", "ports", "poe", "vlans", "connected"]

    async def fetch(self, cache_key: str) -> Any:
        if cache_key == "vlans":
            return await self._vlans()
        return await super().fetch(cache_key)

    async def _status(self) -> dict:
        base = await super()._status()
        # Override SNMP-derived ipOrigin via CLI — this firmware reports the
        # SNMP field as "manual" even for DHCP-acquired addresses. CLI is
        # authoritative. Best-effort: any SSH failure leaves the SNMP value.
        if not base.get("online"):
            return base
        # Current chassis temperature (D-Link private MIB; SNMP, cheap).
        temp = await self._temperature()
        if temp is not None:
            base["temperature"] = temp
        try:
            result = await self._cli("show ipif")
        except Exception:
            return base
        if result.get("ok"):
            m = _IPIF_DHCP_RE.search(result.get("output", ""))
            if m:
                base["ipOrigin"] = m.group(1).lower()  # "dhcp" or "manual"
        return base

    async def _temperature(self) -> int | None:
        """Hottest current unit temperature in °C from the D-Link private env
        MIB. Indexed per stack unit; we report the max. Best-effort — returns
        None on any SNMP failure or if the table is empty."""
        try:
            rows = await _walk(self.hostname, self.community, _DLINK_TEMP_CURRENT, self.port)
        except Exception:
            return None
        temps = []
        for _oid, val in rows:
            try:
                temps.append(int(val))
            except (TypeError, ValueError):
                continue
        return max(temps) if temps else None

    async def _ports(self) -> list[dict]:
        ports = await super()._ports()

        for p in ports:
            m = _IFDESCR_PORT_RE.search(str(p.get("name", "")))
            if m:
                unit = m.group(2)
                p["name"] = f"Unit {unit} / Port {m.group(1)}" if unit and unit != "1" else f"Port {m.group(1)}"

        try:
            ent = await _walk(self.hostname, self.community, _ENT_PHYSICAL_NAME, self.port)
        except Exception:
            return ports

        # Count "Port N" occurrences in Entity MIB. Combo ports (RJ45 + SFP
        # cage sharing the same logical port number) appear twice — once for
        # each physical media. A standalone count of 1 means non-combo or a
        # stacking-slot entry; we keep the former (it intersects with IF-MIB)
        # and drop the latter (no IF-MIB sibling).
        port_counts: dict[str, int] = {}
        for _oid, val in ent:
            name = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
            m = _PORT_NAME_RE.match(name.strip())
            if m:
                port_counts[m.group(1)] = port_counts.get(m.group(1), 0) + 1

        if not port_counts:
            return ports

        # Drop virtual interfaces (VLAN tags, routing interfaces) that IF-MIB
        # returns but Entity MIB doesn't list as physical ports.
        filtered = []
        for p in ports:
            idx = str(p["index"])
            if idx not in port_counts:
                continue
            if port_counts[idx] > 1:
                p["combo"] = True
            filtered.append(p)
        return filtered

    async def _poe(self) -> dict:
        base = await super()._poe()

        power_walk, max_walk = await asyncio.gather(
            _walk(self.hostname, self.community, _DLINK_POE_POWER, self.port),
            _walk(self.hostname, self.community, _DLINK_POE_MAX_POWER, self.port),
            return_exceptions=True,
        )

        def safe_map(result):
            if isinstance(result, Exception):
                return {}
            return {_last(oid): val for oid, val in result}

        power_m   = safe_map(power_walk)
        max_pow_m = safe_map(max_walk)

        for port in base.get("ports", []):
            idx = port.get("portIndex", "")
            if idx in power_m:
                try:
                    mw = int(power_m[idx])
                    port["powerMilliwatts"] = mw
                    port["powerWatts"]      = round(mw / 1000, 2)
                except ValueError:
                    pass
            if idx in max_pow_m:
                try:
                    port["maxPowerMilliwatts"] = int(max_pow_m[idx])
                except ValueError:
                    pass

        # DGS-3120 R4.x doesn't expose PoE over any SNMP MIB. If the SNMP path
        # came back empty, fall through to `show poe ports` over SSH.
        if not base.get("ports"):
            cli_data = await self._cli_poe()
            if cli_data.get("ports"):
                return cli_data

        return base

    async def _cli_poe(self) -> dict:
        result = await self._cli("show poe ports 1-48")
        raw = result.get("output") or ""
        if not raw or "error" in result:
            return {}
        # If SSH succeeded but the response carries no port lines, the firmware
        # may have changed `show poe` formatting or PoE itself is disabled on
        # the chassis. Either way the user sees "PoE info gone" — log so we can
        # tell it apart from the SSH-down case (which is logged in _cli_many).

        # DGS-3120 ends each line with `\n\r` (LF before CR). Python's splitlines
        # treats these as two separators and produces empty lines between every
        # real line, breaking 3-lines-per-port lookahead. Also strip any ANSI/CSI
        # escape sequences that some firmwares emit. Then split on \n only.
        output = _ANSI_CSI_RE.sub("", raw).replace("\r", "")

        ports: list[dict] = []
        consumption_mw = 0
        lines = output.split("\n")
        i = 0
        # If SSH succeeded but the response carries no port lines, the firmware
        # may have changed `show poe` formatting or PoE itself is disabled on
        # the chassis. Either way the user sees "PoE info gone"; log a snippet
        # so we can distinguish format-drift from a turned-off feature without
        # a packet capture.
        _initial_line_count = len(lines)
        while i < len(lines):
            m1 = _POE_LINE1_RE.search(lines[i])
            if not m1 or i + 2 >= len(lines):
                i += 1
                continue
            m2 = _POE_LINE2_RE.match(lines[i + 1])
            m3 = _POE_LINE3_RE.search(lines[i + 2])
            if not (m2 and m3):
                i += 1
                continue

            unit, port_idx, state, _priority, limit_mw, _cfg_class = m1.groups()
            detected_class, power_mw, _voltage_dv, _current_ma = (int(x) for x in m2.groups())
            status_code = m3.group(1).upper()

            if status_code == "ON":
                detection_status = "delivering"
            elif "FAULT" in status_code:
                detection_status = "fault"
            else:
                detection_status = "disabled"

            ports.append({
                "key":                f"{unit}.{port_idx}",
                "portIndex":          port_idx,
                "adminEnabled":       state.lower() == "enabled",
                "detectionStatus":    detection_status,
                "powerClass":         detected_class,
                "powerMilliwatts":    power_mw,
                "powerWatts":         round(power_mw / 1000, 2),
                "maxPowerMilliwatts": int(limit_mw),
            })
            consumption_mw += power_mw
            i += 3

        if not ports and _initial_line_count > 0:
            snippet = output.strip().splitlines()[:6]
            logger.warning(
                "DLink %s: `show poe ports 1-48` parsed zero ports from %d lines of "
                "CLI output (firmware format change or PoE disabled?). First lines: %r",
                self.hostname, _initial_line_count, snippet,
            )

        return {
            "ports":            ports,
            "totalPowerWatts":  None,  # would need `show poe pse` parsing
            "consumptionWatts": round(consumption_mw / 1000, 2),
        }

    async def _vlans(self) -> dict:
        result = await self._cli("show vlan")
        if "error" in result:
            return {"vlans": [], "pvidByPort": {}, "error": result["error"]}
        return self._parse_show_vlan(result.get("output", ""))

    @staticmethod
    def _parse_show_vlan(raw: str) -> dict:
        text = _ANSI_CSI_RE.sub("", raw).replace("\r", "")
        # Each VLAN block is separated by a blank line. The first block is
        # the trunk header which we skip via the `VID` check.
        vlans: list[dict] = []
        pvid_by_port: dict[str, int] = {}
        for block in re.split(r"\n\s*\n", text):
            if "VID" not in block:
                continue
            fields: dict[str, str] = {}
            for line in block.split("\n"):
                # The DGS-3120 lays out two key:value chunks per line, separated
                # by 2+ spaces. Split on that boundary then on the colon.
                for chunk in re.split(r"(?<=\S)\s{2,}(?=[A-Z])", line.strip()):
                    if ":" in chunk:
                        k, v = chunk.split(":", 1)
                        fields[k.strip()] = v.strip()
            if "VID" not in fields:
                continue
            try:
                vid = int(fields["VID"])
            except ValueError:
                continue
            tagged   = DLinkAdapter._expand_port_range(fields.get("Static Tagged Ports", ""))
            untagged = DLinkAdapter._expand_port_range(fields.get("Static Untagged Ports", ""))
            vlans.append({
                "vid":      vid,
                "name":     fields.get("VLAN Name", ""),
                "type":     fields.get("VLAN Type", ""),
                "tagged":   tagged,
                "untagged": untagged,
            })
            for p in untagged:
                # CLI port "1:5" → ifIndex "5" on a single-unit DGS-3120. For
                # stacked units the mapping isn't 1:1 — revisit when we have
                # one to test against.
                if ":" in p:
                    unit, port_n = p.split(":", 1)
                    if unit == "1":
                        pvid_by_port[port_n] = vid
                else:
                    pvid_by_port[p] = vid
        return {"vlans": vlans, "pvidByPort": pvid_by_port}

    @staticmethod
    def _expand_port_range(s: str) -> list[str]:
        """Expand 'Static Untagged Ports' style strings — e.g.
        '1:1-1:24,1:30,1:40-1:48' → ['1:1', '1:2', ..., '1:24', '1:30', '1:40', ..., '1:48']."""
        s = s.strip()
        if not s:
            return []
        out: list[str] = []
        for part in s.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                au, ap = (a.split(":", 1) if ":" in a else ("1", a))
                bu, bp = (b.split(":", 1) if ":" in b else ("1", b))
                if au == bu:
                    for p in range(int(ap), int(bp) + 1):
                        out.append(f"{au}:{p}")
                else:
                    # Cross-unit ranges are rare enough to leave unsupported.
                    out += [a, b]
            else:
                out.append(part if ":" in part else f"1:{part}")
        return out

    _VLAN_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")
    # A port spec is interpolated raw into an SSH CLI command, so it must not
    # carry shell/command metacharacters. Legitimate DGS-3120 specs are bare
    # ifIndex (`5`), unit:port (`1:5`), ranges (`1-48`, `1:1-1:48`) and
    # comma-lists — all covered by digits, colon, hyphen, comma. The UI only
    # ever sends numeric ports; this guards the API-key path against injection.
    _PORT_SPEC_RE = re.compile(r"^[0-9:,\-]{1,40}$")

    def _safe_port(self, action: dict):
        """Return (port_str, None) if the action's port_id is a safe spec, else
        (None, error_dict)."""
        port = str(action.get("port_id", "")).strip()
        if not self._PORT_SPEC_RE.match(port):
            return None, {"error": f"Invalid port id: {port!r}"}
        return port, None

    async def execute_action(self, action: dict) -> dict:
        atype = action.get("type")
        if atype == "port_poe":
            port, err = self._safe_port(action)
            if err:
                return err
            return await self._cli(
                f"config poe ports {port} state {'enable' if action.get('enable', True) else 'disable'}"
            )
        if atype == "port_description":
            port, err = self._safe_port(action)
            if err:
                return err
            # Strip the quote that would break out of the quoted argument and any
            # CR/LF that would inject a second CLI command line. Other chars are
            # legitimate description text (they stay literal inside the quotes).
            desc = action.get("description", "").replace('"', "").replace("\r", "").replace("\n", "")
            return await self._cli(f'config ports {port} description "{desc}"')
        if atype == "port_poe_limit":
            port, err = self._safe_port(action)
            if err:
                return err
            mw = int(action.get("milliwatts", 15400))
            return await self._cli(f"config poe ports {port} max_power {mw}")
        if atype == "ssh_command":
            return await self._cli(action.get("command", ""))
        if atype == "vlan_create":
            return await self._vlan_create(action)
        if atype == "vlan_delete":
            return await self._vlan_delete(action)
        if atype == "vlan_set_port":
            return await self._vlan_set_port(action)
        if atype == "vlan_batch":
            return await self._vlan_batch(action)
        # fall back to SNMP for port admin toggle
        return await super().execute_action(action)

    async def _vlan_batch(self, action: dict) -> dict:
        """Apply a batch of VLAN edits — VLAN creates, port-membership changes,
        VLAN deletes — in one SSH session. Order is fixed inside this method
        (creates → membership changes → deletes → save) and overrides whatever
        the caller passed; the order matters because the switch:
          - rejects member-add commands targeting a not-yet-created VID,
          - rejects delete-vlan commands while the VID still has members,
          - clears running-config on reboot if you skip `save config`.
        Within the membership changes, sub-order is none → tagged → untagged so
        an untagged-add doesn't undo a sibling tagged-add via the switch's
        auto-remove-from-prior-untagged-VLAN behaviour."""
        creates = action.get("creates") or []
        renames = action.get("renames") or []
        deletes = action.get("deletes") or []
        changes = action.get("changes") or []
        if not (creates or renames or deletes or changes):
            return {"ok": True, "results": []}

        validation_errors: list[dict] = []

        create_cmds: list[tuple[dict, str]] = []
        for i, c in enumerate(creates):
            try:
                vid = int(c.get("vid", 0))
            except (TypeError, ValueError):
                validation_errors.append({"index": i, "scope": "create", "error": "vid must be an integer", "item": c})
                continue
            name = (c.get("name") or "").strip()
            if vid < 2 or vid > 4094:
                validation_errors.append({"index": i, "scope": "create", "error": "VID must be 2..4094", "item": c})
                continue
            if not self._VLAN_NAME_RE.match(name):
                validation_errors.append({"index": i, "scope": "create", "error": "name must be 1-32 chars: letters, digits, _ or -", "item": c})
                continue
            create_cmds.append((c, f"create vlan {name} tag {vid}"))

        rename_cmds: list[tuple[dict, str]] = []
        for i, r in enumerate(renames):
            try:
                vid = int(r.get("vid", 0))
            except (TypeError, ValueError):
                validation_errors.append({"index": i, "scope": "rename", "error": "vid must be an integer", "item": r})
                continue
            name = (r.get("name") or "").strip()
            if vid < 1 or vid > 4094:
                validation_errors.append({"index": i, "scope": "rename", "error": "VID must be 1..4094", "item": r})
                continue
            if not self._VLAN_NAME_RE.match(name):
                validation_errors.append({"index": i, "scope": "rename", "error": "name must be 1-32 chars: letters, digits, _ or -", "item": r})
                continue
            rename_cmds.append((r, f"config vlan vlanid {vid} name {name}"))

        change_cmds: list[tuple[dict, str]] = []
        # Sub-order changes: none, tagged, untagged.
        order = {"none": 0, "tagged": 1, "untagged": 2}
        sorted_changes = sorted(
            ((i, ch) for i, ch in enumerate(changes)),
            key=lambda t: order.get(t[1].get("mode"), 99),
        )
        for i, ch in sorted_changes:
            try:
                vid = int(ch.get("vid", 0))
            except (TypeError, ValueError):
                validation_errors.append({"index": i, "scope": "change", "error": "vid must be an integer", "item": ch})
                continue
            if vid < 1 or vid > 4094:
                validation_errors.append({"index": i, "scope": "change", "error": "VID must be 1..4094", "item": ch})
                continue
            port = str(ch.get("port_id", "")).strip()
            if not port:
                validation_errors.append({"index": i, "scope": "change", "error": "port_id is required", "item": ch})
                continue
            if ":" not in port:
                port = f"1:{port}"
            if not re.match(r"^\d+:\d+$", port):
                validation_errors.append({"index": i, "scope": "change", "error": f"invalid port id {port!r}", "item": ch})
                continue
            mode = ch.get("mode", "none")
            if mode == "tagged":
                cmd = f"config vlan vlanid {vid} add tagged {port}"
            elif mode == "untagged":
                cmd = f"config vlan vlanid {vid} add untagged {port}"
            elif mode == "none":
                cmd = f"config vlan vlanid {vid} delete {port}"
            else:
                validation_errors.append({"index": i, "scope": "change", "error": f"mode must be tagged|untagged|none, got {mode!r}", "item": ch})
                continue
            change_cmds.append((ch, cmd))

        delete_cmds: list[tuple[dict, str]] = []
        for i, d in enumerate(deletes):
            try:
                vid = int(d if isinstance(d, (int, str)) else d.get("vid", 0))
            except (TypeError, ValueError):
                validation_errors.append({"index": i, "scope": "delete", "error": "vid must be an integer", "item": d})
                continue
            if vid == 1:
                validation_errors.append({"index": i, "scope": "delete", "error": "Refusing to delete the default VLAN (VID 1)", "item": d})
                continue
            if vid < 2 or vid > 4094:
                validation_errors.append({"index": i, "scope": "delete", "error": "VID must be 2..4094", "item": d})
                continue
            delete_cmds.append(({"vid": vid}, f"delete vlan vlanid {vid}"))

        if validation_errors:
            return {"ok": False, "errors": validation_errors, "results": []}

        ordered = create_cmds + rename_cmds + change_cmds + delete_cmds
        all_commands = [cmd for _, cmd in ordered] + ["save config"]
        cli_results = await self._cli_many(all_commands)

        results: list[dict] = []
        errors: list[dict] = []
        for (item, cmd), raw in zip(ordered, cli_results):
            classified = self._classify(raw)
            entry = {"item": item, "command": cmd, **classified}
            results.append(entry)
            if "error" in classified:
                errors.append(entry)

        save_idx = len(ordered)
        save_classified = self._classify(cli_results[save_idx] if save_idx < len(cli_results) else {"ok": True})
        if "error" in save_classified:
            errors.append({"item": None, "command": "save config", **save_classified})
        return {"ok": not errors, "results": results, "errors": errors, "saved": "error" not in save_classified}

    async def _run_and_save(self, command: str) -> dict:
        """Run one config-mutating command then `save config` in the same SSH
        session so changes survive a reboot."""
        results = await self._cli_many([command, "save config"])
        primary = self._classify(results[0] if results else {"error": "no result"})
        if "error" in primary:
            return primary
        if len(results) > 1:
            save = self._classify(results[1])
            if "error" in save:
                return {**primary, "warning": f"command applied but save config failed: {save['error']}"}
        return primary

    async def _vlan_create(self, action: dict) -> dict:
        try:
            vid = int(action.get("vid", 0))
        except (TypeError, ValueError):
            return {"error": "vid must be an integer"}
        name = (action.get("name") or "").strip()
        if vid < 2 or vid > 4094:
            return {"error": "VID must be 2..4094"}
        if not self._VLAN_NAME_RE.match(name):
            return {"error": "name must be 1-32 chars: letters, digits, _ or -"}
        return await self._run_and_save(f"create vlan {name} tag {vid}")

    async def _vlan_delete(self, action: dict) -> dict:
        try:
            vid = int(action.get("vid", 0))
        except (TypeError, ValueError):
            return {"error": "vid must be an integer"}
        if vid == 1:
            return {"error": "Refusing to delete the default VLAN (VID 1)"}
        if vid < 2 or vid > 4094:
            return {"error": "VID must be 2..4094"}
        return await self._run_and_save(f"delete vlan vlanid {vid}")

    async def _vlan_set_port(self, action: dict) -> dict:
        try:
            vid = int(action.get("vid", 0))
        except (TypeError, ValueError):
            return {"error": "vid must be an integer"}
        if vid < 1 or vid > 4094:
            return {"error": "VID must be 1..4094"}
        port = str(action.get("port_id", "")).strip()
        if not port:
            return {"error": "port_id is required"}
        # Frontend passes the ifIndex (e.g. "5"); CLI wants "1:5" on a single
        # unit. Pass through anything that already looks like "U:P".
        if ":" not in port:
            port = f"1:{port}"
        if not re.match(r"^\d+:\d+$", port):
            return {"error": f"invalid port id {port!r}"}
        mode = action.get("mode", "none")
        if mode == "tagged":
            cmd = f"config vlan vlanid {vid} add tagged {port}"
        elif mode == "untagged":
            cmd = f"config vlan vlanid {vid} add untagged {port}"
        elif mode == "none":
            cmd = f"config vlan vlanid {vid} delete {port}"
        else:
            return {"error": f"mode must be tagged|untagged|none, got {mode!r}"}
        return await self._run_and_save(cmd)

    @staticmethod
    def _classify(result: dict) -> dict:
        """Promote a Fail! line in the CLI output to a structured error so
        the frontend can show the actual switch message instead of having to
        eyeball the raw stdout. DGS-3120 prints the error reason on a line
        *before* Fail!, separated by a blank line — walk backwards from Fail!
        to find the first non-empty line."""
        if "error" in result:
            return result
        out = result.get("output", "")
        if "Fail!" not in out:
            return result
        clean = _ANSI_CSI_RE.sub("", out).replace("\r", "")
        lines = [l.rstrip() for l in clean.split("\n")]
        try:
            fail_idx = next(i for i, l in enumerate(lines) if l.strip() == "Fail!")
        except StopIteration:
            return {"error": "command failed", "output": out}
        for i in range(fail_idx - 1, -1, -1):
            msg = lines[i].strip()
            if msg:
                return {"error": msg, "output": out}
        return {"error": "command failed", "output": out}

    async def _cli(self, command: str) -> dict:
        results = await self._cli_many([command])
        return results[0] if results else {"error": "no result"}

    async def _cli_many(self, commands: list[str]) -> list[dict]:
        """Open one SSH session, run each command sequentially, return one
        result dict per command. Saves the ~3s handshake on multi-step VLAN
        config that would otherwise pay it per command."""
        if not commands:
            return []
        username = self.credentials.get("ssh_username", "admin")
        password = self.credentials.get("ssh_password", "")
        ssh_port = int(self.credentials.get("ssh_port", 22))

        loop = asyncio.get_running_loop()

        def _do() -> list[dict]:
            import socket as _socket
            import paramiko

            transport = None
            try:
                sock = _socket.create_connection((self.hostname, ssh_port), timeout=10)
                transport = paramiko.Transport(sock)

                # D-Link DGS-3120 uses legacy algorithms that modern paramiko disables
                # by default. These must be set on the Transport before start_client().
                # paramiko 3.x renamed `keys` -> `key_types`; cryptography 42+ dropped
                # 3des-cbc, so the setter raises "unknown cipher" if we include it.
                opts = transport.get_security_options()
                host_key_attr = "key_types" if hasattr(opts, "key_types") else "keys"
                preferences = [
                    ("kex", [
                        "diffie-hellman-group1-sha1",
                        "diffie-hellman-group14-sha1",
                        "diffie-hellman-group14-sha256",
                        "diffie-hellman-group-exchange-sha256",
                        "diffie-hellman-group-exchange-sha1",
                    ]),
                    ("ciphers", [
                        "aes128-cbc", "aes192-cbc", "aes256-cbc",
                        "aes128-ctr", "aes192-ctr", "aes256-ctr",
                    ]),
                    ("digests", ["hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-sha2-256"]),
                    (host_key_attr, ["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256"]),
                ]
                for attr, values in preferences:
                    try:
                        setattr(opts, attr, values)
                    except ValueError:
                        usable = []
                        for v in values:
                            try:
                                setattr(opts, attr, usable + [v])
                                usable.append(v)
                            except ValueError:
                                pass
                        if usable:
                            setattr(opts, attr, usable)

                # Surface what actually got negotiated. paramiko silently
                # filters algorithms that the linked cryptography backend
                # doesn't support; if a future paramiko/cryptography bump
                # drops one of these, the docker logs will show exactly which
                # category lost coverage instead of a bare "no acceptable
                # kex algorithm" error.
                logger.info(
                    "DLink SSH algos to %s — kex=%s ciphers=%s macs=%s host_keys=%s",
                    self.hostname,
                    list(opts.kex), list(opts.ciphers),
                    list(opts.digests), list(getattr(opts, host_key_attr)),
                )

                transport.start_client(timeout=10)
                transport.auth_password(username, password)

                channel = transport.open_session()
                channel.get_pty(term="vt100", width=200, height=2000)
                channel.invoke_shell()
                time.sleep(1.5)
                while channel.recv_ready():
                    channel.recv(8192)  # drain banner/prompt

                # DGS-3120 paginates regardless of PTY height. Disable up-front.
                channel.send("disable clipaging\n")
                _read_quiet(channel, quiet_ms=400, timeout=3)

                results: list[dict] = []
                for cmd in commands:
                    channel.send(cmd + "\n")
                    out = _read_quiet(channel, quiet_ms=600, timeout=10)
                    results.append({"ok": True, "command": cmd, "output": out.strip()})

                channel.send("logout\n")
                return results
            except Exception as exc:
                logger.warning(
                    "DLink SSH session to %s:%s failed: %s: %s",
                    self.hostname, ssh_port, type(exc).__name__, exc,
                )
                err = {"error": str(exc)}
                # Pad so callers indexing by command position still get a result.
                return [err] * len(commands) if not transport else [err]
            finally:
                if transport is not None:
                    transport.close()

        return await loop.run_in_executor(None, _do)
