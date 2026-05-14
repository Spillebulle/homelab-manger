"""
HPE OfficeConnect Switch 1820 adapter (J9984A and family).

This switch has no CLI/SSH — only a web UI (HTTP) plus SNMP. The default SNMP
community ("public") is read-only with no SET access, so:

  Reads  → SNMPv2c (standard MIBs, all populated on PT.02.x firmware).
  Writes → HTTP form-POSTs against the web UI (cookie-session "SID").

The web UI has a tiny session pool (3 slots observed on PT.02.05); we always
log out at the end of an action — and reads never touch the web UI — so we
don't drift toward "maximum number of web sessions" errors. Reads also stay
fast because SNMP doesn't need a session.
"""
import asyncio
import logging
import re
from contextlib import contextmanager
from typing import Any

import httpx

from .snmp import (
    SNMPAdapter,
    _walk,
    _safe_int,
    _to_str,
    _fmt_mac,
)

logger = logging.getLogger(__name__)

# Q-BRIDGE-MIB — the 1820's VLAN config lives here (and reads + decodes cleanly,
# unlike on DGS-3120 where R4.x reports phantom rows).
_DOT1Q_VLAN_NAME            = "1.3.6.1.2.1.17.7.1.4.3.1.1"
_DOT1Q_VLAN_EGRESS_PORTS    = "1.3.6.1.2.1.17.7.1.4.3.1.2"  # tagged + untagged egress (PortList bitmap)
_DOT1Q_VLAN_UNTAGGED_PORTS  = "1.3.6.1.2.1.17.7.1.4.3.1.4"  # untagged egress (subset of above)
_DOT1Q_PVID                 = "1.3.6.1.2.1.17.7.1.4.5.1.1"  # per-port default VLAN

# Q-BRIDGE FDB — bridge-MIB's dot1dTpFdbAddress is empty on the 1820; the
# VID-aware table is the only path.
_DOT1Q_TP_FDB_PORT          = "1.3.6.1.2.1.17.7.1.2.2.1.2"
_BRIDGE_PORT_TO_IF          = "1.3.6.1.2.1.17.1.4.1.2"

# ifTable — the 1820 reports 48 copper + 4 SFP + 1 CPU + 16 LAG (= 69 entries).
# All physical ports use ifType=6 (ethernetCsmacd); the CPU port uses ifType=1
# (other); LAGs use ifType=161 (ieee8023adLag). We use ifType to filter.
_IF_TABLE_TYPE              = "1.3.6.1.2.1.2.2.1.3"
_IFTYPE_ETHERNET            = 6
_IFTYPE_OTHER               = 1
_IFTYPE_LAG                 = 161

# ifDescr on the 1820 reads "N Gigabit - Level" (where N is the port number).
# That's noise in the UI — strip the suffix and prefer a clean "Port N" label.
_GENERIC_IFDESCR_RE = re.compile(r"^(\d+)\s+Gigabit\s*-\s*Level\s*$")

# How many copper ports the model has (everything above is SFP). The 1820-48G
# variants have 48 copper + 4 SFP. For the 1820-24G it's 24 copper + 2 SFP.
# Both fit the pattern "first N are copper, rest are SFP" so we derive N from
# the ifType set rather than hard-coding a model match.

# Web UI paths.
_WEB_LOGIN     = "/htdocs/login/login.lua"
_WEB_LOGOUT    = "/htdocs/pages/main/logout.lsp"
_WEB_POE_MODAL = "/htdocs/pages/base/poe_port_cfg_modal.lsp"
_WEB_PORT_MODAL = "/htdocs/pages/base/port_summary_modal.lsp"
_WEB_VLAN_ADD_MODAL    = "/htdocs/pages/switching/vlan_status_modal.lsp"
_WEB_VLAN_LIST_PAGE    = "/htdocs/pages/switching/vlan_status.lsp"
_WEB_VLAN_EDIT_MODAL   = "/htdocs/pages/switching/vlan_status_edit_modal.lsp"
_WEB_VLAN_MEMBER_MODAL = "/htdocs/pages/switching/vlan_per_port_modal.lsp"

# 1820 VLAN constraints (taken from the validation JS on the Add VLAN modal).
_MAX_VLANS         = 64
_VLAN_NAME_MAX     = 32
_VLAN_NAME_RE      = re.compile(r"^[\w\-]{1,32}$")  # web UI accepts letters/digits/underscore/dash

# A "submit" click on a form/modal — the framework appends b_<form>_clicked
# = b_<form>_submit when the dialog's Apply button is pressed.
def _submit_marker(form_id: str = "modal1") -> dict[str, str]:
    return {f"b_{form_id}_clicked": f"b_{form_id}_submit"}


def _decode_portlist(b: Any) -> list[int]:
    """Decode a Q-BRIDGE-MIB PortList (RFC 2674): a packed bitstring, 1 bit
    per port, MSB-first within each byte. Byte 0 bit 7 (0x80) = port 1.

    Example: b'\\x80\\x00' → [1]; b'\\xff' → [1..8]; b'\\xf7' (byte 6) means
    ports 49..52,54..56 (port 53 is the CPU interface and never participates
    in user VLANs).
    """
    if not isinstance(b, (bytes, bytearray)):
        return []
    out: list[int] = []
    for byte_idx, byte_val in enumerate(b):
        if not byte_val:
            continue
        base = byte_idx * 8
        for bit in range(8):
            if byte_val & (0x80 >> bit):
                out.append(base + bit + 1)
    return out


def _encode_portlist(ports: list[int], min_bytes: int) -> bytes:
    """Inverse of _decode_portlist. min_bytes pads the result so the SET
    matches the size the agent expects (the 1820 returns 9-byte bitmaps
    even when only ports 1-8 are populated).

    Unused at the moment — we write through the web UI, not via SNMP-SET —
    but kept here so a future SNMP-write path doesn't have to reinvent it.
    """
    if not ports:
        return b"\x00" * min_bytes
    max_port = max(ports)
    n = max((max_port + 7) // 8, min_bytes)
    buf = bytearray(n)
    for p in ports:
        idx, bit = (p - 1) // 8, (p - 1) % 8
        buf[idx] |= 0x80 >> bit
    return bytes(buf)


class HPE1820Adapter(SNMPAdapter):
    REQUIREMENTS = [
        {
            "service": "SNMPv2c",
            "transport": "snmp",
            "port": 161,
            "description": "All read operations (inventory, ports, VLANs, FDB)",
            "required": True,
        },
        {
            "service": "Web UI (HTTP)",
            "transport": "http",
            "port": 80,
            "description": "Form-POST writes for port admin, PoE, VLANs (no CLI on this switch)",
            "required": True,
        },
    ]

    def requirements(self) -> list[dict]:
        snmp_port = int(self.credentials.get("port") or 161)
        web_port  = int(self.credentials.get("web_port") or 80)
        return [
            {**self.REQUIREMENTS[0], "port": snmp_port},
            {**self.REQUIREMENTS[1], "port": web_port},
        ]

    def __init__(self, hostname: str, credentials: dict):
        super().__init__(hostname, credentials)
        # Web UI credentials. Fall back to top-level username/password so
        # users don't have to fill in three credential pairs in the form.
        self.web_username = credentials.get("web_username") or credentials.get("username", "admin")
        self.web_password = credentials.get("web_password") or credentials.get("password", "")
        self.web_port     = int(credentials.get("web_port", 80))
        # The 1820 only listens on HTTP by default; HTTPS is opt-in in
        # security settings. Allow override per device.
        self.web_scheme   = credentials.get("web_scheme", "http")

    def get_supported_cache_keys(self) -> list[str]:
        return ["status", "ports", "poe", "vlans", "connected"]

    async def fetch(self, cache_key: str) -> Any:
        if cache_key == "vlans":
            return await self._vlans()
        return await super().fetch(cache_key)

    # ── Reads ────────────────────────────────────────────────────────────────

    async def _status(self) -> dict:
        base = await super()._status()
        # The 1820's Entity MIB is empty (entPhysicalSoftwareRev returns 0 rows),
        # but sysDescr embeds the firmware version after the model — pull it
        # out so the UI shows "PT.02.05" instead of "—".
        if not base.get("firmware") and base.get("sysDescr"):
            m = re.search(r",\s*(PT\.\d[\w.\-]*)\b", base["sysDescr"])
            if m:
                base["firmware"] = m.group(1)
        return base

    async def _ports(self) -> list[dict]:
        """Filter the ifTable to physical ports only and rewrite the generic
        ifDescr ("3 Gigabit - Level") to a clean "Port N" label. Ports above
        the copper count get a (SFP) suffix so the user can tell them apart
        from the front-panel visual."""
        ports = await super()._ports()
        # Walk ifType once to know which indices are physical, CPU, or LAG.
        try:
            type_walk = await _walk(self.hostname, self.community, _IF_TABLE_TYPE, self.port)
        except Exception:
            type_walk = []
        type_by_idx = {str(oid).rsplit(".", 1)[-1]: _safe_int(v) for oid, v in (type_walk or [])}

        physical = [
            (int(idx), t) for idx, t in type_by_idx.items()
            if t == _IFTYPE_ETHERNET
        ]
        if not physical:
            return ports  # SNMP path failed — fall back to base behaviour.

        # On the 1820 the highest ethernet ifIndex equals copper + SFP count.
        # Detect the SFP boundary by counting ifHighSpeed=0 ports... no — that
        # would mis-tag down ports. Use a simpler rule: ports 1..(max-4) are
        # copper, last 4 are SFP for the 1820-48G family. For 1820-24G the
        # split is max-2.
        max_phys = max(idx for idx, _ in physical)
        # The 1820 has 4 SFPs on 48G models, 2 on 24G models. Both are even.
        # Map the SFP slots as the trailing 4 (or 2) ports.
        if max_phys >= 26:
            copper_end = max_phys - 4
        else:
            copper_end = max_phys - 2

        filtered = []
        for p in ports:
            idx_str = str(p["index"])
            t = type_by_idx.get(idx_str)
            if t != _IFTYPE_ETHERNET:
                continue
            idx = _safe_int(idx_str)
            # Rewrite "N Gigabit - Level" → "Port N" (or "Port N (SFP)").
            if idx > copper_end:
                p["name"] = f"Port {idx} (SFP)"
            else:
                m = _GENERIC_IFDESCR_RE.match(_to_str(p.get("name", "")))
                p["name"] = f"Port {idx}" if m else f"Port {idx}"
            filtered.append(p)
        return filtered

    async def _vlans(self) -> dict:
        """Read static VLAN config via Q-BRIDGE-MIB."""
        name_w, eg_w, un_w, pvid_w = await asyncio.gather(
            _walk(self.hostname, self.community, _DOT1Q_VLAN_NAME,           self.port),
            _walk(self.hostname, self.community, _DOT1Q_VLAN_EGRESS_PORTS,   self.port),
            _walk(self.hostname, self.community, _DOT1Q_VLAN_UNTAGGED_PORTS, self.port),
            _walk(self.hostname, self.community, _DOT1Q_PVID,                self.port),
            return_exceptions=True,
        )

        def _safe(w):
            return [] if isinstance(w, Exception) else (w or [])

        names: dict[int, str] = {}
        for oid, v in _safe(name_w):
            vid = _safe_int(str(oid).rsplit(".", 1)[-1])
            names[vid] = _to_str(v)

        egress: dict[int, list[int]] = {}
        for oid, v in _safe(eg_w):
            vid = _safe_int(str(oid).rsplit(".", 1)[-1])
            egress[vid] = _decode_portlist(v)

        untag: dict[int, list[int]] = {}
        for oid, v in _safe(un_w):
            vid = _safe_int(str(oid).rsplit(".", 1)[-1])
            untag[vid] = _decode_portlist(v)

        pvid_by_port: dict[str, int] = {}
        for oid, v in _safe(pvid_w):
            ifidx = str(oid).rsplit(".", 1)[-1]
            pvid_by_port[ifidx] = _safe_int(v)

        vlans = []
        for vid in sorted(names):
            untagged_ports = untag.get(vid, [])
            egress_ports = egress.get(vid, [])
            tagged_ports = [p for p in egress_ports if p not in untagged_ports]
            vlans.append({
                "vid":      vid,
                "name":     names[vid],
                "type":     "Default" if vid == 1 else "Static",
                "tagged":   [str(p) for p in tagged_ports],
                "untagged": [str(p) for p in untagged_ports],
            })
        return {"vlans": vlans, "pvidByPort": pvid_by_port}

    async def _connected(self) -> list[dict]:
        """The 1820 keeps the FDB in the VID-aware Q-BRIDGE table; the legacy
        BRIDGE-MIB dot1dTpFdbAddress walk returns zero rows. We parse the
        Q-BRIDGE form and reuse the bridge-port → ifIndex mapping that's
        identical on this device."""
        from .oui import lookup as oui_lookup

        fdb_w, b2i_w = await asyncio.gather(
            _walk(self.hostname, self.community, _DOT1Q_TP_FDB_PORT,   self.port),
            _walk(self.hostname, self.community, _BRIDGE_PORT_TO_IF,   self.port),
            return_exceptions=True,
        )

        def _safe(w):
            return [] if isinstance(w, Exception) else (w or [])

        b2i = {oid.rsplit(".", 1)[-1]: str(_safe_int(v)) for oid, v in _safe(b2i_w)}

        # ifType to filter the CPU interface out of "connected devices" —
        # otherwise the switch's own MAC always shows up.
        try:
            type_walk = await _walk(self.hostname, self.community, _IF_TABLE_TYPE, self.port)
            type_by_idx = {str(oid).rsplit(".", 1)[-1]: _safe_int(v) for oid, v in (type_walk or [])}
        except Exception:
            type_by_idx = {}

        result: list[dict] = []
        prefix = _DOT1Q_TP_FDB_PORT + "."
        for oid, v in _safe(fdb_w):
            soid = str(oid)
            if not soid.startswith(prefix):
                continue
            tail = soid[len(prefix):].split(".")
            if len(tail) != 7:
                continue
            try:
                mac_octets = [int(x) for x in tail[1:]]
            except ValueError:
                continue
            mac = ":".join(f"{o:02x}" for o in mac_octets)
            bridge_port = str(_safe_int(v))
            if bridge_port == "0":
                continue
            if_index = b2i.get(bridge_port, bridge_port)
            # Skip the CPU port — it forwards the switch's own MAC, not a
            # remote device.
            if type_by_idx.get(if_index) == _IFTYPE_OTHER:
                continue
            result.append({
                "mac":     mac,
                "port_id": if_index,
                "vendor":  oui_lookup(mac),
                "ip":      None,   # The 1820's ARP table is empty on PT.02.x
                "is_self": False,
            })

        result.sort(key=lambda r: (_safe_int(r["port_id"], 9999), r["mac"]))
        return result

    # ── Writes (web UI) ──────────────────────────────────────────────────────

    async def execute_action(self, action: dict) -> dict:
        atype = action.get("type")
        if atype == "port_admin":
            return await self._web_port_admin(action)
        if atype == "port_description":
            return await self._web_port_description(action)
        if atype == "port_poe":
            return await self._web_port_poe(action)
        if atype == "port_poe_limit":
            return await self._web_port_poe(action)  # same modal handles limit
        if atype == "vlan_create":
            return await self._web_vlan_create(action)
        if atype == "vlan_delete":
            return await self._web_vlan_delete(action)
        if atype == "vlan_set_port":
            return await self._web_vlan_set_port(action)
        if atype == "vlan_batch":
            return await self._web_vlan_batch(action)
        return {"error": f"Unsupported action: {atype!r}"}

    def _base_url(self) -> str:
        return f"{self.web_scheme}://{self.hostname}:{self.web_port}"

    @contextmanager
    def _web_session_sync(self):
        """Single-session context. Yields an httpx Client that is logged in.
        Always logs out on exit so we don't leak the (small) session pool —
        even on exceptions."""
        client = httpx.Client(base_url=self._base_url(), timeout=10, follow_redirects=False, verify=False)
        try:
            r = client.post(_WEB_LOGIN, data={
                "username": self.web_username,
                "password": self.web_password,
            })
            if r.status_code == 503:
                raise RuntimeError("HPE 1820 web session pool is full — wait a few minutes for idle sessions to time out")
            if r.status_code != 200:
                raise RuntimeError(f"login HTTP {r.status_code}")
            # Body is JSON: {"redirect": "...", "error": ""} on success.
            try:
                data = r.json()
            except Exception:
                raise RuntimeError(f"login returned non-JSON body: {r.text[:120]!r}")
            if data.get("error"):
                raise RuntimeError(f"login failed: {data['error']}")
            yield client
        finally:
            try:
                client.get(_WEB_LOGOUT)
            except Exception:
                pass
            client.close()

    async def _run_in_session(self, work):
        """Open one web UI session, run the supplied sync callable with the
        httpx Client, log out, and return whatever the callable returned."""
        loop = asyncio.get_running_loop()
        def _do():
            with self._web_session_sync() as client:
                return work(client)
        try:
            return await loop.run_in_executor(None, _do)
        except Exception as exc:
            logger.warning("HPE1820 web action against %s failed: %s: %s",
                           self.hostname, type(exc).__name__, exc)
            return {"error": str(exc)}

    @staticmethod
    def _normalise_port(port_id) -> str | None:
        """Frontend passes the ifIndex (e.g. '5'). The 1820's web UI also
        accepts bare ifIndex in intfStr; comma-separated for multi-port."""
        s = str(port_id).strip()
        if not s:
            return None
        # Reject things that aren't a digit or a comma list of digits.
        if not re.match(r"^\d+(?:,\d+)*$", s):
            return None
        return s

    def _post_form(self, client: httpx.Client, path: str, data: dict, form_id: str = "modal1") -> dict:
        """POST a form to the 1820 web UI, append the submit marker the
        framework's JS would have added on click, and return either
        {"ok": True} on success or {"error": "..."} when the response
        carries a recognisable error message."""
        payload = dict(data)
        payload.update(_submit_marker(form_id))
        r = client.post(path, data=payload)
        # The 1820 returns 200 with the (re-rendered) page on success or
        # failure; failures embed an error span. 303 means the session is
        # stale (we got redirected to /htdocs/login/login.lsp).
        if r.status_code in (301, 302, 303):
            return {"error": "session expired or unauthorised"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        # Look for a typical error rendering. The 1820's response embeds an
        # error message in a parent.error_alert() JS call when validation
        # fails. We surface that verbatim.
        m = re.search(r"parent\.error_alert\(\s*['\"]([^'\"]+)['\"]", r.text)
        if m:
            return {"error": m.group(1).strip()}
        m2 = re.search(r"alert_msg\s*[:=]\s*['\"]([^'\"]+)['\"]", r.text)
        if m2 and m2.group(1).strip().lower() not in ("", "success", "ok"):
            return {"error": m2.group(1).strip()}
        return {"ok": True}

    # ── Action implementations ───────────────────────────────────────────────

    async def _web_port_admin(self, action: dict) -> dict:
        port = self._normalise_port(action.get("port_id"))
        if port is None:
            return {"error": "port_id is required"}
        enable = bool(action.get("enable", True))
        def _do(c):
            return self._post_form(c, _WEB_PORT_MODAL, {
                "intf": port,
                "intfStr": port,
                "admin_mode_sel[]": "enabled" if enable else "disabled",
                "phys_mode_sel[]": "1",   # 1 = Auto Negotiate (default)
                "port_descr": "",
            })
        return await self._run_in_session(_do)

    async def _web_port_description(self, action: dict) -> dict:
        port = self._normalise_port(action.get("port_id"))
        if port is None:
            return {"error": "port_id is required"}
        desc = str(action.get("description", ""))[:64]
        def _do(c):
            return self._post_form(c, _WEB_PORT_MODAL, {
                "intf": port,
                "intfStr": port,
                # Don't disable a port just to set its description: re-send
                # admin=enabled as the default. Caller can hit port_admin
                # separately if they want to flip the admin bit.
                "admin_mode_sel[]": "enabled",
                "phys_mode_sel[]": "1",
                "port_descr": desc,
            })
        return await self._run_in_session(_do)

    async def _web_port_poe(self, action: dict) -> dict:
        port = self._normalise_port(action.get("port_id"))
        if port is None:
            return {"error": "port_id is required"}
        enable = action.get("enable")
        # When called with milliwatts (port_poe_limit), keep admin_mode at its
        # current default ("enabled") since the caller specifically wants to
        # cap power not disable the port.
        if enable is None and "milliwatts" in action:
            admin = "enabled"
            power_limit_type = "user"
            power_limit = max(3000, min(30000, int(action.get("milliwatts", 30000))))
        else:
            admin = "enabled" if enable else "disabled"
            power_limit_type = "dot3af"
            power_limit = 30000
        def _do(c):
            return self._post_form(c, _WEB_POE_MODAL, {
                "intfStr": port,
                "admin_mode_sel[]": admin,
                "schedule_sel[]": "none",
                "priority_sel[]": "low",
                "high_power_mode_sel[]": "disable",     # = AF mode (15.4 W cap)
                "power_detect_type_sel[]": "4pt_dot3af",
                "power_limit_type_sel[]": power_limit_type,
                "power_limit": str(power_limit),
            })
        return await self._run_in_session(_do)

    async def _web_vlan_create(self, action: dict) -> dict:
        try:
            vid = int(action.get("vid", 0))
        except (TypeError, ValueError):
            return {"error": "vid must be an integer"}
        if vid < 2 or vid > 4093:
            return {"error": "VID must be 2..4093"}
        name = (action.get("name") or "").strip()
        if not _VLAN_NAME_RE.match(name):
            return {"error": "name must be 1-32 chars: letters, digits, _ or -"}

        def _do(client: httpx.Client) -> dict:
            # The 1820 creates the VLAN with the VID first (numeric), then a
            # separate rename POST sets the name.
            r1 = self._post_form(client, _WEB_VLAN_ADD_MODAL, {
                "vlan_id_range": str(vid),
                "vlancount": "0",
            })
            if "error" in r1:
                return r1
            r2 = self._post_form(client, _WEB_VLAN_EDIT_MODAL, {
                "vlan": str(vid),
                "vlan_name": name,
            })
            return r2
        return await self._run_in_session(_do)

    async def _web_vlan_delete(self, action: dict) -> dict:
        try:
            vid = int(action.get("vid", 0))
        except (TypeError, ValueError):
            return {"error": "vid must be an integer"}
        if vid == 1:
            return {"error": "Refusing to delete the default VLAN (VID 1)"}
        if vid < 2 or vid > 4093:
            return {"error": "VID must be 2..4093"}
        def _do(client: httpx.Client) -> dict:
            # The Remove button on vlan_status.lsp submits the row checkbox
            # selection back to the same page with the b_form1_dt_remove
            # marker pretending the user clicked the Remove button.
            payload = {
                "chkrow[]": str(vid),
                "b_form1_dt_remove": "Remove",
                "b_form1_clicked": "b_form1_dt_remove",
            }
            r = client.post(_WEB_VLAN_LIST_PAGE, data=payload)
            if r.status_code in (301, 302, 303):
                return {"error": "session expired or unauthorised"}
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            m = re.search(r"parent\.error_alert\(\s*['\"]([^'\"]+)['\"]", r.text)
            if m:
                return {"error": m.group(1).strip()}
            return {"ok": True}
        return await self._run_in_session(_do)

    async def _web_vlan_rename(self, vid: int, name: str) -> dict:
        if not _VLAN_NAME_RE.match(name):
            return {"error": "name must be 1-32 chars: letters, digits, _ or -"}
        def _do(c):
            return self._post_form(c, _WEB_VLAN_EDIT_MODAL, {
                "vlan": str(vid),
                "vlan_name": name,
            })
        return await self._run_in_session(_do)

    async def _web_vlan_set_port(self, action: dict) -> dict:
        try:
            vid = int(action.get("vid", 0))
        except (TypeError, ValueError):
            return {"error": "vid must be an integer"}
        if vid < 1 or vid > 4093:
            return {"error": "VID must be 1..4093"}
        port = self._normalise_port(action.get("port_id"))
        if port is None:
            return {"error": "port_id is required"}
        mode = action.get("mode", "none")
        # The 1820 names them tagged | untagged | exclude (not "none").
        mode_to_form = {"tagged": "tagged", "untagged": "untagged", "none": "exclude"}
        if mode not in mode_to_form:
            return {"error": f"mode must be tagged|untagged|none, got {mode!r}"}

        def _do(c):
            return self._post_form(c, _WEB_VLAN_MEMBER_MODAL, {
                "vlan": str(vid),
                "intfStr": port,
                "part_tagg_sel[]": mode_to_form[mode],
                "part_exclude": "yes",
                "parentQStr": f"?vlan={vid}",
            })
        return await self._run_in_session(_do)

    async def _web_vlan_batch(self, action: dict) -> dict:
        """Apply a batch of VLAN edits in a single web UI session.

        Order follows the same logic as DLinkAdapter._vlan_batch:
          creates → renames → membership changes → deletes.
        Within changes, sub-order is none → tagged → untagged so that an
        untagged-add doesn't undo a sibling tagged-add via the switch's
        auto-remove-from-prior-untagged-VLAN behaviour.

        Unlike D-Link there's no "save config" command — the 1820 commits
        each form post immediately to startup-config.
        """
        creates = action.get("creates") or []
        renames = action.get("renames") or []
        deletes = action.get("deletes") or []
        changes = action.get("changes") or []
        if not (creates or renames or deletes or changes):
            return {"ok": True, "results": []}

        validation_errors: list[dict] = []

        def _vid(raw, i, scope, item):
            try:
                return int(raw)
            except (TypeError, ValueError):
                validation_errors.append({"index": i, "scope": scope, "error": "vid must be an integer", "item": item})
                return None

        norm_creates = []
        for i, c in enumerate(creates):
            vid = _vid(c.get("vid", 0), i, "create", c)
            if vid is None: continue
            if vid < 2 or vid > 4093:
                validation_errors.append({"index": i, "scope": "create", "error": "VID must be 2..4093", "item": c}); continue
            name = (c.get("name") or "").strip()
            if not _VLAN_NAME_RE.match(name):
                validation_errors.append({"index": i, "scope": "create", "error": "name must be 1-32 chars: letters, digits, _ or -", "item": c}); continue
            norm_creates.append((c, vid, name))

        norm_renames = []
        for i, r in enumerate(renames):
            vid = _vid(r.get("vid", 0), i, "rename", r)
            if vid is None: continue
            if vid < 1 or vid > 4093:
                validation_errors.append({"index": i, "scope": "rename", "error": "VID must be 1..4093", "item": r}); continue
            name = (r.get("name") or "").strip()
            if not _VLAN_NAME_RE.match(name):
                validation_errors.append({"index": i, "scope": "rename", "error": "name must be 1-32 chars: letters, digits, _ or -", "item": r}); continue
            norm_renames.append((r, vid, name))

        order = {"none": 0, "tagged": 1, "untagged": 2}
        sorted_changes = sorted(
            ((i, ch) for i, ch in enumerate(changes)),
            key=lambda t: order.get(t[1].get("mode"), 99),
        )
        norm_changes = []
        for i, ch in sorted_changes:
            vid = _vid(ch.get("vid", 0), i, "change", ch)
            if vid is None: continue
            if vid < 1 or vid > 4093:
                validation_errors.append({"index": i, "scope": "change", "error": "VID must be 1..4093", "item": ch}); continue
            port = self._normalise_port(ch.get("port_id"))
            if port is None:
                validation_errors.append({"index": i, "scope": "change", "error": "port_id is required", "item": ch}); continue
            mode = ch.get("mode", "none")
            if mode not in ("tagged", "untagged", "none"):
                validation_errors.append({"index": i, "scope": "change", "error": f"mode must be tagged|untagged|none, got {mode!r}", "item": ch}); continue
            norm_changes.append((ch, vid, port, mode))

        norm_deletes = []
        for i, d in enumerate(deletes):
            raw = d if isinstance(d, (int, str)) else d.get("vid", 0)
            vid = _vid(raw, i, "delete", d)
            if vid is None: continue
            if vid == 1:
                validation_errors.append({"index": i, "scope": "delete", "error": "Refusing to delete the default VLAN (VID 1)", "item": d}); continue
            if vid < 2 or vid > 4093:
                validation_errors.append({"index": i, "scope": "delete", "error": "VID must be 2..4093", "item": d}); continue
            norm_deletes.append(({"vid": vid}, vid))

        if validation_errors:
            return {"ok": False, "errors": validation_errors, "results": []}

        mode_to_form = {"tagged": "tagged", "untagged": "untagged", "none": "exclude"}

        def _do(client: httpx.Client) -> dict:
            results: list[dict] = []
            errors: list[dict] = []

            def _run(scope: str, item: dict, label: str, fn):
                r = fn()
                entry = {"item": item, "scope": scope, "command": label, **r}
                results.append(entry)
                if "error" in r:
                    errors.append(entry)
                return "error" not in r

            for item, vid, name in norm_creates:
                if not _run("create", item, f"create vlan {vid}", lambda: self._post_form(client, _WEB_VLAN_ADD_MODAL, {
                    "vlan_id_range": str(vid),
                    "vlancount": "0",
                })):
                    continue
                _run("create", item, f"rename vlan {vid} {name}", lambda: self._post_form(client, _WEB_VLAN_EDIT_MODAL, {
                    "vlan": str(vid),
                    "vlan_name": name,
                }))

            for item, vid, name in norm_renames:
                _run("rename", item, f"rename vlan {vid} {name}", lambda: self._post_form(client, _WEB_VLAN_EDIT_MODAL, {
                    "vlan": str(vid),
                    "vlan_name": name,
                }))

            for item, vid, port, mode in norm_changes:
                _run("change", item, f"vlan {vid} port {port} {mode}", lambda: self._post_form(client, _WEB_VLAN_MEMBER_MODAL, {
                    "vlan": str(vid),
                    "intfStr": port,
                    "part_tagg_sel[]": mode_to_form[mode],
                    "part_exclude": "yes",
                    "parentQStr": f"?vlan={vid}",
                }))

            for item, vid in norm_deletes:
                def _delete(vid=vid):
                    payload = {
                        "chkrow[]": str(vid),
                        "b_form1_dt_remove": "Remove",
                        "b_form1_clicked": "b_form1_dt_remove",
                    }
                    r = client.post(_WEB_VLAN_LIST_PAGE, data=payload)
                    if r.status_code in (301, 302, 303):
                        return {"error": "session expired or unauthorised"}
                    if r.status_code != 200:
                        return {"error": f"HTTP {r.status_code}"}
                    m = re.search(r"parent\.error_alert\(\s*['\"]([^'\"]+)['\"]", r.text)
                    if m:
                        return {"error": m.group(1).strip()}
                    return {"ok": True}
                _run("delete", item, f"delete vlan {vid}", _delete)

            return {"ok": not errors, "results": results, "errors": errors, "saved": True}

        return await self._run_in_session(_do)
