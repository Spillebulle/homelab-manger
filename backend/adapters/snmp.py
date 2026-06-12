"""
Generic SNMP adapter using puresnmp (pure Python, no C deps, no version chaos).
"""
import asyncio
import logging
import time
from datetime import timedelta
from typing import Any
from .base import BaseAdapter
from .oui import lookup as oui_lookup

logger = logging.getLogger(__name__)

# Rate-limit duplicate SNMP failure warnings per (host, port, error-type).
# A single misconfigured device (wrong community, host down) otherwise spams
# ~10 walk-failed lines per poll cycle. We still want to know it happened -
# just not 10x per minute forever. First occurrence logs immediately; further
# occurrences are suppressed until _SNMP_WARN_QUIET_SECONDS has elapsed.
_SNMP_WARN_QUIET_SECONDS = 300
_snmp_last_warn: dict[tuple, float] = {}


def _snmp_warn_ratelimited(key: tuple, *args, **kwargs) -> None:
    """Emit `logger.warning(*args, **kwargs)` only if we haven't already
    warned for this `key` within _SNMP_WARN_QUIET_SECONDS. Otherwise drop it
    silently - the first occurrence is enough context for an operator to
    investigate; the rest is noise."""
    now = time.monotonic()
    last = _snmp_last_warn.get(key)
    if last is not None and (now - last) < _SNMP_WARN_QUIET_SECONDS:
        return
    _snmp_last_warn[key] = now
    logger.warning(*args, **kwargs)

# IF-MIB
_IF_DESCR        = "1.3.6.1.2.1.2.2.1.2"
_IF_TYPE         = "1.3.6.1.2.1.2.2.1.3"   # 6=copper 117=GigE 161=LAG 24=loopback
_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
_IF_OPER_STATUS  = "1.3.6.1.2.1.2.2.1.8"
_IF_IN_OCTETS    = "1.3.6.1.2.1.2.2.1.10"
_IF_OUT_OCTETS   = "1.3.6.1.2.1.2.2.1.16"
_IF_HIGH_SPEED   = "1.3.6.1.2.1.31.1.1.1.15"
_IF_ALIAS        = "1.3.6.1.2.1.31.1.1.1.18"

# POWER-ETHERNET-MIB (IEEE 802.3af/at)
_POE_PORT_ADMIN     = "1.3.6.1.2.1.105.1.1.1.3"
_POE_PORT_DETECTION = "1.3.6.1.2.1.105.1.1.1.6"
_POE_PORT_CLASS     = "1.3.6.1.2.1.105.1.1.1.7"
_POE_MAIN_POWER     = "1.3.6.1.2.1.105.1.3.1.2"
_POE_CONSUMPTION    = "1.3.6.1.2.1.105.1.3.1.4"

# System
_SYS_NAME   = "1.3.6.1.2.1.1.5.0"
_SYS_DESCR  = "1.3.6.1.2.1.1.1.0"
_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"

# BRIDGE-MIB (FDB / forwarding table)
_FDB_ADDR    = "1.3.6.1.2.1.17.4.3.1.1"  # dot1dTpFdbAddress (MAC)
_FDB_PORT    = "1.3.6.1.2.1.17.4.3.1.2"  # dot1dTpFdbPort   (bridge-port)
_BRIDGE_PORT_TO_IF = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex

# IP-MIB ARP - modern (RFC 4293) and legacy (RFC 1213) tables
_ARP_MODERN  = "1.3.6.1.2.1.4.35.1.4"   # ipNetToPhysicalPhysAddress (mac value, IP in OID)
_ARP_LEGACY  = "1.3.6.1.2.1.4.22.1.2"   # ipNetToMediaPhysAddress
_OWN_IP_TBL  = "1.3.6.1.2.1.4.20.1.1"   # ipAdEntAddr (this device's L3 addresses)
_IP_NETMASK  = "1.3.6.1.2.1.4.20.1.3"   # ipAdEntNetMask (sibling column to ipAdEntAddr)
_IP_ORIGIN   = "1.3.6.1.2.1.4.34.1.6"   # ipAddressOrigin (1=other 2=manual 4=dhcp 5=link 6=random)
_ROUTE_NEXTHOP = "1.3.6.1.2.1.4.21.1.7" # ipRouteNextHop (legacy table; default route's row indexed by .0.0.0.0)

# Entity MIB - physical inventory (firmware, serial, model)
_ENT_SOFT_REV = "1.3.6.1.2.1.47.1.1.1.1.10"  # entPhysicalSoftwareRev
_ENT_SERIAL   = "1.3.6.1.2.1.47.1.1.1.1.11"  # entPhysicalSerialNum

# BRIDGE-MIB - chassis MAC (the address used by the management UI)
_BRIDGE_BASE_MAC = "1.3.6.1.2.1.17.1.1.0"

_IP_ORIGIN_NAMES = {1: "other", 2: "manual", 4: "dhcp", 5: "linklayer", 6: "random"}

# Communities we treat as non-secret for log purposes. Anything else (a custom
# string the operator picked) gets masked so it doesn't end up in container
# logs / log shippers in plaintext. `public` / `private` are the historical
# RFC defaults - virtually every SNMP agent ships pre-configured with them.
_PUBLIC_COMMUNITIES = {"public", "private"}


def _mask_community(community: str) -> str:
    """Return a redacted form unless the community is one of the well-known
    defaults. Avoids leaking custom strings into shared logs."""
    return community if community in _PUBLIC_COMMUNITIES else "<set>"

# POWER-ETHERNET-MIB pethPsePortDetectionStatus values, mapped to the three
# states the UI actually distinguishes: delivering, fault, and "nothing here".
# Standard state 2 (searching = PoE enabled but no PD detected) and state 5
# (test) both fold to "disabled" so empty/idle PoE ports render without a
# status dot - otherwise every disconnected PoE port carries a dim yellow
# indicator and the ones genuinely delivering power get lost in the noise.
# Same rule the D-Link CLI parser applies to "OFF/Interim".
_POE_DETECTION_NAMES = {
    1: "disabled", 2: "disabled",  3: "delivering",
    4: "fault",    5: "disabled",  6: "otherFault",
}


def _to_str(v) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    return str(v)


def _walk_sync(host: str, community: str, oid: str, port: int = 161) -> list[tuple[str, Any]]:
    """Walk an OID subtree. Swallows exceptions and returns [] so a single failed
    sub-walk doesn't blow up the caller, but logs the failure at WARNING so
    silent-empty results are diagnosable. Empty community looks identical to
    "device offline" at the wire level - both produce timeouts - so the log
    message is the only way to tell them apart without packet capture."""
    import puresnmp
    results = []
    try:
        for vb in puresnmp.walk(host, community, oid, port=port):
            results.append((str(vb.oid), vb.value))
    except Exception as exc:
        # De-dupe on (host, port, exception class). A wrong community produces
        # the same exception type for every OID in a poll - log once per host
        # per 5 minutes instead of per-OID.
        _snmp_warn_ratelimited(
            ("walk", host, port, type(exc).__name__),
            "SNMP walk failed: host=%s oid=%s community=%s port=%d - %s: %s "
            "(further identical failures from this host suppressed for %ds)",
            host, oid, _mask_community(community), port,
            type(exc).__name__, exc, _SNMP_WARN_QUIET_SECONDS,
        )
    return results


def _get_sync(host: str, community: str, oid: str, port: int = 161) -> Any:
    import puresnmp
    return puresnmp.get(host, community, oid, port=port)


def _set_sync(host: str, community: str, oid: str, value: int, port: int = 161) -> dict:
    import puresnmp
    try:
        from puresnmp.types import Integer
    except ImportError:
        from x690.types import Integer  # puresnmp 2.x moved types here
    try:
        puresnmp.set(host, community, oid, Integer(value), port=port)
        return {"ok": True}
    except Exception as exc:
        return {"error": str(exc)}


async def _walk(host, community, oid, port=161) -> list[tuple[str, Any]]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _walk_sync, host, community, oid, port)


async def _get(host, community, oid, port=161) -> Any:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _get_sync, host, community, oid, port)


async def _set(host, community, oid, value, port=161) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _set_sync, host, community, oid, value, port)


def _last(oid: str) -> str:
    return str(oid).rsplit(".", 1)[-1]


def _last2(oid: str) -> str:
    parts = str(oid).rsplit(".", 2)
    return f"{parts[-2]}.{parts[-1]}" if len(parts) >= 3 else parts[-1]


def _safe_int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _fmt_mac(value) -> str | None:
    """Format a 6-byte SNMP value (bytes or ASCII-hex) as 'aa:bb:cc:dd:ee:ff'."""
    if isinstance(value, bytes) and len(value) == 6:
        return ":".join(f"{b:02x}" for b in value)
    if isinstance(value, str) and len(value) == 17 and value.count(":") == 5:
        return value.lower()
    return None


def _ip_from_oid_tail(oid: str) -> str | None:
    """Extract a dotted-decimal IPv4 from the last 4 numeric segments of an OID.
    Both ipNetToMediaTable and ipNetToPhysicalTable encode the IP as the final
    4 sub-IDs of the index. Returns None if no plausible IPv4 is found."""
    parts = str(oid).split(".")
    if len(parts) < 4:
        return None
    try:
        octets = [int(p) for p in parts[-4:]]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    return ".".join(str(o) for o in octets)


def _bytes_to_ip(value) -> str | None:
    """Convert a 4-byte SNMP IpAddress value (or already-stringified IP) to
    dotted-decimal."""
    if isinstance(value, bytes) and len(value) == 4:
        return ".".join(str(b) for b in value)
    if isinstance(value, str):
        # Already dotted-decimal? Validate loosely and pass through.
        parts = value.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return value
    return None


def _format_uptime(value) -> str | None:
    """sysUpTime comes back as a Python timedelta from puresnmp (TimeTicks
    decoded). Drop sub-second precision so the UI doesn't show '0:01:23.456'."""
    if value is None:
        return None
    if isinstance(value, timedelta):
        return str(timedelta(seconds=int(value.total_seconds())))
    return _to_str(value)


def _first_nonempty(walk_result) -> str | None:
    """Pick the first non-empty string value from a walk (Entity MIB rows are
    repeated per slot/module/PSU; we just want the chassis row, which is the
    first one with content)."""
    if not walk_result:
        return None
    for _oid, v in walk_result:
        s = _to_str(v).strip() if v is not None else ""
        if s:
            return s
    return None


class SNMPAdapter(BaseAdapter):
    REQUIREMENTS = [
        {
            "service": "SNMPv2c",
            "transport": "snmp",
            "port": 161,
            "description": "Read community for inventory, ports, MAC table",
            "required": True,
        },
    ]

    def requirements(self) -> list[dict]:
        # Reflect any port override from credentials so the tooltip and the
        # active test use the same number the adapter actually talks to.
        port = int(self.credentials.get("port") or 161)
        return [{**r, "port": port} for r in self.REQUIREMENTS]

    def __init__(self, hostname: str, credentials: dict):
        super().__init__(hostname, credentials)
        # `.get(key, default)` only uses the default when the key is missing.
        # An empty string in the form lands in the JSON blob as "" - which is
        # a valid community wire-side but always rejected by the agent - so
        # use `or` to also fall back when the stored value is empty/None.
        # Defaults follow the historical SNMP convention: public for reads
        # (read-only), private for writes (read-write). Most agents ship with
        # exactly these two communities pre-configured. Users with a custom
        # write community must set `write_community` explicitly; we don't fall
        # back to the read community for writes because that would silently
        # SET-with-public on misconfigured devices and produce confusing
        # "No Access" errors instead of failing the SET at credential build.
        self.community       = credentials.get("community") or "public"
        self.write_community = credentials.get("write_community") or "private"
        self.port            = int(credentials.get("port") or 161)

    def get_supported_cache_keys(self) -> list[str]:
        return ["status", "ports", "poe", "connected"]

    async def fetch(self, cache_key: str) -> Any:
        if cache_key == "status":    return await self._status()
        if cache_key == "ports":     return await self._ports()
        if cache_key == "poe":       return await self._poe()
        if cache_key == "connected": return await self._connected()
        raise ValueError(f"Unknown cache key: {cache_key!r}")

    async def _status(self) -> dict:
        # All probes in parallel - single round-trip latency for the whole set.
        # Devices that don't expose a given table just return [] / None and
        # the corresponding field stays null in the response.
        probe_labels = (
            "sysName", "sysDescr", "sysUptime", "bridgeBaseMac",
            "ipAdEntAddr", "ipAdEntNetMask", "ipAddressOrigin", "ipRouteNextHop",
            "entPhysicalSoftwareRev", "entPhysicalSerialNum",
        )
        results = await asyncio.gather(
            _get(self.hostname,  self.community, _SYS_NAME,         self.port),
            _get(self.hostname,  self.community, _SYS_DESCR,        self.port),
            _get(self.hostname,  self.community, _SYS_UPTIME,       self.port),
            _get(self.hostname,  self.community, _BRIDGE_BASE_MAC,  self.port),
            _walk(self.hostname, self.community, _OWN_IP_TBL,       self.port),
            _walk(self.hostname, self.community, _IP_NETMASK,       self.port),
            _walk(self.hostname, self.community, _IP_ORIGIN,        self.port),
            _walk(self.hostname, self.community, _ROUTE_NEXTHOP,    self.port),
            _walk(self.hostname, self.community, _ENT_SOFT_REV,     self.port),
            _walk(self.hostname, self.community, _ENT_SERIAL,       self.port),
            return_exceptions=True,
        )

        # `return_exceptions=True` turns probe failures into values rather than
        # propagating them - without this loop they vanish silently and the
        # device just looks "offline" with no log line to debug. The walks
        # already log via _walk_sync; only _get failures need surfacing here.
        for label, result in zip(probe_labels, results):
            if isinstance(result, Exception):
                _snmp_warn_ratelimited(
                    ("probe", self.hostname, self.port, label, type(result).__name__),
                    "SNMP probe failed: host=%s probe=%s community=%s port=%d - %s: %s",
                    self.hostname, label, _mask_community(self.community),
                    self.port, type(result).__name__, result,
                )

        def _ok(v):
            return None if isinstance(v, Exception) else v

        name, descr, uptime, base_mac = (_ok(r) for r in results[:4])
        ipaddr_w, mask_w, origin_w, route_w, fw_w, sn_w = (
            _ok(r) or [] for r in results[4:]
        )

        # Pick the first non-loopback IP from ipAdEntAddr; the OID tail is the
        # IP itself, which makes joining to netmask and origin trivial.
        ip_address: str | None = None
        ip_tail: str | None = None
        for oid, v in ipaddr_w:
            ip = _bytes_to_ip(v)
            if ip and not ip.startswith("127."):
                ip_address = ip
                ip_tail = oid[len(_OWN_IP_TBL) + 1:]
                break

        subnet_mask: str | None = None
        if ip_tail:
            for oid, v in mask_w:
                if oid.endswith("." + ip_tail):
                    subnet_mask = _bytes_to_ip(v)
                    break

        # ipAddressOrigin is keyed by `<addr-type>.<addr-len>.<ip-bytes>`; we
        # can't trivially match by tail, so just take the first row that maps
        # to our IP. On switches with one mgmt IP there's only one row anyway.
        ip_origin: str | None = None
        for oid, v in origin_w:
            if ip_address and oid.endswith("." + ip_address):
                ip_origin = _IP_ORIGIN_NAMES.get(_safe_int(v), str(_safe_int(v)))
                break
        if ip_origin is None and origin_w:
            # Fallback: take the first row even without an IP match.
            ip_origin = _IP_ORIGIN_NAMES.get(_safe_int(origin_w[0][1]), None)

        # Default-route gateway: ipRouteNextHop indexed by .0.0.0.0 destination.
        gateway: str | None = None
        for oid, v in route_w:
            if oid.endswith(".0.0.0.0"):
                gw = _bytes_to_ip(v)
                if gw and gw != "0.0.0.0":
                    gateway = gw
                    break

        online = name is not None
        if not online:
            # sysName is the cheapest "is this thing answering at all?" probe.
            # When it comes back as None *and* nothing else did either, we're
            # almost always looking at wrong creds or unreachable host - log
            # so the user can tell those apart from a legitimately-down box.
            other_results = (descr, uptime, base_mac, ipaddr_w, mask_w, origin_w, route_w, fw_w, sn_w)
            if all(v is None or v == [] for v in other_results):
                _snmp_warn_ratelimited(
                    ("offline", self.hostname, self.port),
                    "SNMP host=%s appears offline or rejecting all probes "
                    "(community=%s port=%d) - check community string, host reachability, "
                    "and SNMP manager allow-list on the device",
                    self.hostname, _mask_community(self.community), self.port,
                )

        return {
            "online":     online,
            "sysName":    _to_str(name)  if name  is not None else None,
            "sysDescr":   _to_str(descr) if descr is not None else None,
            "sysUptime":  _format_uptime(uptime),
            "ipAddress":  ip_address,
            "subnetMask": subnet_mask,
            "gateway":    gateway,
            "ipOrigin":   ip_origin,
            "mac":        _fmt_mac(base_mac),
            "firmware":   _first_nonempty(fw_w),
            "serial":     _first_nonempty(sn_w),
        }

    async def _ports(self) -> list[dict]:
        oids = [_IF_DESCR, _IF_TYPE, _IF_ADMIN_STATUS, _IF_OPER_STATUS,
                _IF_IN_OCTETS, _IF_OUT_OCTETS, _IF_HIGH_SPEED, _IF_ALIAS]
        walks = await asyncio.gather(
            *[_walk(self.hostname, self.community, o, self.port) for o in oids],
            return_exceptions=True,
        )

        def to_map(result):
            if isinstance(result, Exception) or not result:
                return {}
            return {_last(oid): v for oid, v in result}

        descr_m = to_map(walks[0])
        type_m  = to_map(walks[1])
        admin_m = to_map(walks[2])
        oper_m  = to_map(walks[3])
        in_m    = to_map(walks[4])
        out_m   = to_map(walks[5])
        speed_m = to_map(walks[6])
        alias_m = to_map(walks[7])

        # Use the union of ALL walked OIDs - D-Link sometimes omits ifDescr
        # for unpopulated SFP/combo ports, but they still have admin/oper status.
        all_indices = set(descr_m) | set(admin_m) | set(oper_m)

        ports = []
        for idx in sorted(all_indices, key=lambda x: _safe_int(x, 0)):
            ports.append({
                "index":       idx,
                "name":        _to_str(descr_m.get(idx, f"Port {idx}")),
                "alias":       _to_str(alias_m.get(idx, "")),
                "ifType":      _safe_int(type_m.get(idx), 0),
                "adminStatus": _safe_int(admin_m.get(idx), 0),  # 1=up 2=down
                "operStatus":  _safe_int(oper_m.get(idx),  0),
                "speedMbps":   _safe_int(speed_m.get(idx), 0),
                "inOctets":    _safe_int(in_m.get(idx),    0),
                "outOctets":   _safe_int(out_m.get(idx),   0),
            })
        return ports

    async def _poe(self) -> dict:
        walks = await asyncio.gather(
            _walk(self.hostname, self.community, _POE_PORT_ADMIN,     self.port),
            _walk(self.hostname, self.community, _POE_PORT_DETECTION, self.port),
            _walk(self.hostname, self.community, _POE_PORT_CLASS,     self.port),
            _walk(self.hostname, self.community, _POE_MAIN_POWER,     self.port),
            _walk(self.hostname, self.community, _POE_CONSUMPTION,    self.port),
            return_exceptions=True,
        )

        def poe_map(result):
            if isinstance(result, Exception) or not result:
                return {}
            return {_last2(oid): v for oid, v in result}

        admin_m  = poe_map(walks[0])
        detect_m = poe_map(walks[1])
        class_m  = poe_map(walks[2])

        def scalar_list(result):
            if isinstance(result, Exception) or not result:
                return []
            return [_safe_int(v) for _, v in result]

        main_watts = scalar_list(walks[3])
        cons_watts = scalar_list(walks[4])

        # Sort numerically by (group, port). The keys look like "1.1", "1.10",
        # "1.2"; sorted() on strings would produce 1.1, 1.10, 1.11, …, 1.2 -
        # the classic natural-sort trap.
        def _poe_key(k: str) -> tuple[int, ...]:
            try:
                return tuple(int(p) for p in k.split("."))
            except ValueError:
                return (10**9,)  # malformed keys go to the end

        ports = []
        for key in sorted(admin_m, key=_poe_key):
            port_idx = key.split(".")[-1]
            det = _safe_int(detect_m.get(key), 1)
            ports.append({
                "key":             key,
                "portIndex":       port_idx,
                "adminEnabled":    _safe_int(admin_m.get(key), 2) == 1,
                "detectionStatus": _POE_DETECTION_NAMES.get(det, str(det)),
                "powerClass":      _safe_int(class_m.get(key), 0),
            })

        return {
            "ports":            ports,
            "totalPowerWatts":  main_watts[0] if main_watts else None,
            "consumptionWatts": cons_watts[0] if cons_watts else None,
        }

    async def _connected(self) -> list[dict]:
        """Return MAC table joined with bridge-port→ifIndex and (where the
        switch knows it) ARP-derived IP. Devices that haven't talked to the
        switch's L3 plane will have ip=None - that's not a bug, the switch
        genuinely doesn't know.
        """
        fdb_addr_w, fdb_port_w, b2i_w, arp_mod_w, arp_leg_w, own_w = await asyncio.gather(
            _walk(self.hostname, self.community, _FDB_ADDR,           self.port),
            _walk(self.hostname, self.community, _FDB_PORT,           self.port),
            _walk(self.hostname, self.community, _BRIDGE_PORT_TO_IF,  self.port),
            _walk(self.hostname, self.community, _ARP_MODERN,         self.port),
            _walk(self.hostname, self.community, _ARP_LEGACY,         self.port),
            _walk(self.hostname, self.community, _OWN_IP_TBL,         self.port),
            return_exceptions=True,
        )

        def _safe(walk):
            return [] if isinstance(walk, Exception) else (walk or [])

        # bridge-port → ifIndex (e.g. {"1": 1, "2": 2, ...})
        b2i = {oid.rsplit(".", 1)[-1]: str(_safe_int(v)) for oid, v in _safe(b2i_w)}

        # Build MAC table: the OID tail after _FDB_ADDR is shared between the
        # address and port walks, so we can join by it.
        addr_by_tail = {oid[len(_FDB_ADDR) + 1:]: v for oid, v in _safe(fdb_addr_w)}
        port_by_tail = {oid[len(_FDB_PORT) + 1:]: v for oid, v in _safe(fdb_port_w)}

        # ARP joins. Modern table is preferred - its key already contains the
        # IP as dotted decimal (e.g. ".5121.1.4.192.168.0.1"); the trailing 4
        # octets are the IP. Legacy table encodes the IP the same way.
        mac_to_ip: dict[str, str] = {}
        for oid, v in _safe(arp_mod_w):
            mac = _fmt_mac(v)
            ip = _ip_from_oid_tail(oid)
            if mac and ip:
                mac_to_ip.setdefault(mac, ip)
        if not mac_to_ip:
            for oid, v in _safe(arp_leg_w):
                mac = _fmt_mac(v)
                ip = _ip_from_oid_tail(oid)
                if mac and ip:
                    mac_to_ip.setdefault(mac, ip)

        own_ips = {_ip_from_oid_tail(oid) for oid, _ in _safe(own_w)}
        own_ips.discard(None)

        result = []
        for tail, mac_bytes in addr_by_tail.items():
            mac = _fmt_mac(mac_bytes)
            if not mac:
                continue
            bridge_port = str(_safe_int(port_by_tail.get(tail), 0))
            # Bridge-port 0 = the switch's own CPU; not a real edge port.
            if bridge_port == "0":
                continue
            if_index = b2i.get(bridge_port, bridge_port)  # fall back to bridge-port if no mapping
            ip = mac_to_ip.get(mac)
            result.append({
                "mac":      mac,
                "port_id":  if_index,
                "vendor":   oui_lookup(mac),
                "ip":       ip,
                "is_self":  bool(ip and ip in own_ips),
            })

        # Stable sort: numeric port asc, then MAC.
        result.sort(key=lambda r: (_safe_int(r["port_id"], 9999), r["mac"]))
        return result

    async def execute_action(self, action: dict) -> dict:
        atype = action.get("type")
        if atype == "port_admin":
            port_id = action.get("port_id")
            enable  = action.get("enable", True)
            oid     = f"1.3.6.1.2.1.2.2.1.7.{port_id}"
            return await _set(self.hostname, self.write_community, oid, 1 if enable else 2, self.port)
        return {"error": f"Unsupported action: {atype!r}"}
