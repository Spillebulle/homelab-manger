"""
Generic SNMP adapter using puresnmp (pure Python, no C deps, no version chaos).
"""
import asyncio
from typing import Any
from .base import BaseAdapter

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

_POE_DETECTION_NAMES = {
    1: "disabled", 2: "searching", 3: "delivering",
    4: "fault",    5: "test",      6: "otherFault",
}


def _to_str(v) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    return str(v)


def _walk_sync(host: str, community: str, oid: str, port: int = 161) -> list[tuple[str, Any]]:
    import puresnmp
    results = []
    try:
        for vb in puresnmp.walk(host, community, oid, port=port):
            results.append((str(vb.oid), vb.value))
    except Exception:
        pass
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
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _walk_sync, host, community, oid, port)


async def _get(host, community, oid, port=161) -> Any:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_sync, host, community, oid, port)


async def _set(host, community, oid, value, port=161) -> dict:
    loop = asyncio.get_event_loop()
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


class SNMPAdapter(BaseAdapter):
    def __init__(self, hostname: str, credentials: dict):
        super().__init__(hostname, credentials)
        self.community       = credentials.get("community", "public")
        self.write_community = credentials.get("write_community", credentials.get("community", "private"))
        self.port            = int(credentials.get("port", 161))

    def get_supported_cache_keys(self) -> list[str]:
        return ["status", "ports", "poe"]

    async def fetch(self, cache_key: str) -> Any:
        if cache_key == "status": return await self._status()
        if cache_key == "ports":  return await self._ports()
        if cache_key == "poe":    return await self._poe()
        raise ValueError(f"Unknown cache key: {cache_key!r}")

    async def _status(self) -> dict:
        name, descr, uptime = await asyncio.gather(
            _get(self.hostname, self.community, _SYS_NAME,   self.port),
            _get(self.hostname, self.community, _SYS_DESCR,  self.port),
            _get(self.hostname, self.community, _SYS_UPTIME, self.port),
        )
        return {
            "online":    name is not None,
            "sysName":   _to_str(name)   if name   is not None else None,
            "sysDescr":  _to_str(descr)  if descr  is not None else None,
            "sysUptime": _to_str(uptime) if uptime is not None else None,
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

        # Use the union of ALL walked OIDs — D-Link sometimes omits ifDescr
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

        ports = []
        for key in sorted(admin_m):
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

    async def execute_action(self, action: dict) -> dict:
        atype = action.get("type")
        if atype == "port_admin":
            port_id = action.get("port_id")
            enable  = action.get("enable", True)
            oid     = f"1.3.6.1.2.1.2.2.1.7.{port_id}"
            return await _set(self.hostname, self.write_community, oid, 1 if enable else 2, self.port)
        return {"error": f"Unsupported action: {atype!r}"}
