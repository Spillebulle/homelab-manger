from .base import BaseAdapter
from .snmp import SNMPAdapter
from .dlink import DLinkAdapter
from .cimc import CIMCAdapter
from .redfish import RedfishAdapter

ADAPTER_MAP: dict[str, type[BaseAdapter]] = {
    "snmp":    SNMPAdapter,
    "dlink":   DLinkAdapter,
    "cimc":    CIMCAdapter,
    "redfish": RedfishAdapter,
    "ilo":     RedfishAdapter,   # HP iLO 5+
    "idrac":   RedfishAdapter,   # Dell iDRAC 8+
    "ibmc":    RedfishAdapter,   # Huawei iBMC
}


def get_adapter(adapter_type: str, hostname: str, credentials: dict) -> BaseAdapter:
    cls = ADAPTER_MAP.get(adapter_type)
    if not cls:
        raise ValueError(f"Unknown adapter type: {adapter_type!r}")
    return cls(hostname, credentials)
