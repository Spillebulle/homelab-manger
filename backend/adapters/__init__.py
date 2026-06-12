from .base import BaseAdapter
from .snmp import SNMPAdapter
from .dlink import DLinkAdapter
from .hpe1820 import HPE1820Adapter
from .cimc import CIMCAdapter
from .cimc_redfish import CIMCRedfishAdapter
from .redfish import RedfishAdapter
from .usbups import USBUPSAdapter

ADAPTER_MAP: dict[str, type[BaseAdapter]] = {
    "snmp":         SNMPAdapter,
    "dlink":        DLinkAdapter,
    "hpe1820":      HPE1820Adapter,      # HPE OfficeConnect 1820 - SNMP read + web UI write
    "cimc":         CIMCAdapter,         # UCS C-series M2/M3, CIMC < 3.0 - XMLAPI + IPMI
    "cimc_redfish": CIMCRedfishAdapter,  # UCS C-series with CIMC 3.0+ - Redfish + XMLAPI hybrid
    "redfish":      RedfishAdapter,
    "ilo":          RedfishAdapter,      # HP iLO 5+
    "idrac":        RedfishAdapter,      # Dell iDRAC 8+
    "ibmc":         RedfishAdapter,      # Huawei iBMC
    "usbups":       USBUPSAdapter,       # USB-connected UPS via HID Power Device class
}


def get_adapter(adapter_type: str, hostname: str, credentials: dict) -> BaseAdapter:
    cls = ADAPTER_MAP.get(adapter_type)
    if not cls:
        raise ValueError(f"Unknown adapter type: {adapter_type!r}")
    instance = cls(hostname, credentials)
    # Tag the instance with the type key it was looked up under. RedfishAdapter
    # serves four types (redfish/ilo/idrac/ibmc); requirements() needs to
    # branch on this so iBMC surfaces its SNMPv3 dependency. Set on the
    # instance rather than the class so two devices with different types
    # (rare, but allowed) don't fight.
    instance.adapter_type = adapter_type
    return instance
