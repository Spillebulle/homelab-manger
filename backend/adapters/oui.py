"""
Tiny embedded OUI → vendor lookup. Intentionally not exhaustive — covers what's
likely to show up in a homelab. Extend by adding entries below; keys are the
first 6 hex chars of a MAC, lowercase, no separator.

If you need full coverage, swap this for a parser that reads the IEEE OUI list
or the wireshark `manuf` file from disk. For now, unknown OUIs just render as
the prefix itself in the UI.
"""

OUI_VENDORS: dict[str, str] = {
    # ── Virtualisation ──────────────────────────────────────────────
    "005056": "VMware", "000c29": "VMware", "001c14": "VMware",
    "00155d": "Microsoft Hyper-V",
    "525400": "QEMU/KVM",
    "080027": "VirtualBox",
    "0a0027": "VirtualBox",
    "0242ac": "Docker", "024200": "Docker",

    # ── Single-board / IoT ──────────────────────────────────────────
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi",
    "e45f01": "Raspberry Pi", "28cdc1": "Raspberry Pi",
    "2ccf67": "Raspberry Pi", "d83add": "Raspberry Pi",

    # ── Servers / enterprise ────────────────────────────────────────
    "00000c": "Cisco", "001142": "Cisco", "001bd4": "Cisco",
    "002354": "Cisco", "0023cd": "Cisco", "00243d": "Cisco",
    "70b3d5": "Cisco", "ec3091": "Cisco",
    "f4ea67": "Cisco", "1cdf0f": "Cisco",

    "001b21": "Dell", "001f3b": "Dell", "00237d": "Dell",
    "002564": "Dell", "001e0b": "Dell", "b083fe": "Dell",
    "141877": "Dell", "782bcb": "Dell", "18dbf2": "Dell",
    "f4e9d4": "Dell", "f8b156": "Dell", "f8db88": "Dell",

    "001a4b": "HP/HPE", "001a4d": "HP/HPE", "001cc4": "HP/HPE",
    "002481": "HP/HPE", "70624b": "HP/HPE", "7062b8": "HP/HPE",
    "9c8e99": "HP/HPE", "1c98ec": "HP/HPE", "98e7f4": "HP/HPE",
    "c4346b": "HP/HPE", "ecb1d7": "HP/HPE", "fc15b4": "HP/HPE",

    "0017a4": "Huawei", "001882": "Huawei", "002568": "Huawei",
    "0025b3": "Huawei", "0025b9": "Huawei", "1c1d67": "Huawei",
    "2cab00": "Huawei", "346f92": "Huawei", "70541c": "Huawei",
    "7c1c68": "Huawei", "8421f1": "Huawei", "f4cb52": "Huawei",
    "fc01cb": "Huawei",

    "00112f": "ASUSTek", "001bfc": "ASUSTek", "00248c": "ASUSTek",
    "0c9d92": "ASUSTek", "1c872c": "ASUSTek", "2c4d54": "ASUSTek",
    "305a3a": "ASUSTek", "381a52": "ASUSTek", "60a44c": "ASUSTek",

    "ac1f6b": "Supermicro", "0025902": "Supermicro",
    "002590": "Supermicro", "00306e": "Supermicro",
    "3cecef": "Supermicro", "7cc25535": "Supermicro",

    "001321": "IBM", "00145e": "IBM", "5cf3fc": "Lenovo",
    "08f1ea": "Lenovo", "70a6cc": "Lenovo", "e8e8b7": "Lenovo",

    # ── Switching / networking ──────────────────────────────────────
    "001b11": "D-Link", "001cf0": "D-Link", "001e58": "D-Link",
    "001f1f": "D-Link", "002191": "D-Link", "0022b0": "D-Link",
    "002401": "D-Link", "00265a": "D-Link", "1c7ee5": "D-Link",
    "1caff7": "D-Link", "28107b": "D-Link", "28cfda": "D-Link",
    "340804": "D-Link", "78321b": "D-Link", "78542e": "D-Link",
    "84c9b2": "D-Link", "acf1df": "D-Link", "b0c554": "D-Link",
    "c0a0bb": "D-Link", "ccb255": "D-Link",

    "245a4c": "Ubiquiti", "f09fc2": "Ubiquiti", "788a20": "Ubiquiti",
    "0418d6": "Ubiquiti", "802aa8": "Ubiquiti", "18e829": "Ubiquiti",
    "44d9e7": "Ubiquiti", "68d79a": "Ubiquiti", "7483c2": "Ubiquiti",
    "784558": "Ubiquiti", "ac8ba9": "Ubiquiti", "b4fbe4": "Ubiquiti",
    "d021f9": "Ubiquiti", "dc9fdb": "Ubiquiti", "e43883": "Ubiquiti",
    "e063da": "Ubiquiti", "fcecda": "Ubiquiti", "242c0a": "Ubiquiti",

    "002272": "MikroTik", "4c5e0c": "MikroTik", "6c3b6b": "MikroTik",
    "744d28": "MikroTik", "b869f4": "MikroTik", "c4ad34": "MikroTik",
    "cc2db7": "MikroTik", "dca632": "MikroTik", "e48d8c": "MikroTik",

    "001fc6": "Netgear", "204e7f": "Netgear", "28c68e": "Netgear",
    "30469a": "Netgear", "3498b5": "Netgear", "44a56e": "Netgear",
    "9c3dcf": "Netgear", "a040a0": "Netgear", "c40415": "Netgear",
    "e091f5": "Netgear",

    "0017df": "Cisco/Linksys", "001839": "Cisco/Linksys",

    "00184d": "Netgear",
    "00226b": "Cisco/Linksys",

    # ── NAS / storage ───────────────────────────────────────────────
    "001132": "Synology", "0011321": "Synology", "9c477e": "Synology",
    "0008c7": "QNAP", "245ebe": "QNAP", "001005": "QNAP",
    "245ebe": "QNAP",

    "0024e8": "Dell EMC", "002219": "NetApp",

    # ── Apple ───────────────────────────────────────────────────────
    "9c6b00": "Apple", "1cce51": "Apple", "1c1ac0": "Apple",
    "001451": "Apple", "001b63": "Apple", "001ec2": "Apple",
    "001f5b": "Apple", "0023df": "Apple", "00254b": "Apple",
    "0025bc": "Apple", "002608": "Apple", "00264a": "Apple",
    "0026b0": "Apple", "0026bb": "Apple", "040cce": "Apple",
    "04489a": "Apple", "045453": "Apple", "08664a": "Apple",
    "0c3021": "Apple", "0c3e9f": "Apple", "0c4de9": "Apple",
    "0c74c2": "Apple", "0c771a": "Apple", "0cbc9f": "Apple",
    "0cd746": "Apple", "101c0c": "Apple", "10dd b1": "Apple",
    "14109f": "Apple", "1099f1": "Apple", "14756d": "Apple",
    "188861": "Apple", "189efc": "Apple", "18af61": "Apple",
    "248a07": "Apple", "24a074": "Apple", "24a2e1": "Apple",
    "24ab81": "Apple", "28e02c": "Apple", "28e7cf": "Apple",
    "2cb43a": "Apple", "2cf0a2": "Apple", "30636b": "Apple",
    "3490fb": "Apple", "34c059": "Apple",
    "38484c": "Apple", "38c986": "Apple", "3c0754": "Apple",
    "3c15c2": "Apple", "402cf4": "Apple", "40331a": "Apple",
    "406c8f": "Apple", "40b395": "Apple", "44d884": "Apple",
    "4c8d79": "Apple", "4cb199": "Apple",
    "5cf938": "Apple", "60334b": "Apple", "606944": "Apple",
    "608c4a": "Apple", "60d9c7": "Apple", "60fb42": "Apple",
    "64200c": "Apple", "649abe": "Apple", "64a3cb": "Apple",
    "64b0a6": "Apple", "64b9e8": "Apple", "64e682": "Apple",
    "685b35": "Apple", "68967b": "Apple", "68a86d": "Apple",
    "6c3e6d": "Apple", "6c4008": "Apple", "6c4d73": "Apple",
    "6c709f": "Apple", "6c8dc1": "Apple", "6c94f8": "Apple",
    "6c96cf": "Apple", "6cab31": "Apple", "703eac": "Apple",
    "704856": "Apple", "70cd60": "Apple", "70dee2": "Apple",
    "70ece4": "Apple", "70f087": "Apple", "741bb2": "Apple",
    "78316b": "Apple", "786c1c": "Apple", "78a3e4": "Apple",
    "78ca39": "Apple", "78d75f": "Apple", "78e103": "Apple",
    "78f882": "Apple", "7c0191": "Apple", "7c11be": "Apple",
    "7c6df8": "Apple", "7cc3a1": "Apple", "7cd1c3": "Apple",
    "7cf05f": "Apple", "7cfadf": "Apple", "80929f": "Apple",
    "80b03d": "Apple", "84299b": "Apple", "843835": "Apple",
    "84788b": "Apple", "848e0c": "Apple", "84a134": "Apple",
    "84b153": "Apple", "84fcac": "Apple", "881fa1": "Apple",
    "8866a5": "Apple", "886b6e": "Apple", "8c006d": "Apple",
    "8c2937": "Apple", "8c2daa": "Apple", "8c5877": "Apple",
    "8c7b9d": "Apple", "8c7c92": "Apple", "8c8590": "Apple",
    "8ce5c5": "Apple", "9027e4": "Apple", "9060f1": "Apple",
    "907240": "Apple", "9084d6": "Apple", "908d6c": "Apple",
    "90b0ed": "Apple", "90b931": "Apple", "90dd5d": "Apple",
    "90e17b": "Apple", "90fd61": "Apple", "98031d": "Apple",
    "98f0ab": "Apple", "9c04eb": "Apple", "9c207b": "Apple",
    "9c4fda": "Apple", "9c84bf": "Apple", "9cf48e": "Apple",
    "9cfc01": "Apple", "a01828": "Apple", "a0d795": "Apple",
    "a45e60": "Apple", "a46706": "Apple", "a483e7": "Apple",
    "a4b197": "Apple", "a4d18c": "Apple", "a4f1e8": "Apple",
    "a82066": "Apple", "a85b78": "Apple", "a85c2c": "Apple",
    "a8667f": "Apple", "a88e24": "Apple", "a8968a": "Apple",
    "a8bbcf": "Apple", "a8fad8": "Apple", "ac1f74": "Apple",
    "ac293a": "Apple", "ac3c0b": "Apple", "ac61ea": "Apple",
    "ac7f3e": "Apple", "ac87a3": "Apple", "ac88fd": "Apple",
    "acbc32": "Apple", "accf5c": "Apple", "ace4b5": "Apple",
    "acfdec": "Apple", "b019c6": "Apple", "b03495": "Apple",
    "b0481a": "Apple", "b065bd": "Apple", "b09fba": "Apple",
    "b0ca68": "Apple", "b418d1": "Apple", "b44bd2": "Apple",
    "b48b19": "Apple", "b4f0ab": "Apple", "b8098a": "Apple",
    "b81fa1": "Apple", "b844d9": "Apple", "b853ac": "Apple",
    "b85d0a": "Apple", "b8782e": "Apple", "b88d12": "Apple",
    "b8c75d": "Apple", "b8e856": "Apple", "b8f6b1": "Apple",
    "b8ff61": "Apple", "bc3baf": "Apple", "bc4cc4": "Apple",
    "bc52b7": "Apple", "bc5436": "Apple", "bc6c21": "Apple",
    "bc926b": "Apple", "bc9fef": "Apple", "bca920": "Apple",
    "bce143": "Apple", "bcec5d": "Apple", "c01ada": "Apple",
    "c0847a": "Apple", "c09f42": "Apple", "c0f2fb": "Apple",
    "c42c03": "Apple", "c48466": "Apple", "c4b301": "Apple",
    "c81ee7": "Apple", "c82a14": "Apple", "c8334b": "Apple",
    "c869cd": "Apple", "c86f1d": "Apple", "c88550": "Apple",
    "c8b5b7": "Apple", "c8bcc8": "Apple", "c8d083": "Apple",
    "c8e0eb": "Apple", "c8f650": "Apple", "cc088d": "Apple",
    "cc08e0": "Apple", "cc25ef": "Apple", "cc29f5": "Apple",
    "cc4463": "Apple", "cc785f": "Apple", "ccc760": "Apple",
    "cccc3f": "Apple", "d0034b": "Apple", "d023db": "Apple",
    "d02598": "Apple", "d03311": "Apple", "d0817a": "Apple",
    "d0a637": "Apple", "d0d2b0": "Apple", "d0e140": "Apple",
    "d4619d": "Apple", "d4909c": "Apple", "d49a20": "Apple",
    "d4f46f": "Apple", "d8004d": "Apple", "d81d72": "Apple",
    "d83062": "Apple", "d88f76": "Apple", "d89695": "Apple",
    "d89e3f": "Apple", "d8a25e": "Apple", "d8bb2c": "Apple",
    "d8cf9c": "Apple", "d8d1cb": "Apple", "dc0c5c": "Apple",
    "dc2b2a": "Apple", "dc2b61": "Apple", "dc3714": "Apple",
    "dc415f": "Apple", "dc56e7": "Apple", "dc86d8": "Apple",
    "dc9b9c": "Apple", "dca4ca": "Apple", "dca904": "Apple",
    "dcd213": "Apple", "dce2ac": "Apple", "e05f45": "Apple",
    "e06678": "Apple", "e0accb": "Apple", "e0b52d": "Apple",
    "e0c97a": "Apple", "e0f5c6": "Apple", "e0f847": "Apple",
    "e425e7": "Apple", "e450eb": "Apple", "e48b7f": "Apple",
    "e49a79": "Apple", "e49adc": "Apple", "e4c63d": "Apple",
    "e4ce8f": "Apple", "e8040b": "Apple", "e80688": "Apple",
    "e88d28": "Apple", "e8b2ac": "Apple", "ec3586": "Apple",
    "ec852f": "Apple", "ecadb8": "Apple", "f01898": "Apple",
    "f02475": "Apple", "f099bf": "Apple", "f0b479": "Apple",
    "f0c1f1": "Apple", "f0cba1": "Apple", "f0d1a9": "Apple",
    "f0dbe2": "Apple", "f0dbf8": "Apple", "f0f61c": "Apple",
    "f40f24": "Apple", "f431c3": "Apple", "f437b7": "Apple",
    "f45c89": "Apple", "f4f15a": "Apple", "f4f951": "Apple",
    "f81edf": "Apple", "f82793": "Apple", "f82d7c": "Apple",
    "f83dff": "Apple", "f86214": "Apple", "f86fc1": "Apple",
    "f887f1": "Apple", "fc253f": "Apple", "fc64ba": "Apple",
    "fcd848": "Apple",

    # ── Other common ────────────────────────────────────────────────
    "a0369f": "Intel", "bcf4d4": "Intel", "0013e8": "Intel",
    "001e67": "Intel", "0024d7": "Intel",
    "001ec9": "Sony", "00074d": "Sony",
    "f4f526": "Google", "f8a3a4": "Google",
}


def _normalise(mac: str) -> str:
    return mac.lower().replace(":", "").replace("-", "").replace(".", "")


def lookup(mac: str) -> str | None:
    """Return a vendor name for the given MAC, or None if unknown."""
    if not mac:
        return None
    n = _normalise(mac)
    if len(n) < 6:
        return None
    return OUI_VENDORS.get(n[:6])
