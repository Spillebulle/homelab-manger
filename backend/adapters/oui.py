"""
MAC vendor lookup, backed by the full IEEE OUI registry bundled at
`backend/adapters/oui.csv`. The CSV is parsed once at import and held in
memory (~2-3 MB string data, ~40k entries). Update it by re-downloading from
https://standards-oui.ieee.org/oui/oui.csv

The CSV has rows for MA-L, MA-M, and MA-S registries. We only consume MA-L
(full 24-bit OUI prefixes — what virtually every consumer/enterprise NIC uses).
MA-M / MA-S are 28-bit and 36-bit shared assignments which would need finer-
grained matching against the full MAC; if that ever matters for homelab gear
we'll extend `lookup()` to walk those tiers.
"""
import csv
import logging
import os

logger = logging.getLogger(__name__)

# Friendly-name overrides for cases where the IEEE registration string is
# clunky in a UI ("Hewlett Packard Enterprise" → "HPE", "Cisco Systems, Inc" →
# "Cisco"). Keys are 6-char uppercase hex (no separators); leave a vendor out
# of this map to use the raw IEEE name. Only override what's actually noisy —
# don't try to curate the whole list.
_FRIENDLY_OVERRIDES: dict[str, str] = {}

_OUI_FILE = os.path.join(os.path.dirname(__file__), "oui.csv")
_OUI_VENDORS: dict[str, str] = {}


def _load() -> None:
    if _OUI_VENDORS:
        return
    if not os.path.exists(_OUI_FILE):
        logger.warning("OUI database missing at %s — vendor lookup disabled", _OUI_FILE)
        return
    try:
        with open(_OUI_FILE, encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)  # header
            for row in reader:
                if len(row) < 3 or row[0] != "MA-L":
                    continue
                prefix = row[1].strip().upper()
                org = row[2].strip()
                if prefix and org:
                    _OUI_VENDORS[prefix] = org
        logger.info("OUI database loaded: %d entries", len(_OUI_VENDORS))
    except Exception:
        logger.exception("Failed to parse %s — vendor lookup disabled", _OUI_FILE)
        _OUI_VENDORS.clear()


def _normalise(mac: str) -> str:
    return mac.upper().replace(":", "").replace("-", "").replace(".", "")


def lookup(mac: str) -> str | None:
    """Return a vendor name for the given MAC, or None if unknown."""
    if not mac:
        return None
    _load()
    n = _normalise(mac)
    if len(n) < 6:
        return None
    prefix = n[:6]
    if prefix in _FRIENDLY_OVERRIDES:
        return _FRIENDLY_OVERRIDES[prefix]
    return _OUI_VENDORS.get(prefix)


# Eager-load at import so the first device poll doesn't pay the parse cost.
_load()
