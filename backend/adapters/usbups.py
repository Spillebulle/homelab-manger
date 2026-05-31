"""
Generic USB-connected UPS adapter — reads a UPS over the standard USB HID
Power Device Class (USB-IF "Usage Tables for HID Power Devices" 1.0), the same
layer NUT's `usbhid-ups` driver sits on. This replaces the need to run NUT for
any UPS that speaks standard HID PDC (APC, CyberPower, Eaton, Tripp Lite, most
PowerWalker/BlueWalker, …).

Why a runtime descriptor parser instead of hardcoded report offsets:
a UPS exposes its data as HID *reports*, and which report ID / bit offset holds
RemainingCapacity vs RunTimeToEmpty vs PercentLoad varies per model and
firmware. Rather than pin to one device's layout, `parse_report_descriptor`
walks the HID report descriptor the device advertises and builds a usage→field
map. We then look up fields by their canonical (page<<16 | selector) usage code
— so the *same* code works across every standard-HID UPS without per-model
tables. The usage codes below are NUT's `usage_lkp` values (the implementation
known to read the BlueWalker VI-2200-SH this was first built for).

What is NOT covered: "megatec/Voltronic/Q*" serial-over-USB UPSs (NUT's
`nutdrv_qx`/`blazer_usb`). Those are not HID Power Devices at all — they're a
USB-serial bridge you send `Q1\r` query strings to. A separate adapter would be
needed; this one will simply find no Power Device usage page and report that.

Hardware access: the UPS must be USB-passed-through to the container
(`docker run --device=/dev/bus/usb/... ` or the bus/dev pair, plus the process
needs permission to open the hidraw node — root in the container, or a udev
rule on the host). See the Dockerfile and CLAUDE.md.
"""
import asyncio
import logging
import threading
import time
from typing import Any

from .base import BaseAdapter

logger = logging.getLogger(__name__)

# The hidraw node is effectively single-open. Each poll cycle builds a fresh
# adapter instance, so a per-instance lock can't serialize a scheduled poll
# against a manual refresh or the /usb-diagnostics endpoint — they'd open the
# device concurrently and one gets EBUSY ("No USB HID Power Device found").
# This process-wide lock serialises every USB session across all instances.
_USB_LOCK = threading.Lock()

# The HID report descriptor is static per device, so parse it once per
# (vid, pid) and reuse — steady-state polls then issue only the GET_REPORT
# value reads (fewer USB transfers, fewer chances for a transient read error).
_FIELDS_CACHE: dict[tuple[int, int], list] = {}

# ── Canonical HID Power Device usage codes (page << 16 | selector) ────────────
# Values from NUT's drivers/usbhid-ups.c `usage_lkp[]`. Do NOT swap these for
# the numbers some online "usb hid usage" tables list (e.g. PercentLoad 0x45,
# RemainingCapacity 0x86) — those tables are wrong for the PDC spec; NUT's are
# the ones that actually decode real UPS hardware.
PAGE_POWER   = 0x84
PAGE_BATTERY = 0x85

U_PRESENT_STATUS   = 0x00840002
U_VOLTAGE          = 0x00840030
U_CURRENT          = 0x00840031
U_FREQUENCY        = 0x00840032
U_APPARENT_POWER   = 0x00840033
U_ACTIVE_POWER     = 0x00840034   # watts (real power), when the UPS reports it
U_PERCENT_LOAD     = 0x00840035   # % of rated load
U_TEMPERATURE      = 0x00840036
U_CONFIG_VOLTAGE   = 0x00840040
U_CONFIG_ACTIVE_PW = 0x00840044   # ConfigActivePower = rated real power (W).
#                                   NB: 0x43 is ConfigApparentPower (VA) — a
#                                   different thing; don't use it for watts.

U_REMAINING_CAP    = 0x00850066   # battery charge %
U_FULL_CHARGE_CAP  = 0x00850067
U_RUNTIME_TO_EMPTY = 0x00850068   # seconds
U_CHARGING         = 0x00850044
U_DISCHARGING      = 0x00850045
U_NEED_REPLACEMENT = 0x0085004b
U_BELOW_CAP_LIMIT  = 0x00850042   # low-battery flag
U_REMAINING_T_LIM  = 0x00850043
U_AC_PRESENT       = 0x008500d0
U_BATTERY_PRESENT  = 0x008500d1
U_SHUTDOWN_IMMINENT = 0x00850069
U_OVERLOAD         = 0x00850065

# Default identity for the unit this adapter was first written against
# (BlueWalker/PowerWalker VI-2200-SH, Phoenixtec chip). Auto-detect kicks in
# when no VID/PID is configured, so these are only a hint, not a hard pin.
_DEFAULT_VID = 0x06DA
_DEFAULT_PID = 0xFFFF

# VI-2200 rated real power. Used only when the UPS doesn't expose ActivePower /
# ConfigActivePower itself (this unit doesn't), to derive watts from load %.
_DEFAULT_NOMINAL_WATTS = 1320


# ── HID report descriptor parser ──────────────────────────────────────────────

class HidField:
    """One scalar field inside a HID report: where it lives (report id + bit
    range), what it means (usage), and how to scale it (logical range + unit
    exponent)."""
    __slots__ = ("usage", "report_id", "report_type", "bit_offset", "bit_size",
                 "logical_min", "logical_max", "unit", "unit_exp")

    def __init__(self, usage, report_id, report_type, bit_offset, bit_size,
                 logical_min, logical_max, unit, unit_exp):
        self.usage = usage
        self.report_id = report_id
        self.report_type = report_type   # "input" | "output" | "feature"
        self.bit_offset = bit_offset
        self.bit_size = bit_size
        self.logical_min = logical_min
        self.logical_max = logical_max
        self.unit = unit
        self.unit_exp = unit_exp

    def __repr__(self):
        return (f"HidField(usage=0x{self.usage:08x} id={self.report_id} "
                f"{self.report_type} off={self.bit_offset} size={self.bit_size})")


def _signed(value: int, bits: int) -> int:
    """Interpret `bits`-wide `value` as two's-complement signed."""
    if bits and (value & (1 << (bits - 1))):
        return value - (1 << bits)
    return value


def _unit_exp(nibble: int) -> int:
    """HID unit-exponent nibble → decimal exponent. 0x0-0x7 → 0..7,
    0x8-0xF → -8..-1."""
    return nibble - 16 if nibble > 7 else nibble


def parse_report_descriptor(desc: bytes) -> list[HidField]:
    """Walk a raw HID report descriptor and return one HidField per scalar
    item in every Input/Output/Feature main item. This is a deliberately small
    HID parser: it tracks just the global/local item state needed to assign
    usages to bit ranges. Long items (0xFE) are skipped — no UPS uses them."""
    fields: list[HidField] = []

    # Global item state (persists across main items; Push/Pop save/restore it).
    g = {"usage_page": 0, "logical_min": 0, "logical_max": 0,
         "report_size": 0, "report_count": 0, "report_id": 0,
         "unit": 0, "unit_exp": 0}
    gstack: list[dict] = []

    # Local item state (reset after every main item).
    usages: list[int] = []
    usage_min = usage_max = None

    # Bit cursor per (report_id, report_type) — each report type has its own
    # packing; the report-id byte itself is not counted (offsets are within the
    # data payload).
    bitpos: dict[tuple[int, str], int] = {}

    def full_usage(u: int) -> int:
        # 4-byte usages carry the page in the high word ("extended usage");
        # 1/2-byte usages combine with the current global Usage Page.
        return u if u > 0xFFFF else ((g["usage_page"] << 16) | (u & 0xFFFF))

    i, n = 0, len(desc)
    while i < n:
        prefix = desc[i]
        i += 1
        if prefix == 0xFE:   # long item — skip it entirely
            if i < n:
                size = desc[i]
                i += 2 + size
            continue
        size_code = prefix & 0x03
        size = (1, 2, 4)[size_code - 1] if size_code else 0
        # Item tag = prefix with the 2 size bits cleared. The canonical tag
        # constants (0x04 Usage Page, 0x74 Report Size, 0x80 Input, …) already
        # encode the type bits, so matching on `prefix & 0xFC` is correct —
        # masking the high nibble alone would drop the type bits and misfile
        # every global/local item.
        tag = prefix & 0xFC

        data = 0
        for b in range(size):
            data |= desc[i + b] << (8 * b)
        i += size

        if tag in (0x80, 0x90, 0xB0):        # Main: Input / Output / Feature
            rtype = {0x80: "input", 0x90: "output", 0xB0: "feature"}[tag]
            rid = g["report_id"]
            key = (rid, rtype)
            pos = bitpos.get(key, 0)
            count = g["report_count"]
            rsize = g["report_size"]
            # We deliberately do NOT skip Constant (bit 0) fields. Real UPS
            # firmwares — PowerWalker/Phoenixtec among them — mark live data
            # (RemainingCapacity, RunTimeToEmpty, PercentLoad) as Constant; NUT
            # reads them regardless. Genuine padding carries no Usage, so it
            # maps to usage 0 and the usage lookups ignore it — but it still
            # advances the bit cursor so following fields land at the right
            # offset.
            for idx in range(count):
                if usage_min is not None and usage_max is not None:
                    u = min(usage_min + idx, usage_max)
                elif usages:
                    u = usages[idx] if idx < len(usages) else usages[-1]
                else:
                    u = 0
                fields.append(HidField(
                    full_usage(u), rid, rtype, pos + idx * rsize, rsize,
                    g["logical_min"], g["logical_max"],
                    g["unit"], g["unit_exp"],
                ))
            bitpos[key] = pos + count * rsize
            usages = []
            usage_min = usage_max = None
        elif tag in (0xA0, 0xC0):            # Main: Collection / End Collection
            usages = []
            usage_min = usage_max = None

        elif tag == 0x04: g["usage_page"] = data           # Global
        elif tag == 0x14: g["logical_min"] = _signed(data, size * 8)
        elif tag == 0x24: g["logical_max"] = _signed(data, size * 8) if size else 0
        elif tag == 0x54: g["unit_exp"] = _unit_exp(data & 0xF)
        elif tag == 0x64: g["unit"] = data
        elif tag == 0x74: g["report_size"] = data
        elif tag == 0x84: g["report_id"] = data
        elif tag == 0x94: g["report_count"] = data
        elif tag == 0xA4: gstack.append(dict(g))           # Push
        elif tag == 0xB4:                                   # Pop
            if gstack:
                g = gstack.pop()

        elif tag == 0x08: usages.append(data)              # Local: Usage
        elif tag == 0x18: usage_min = data                 # Local: Usage Min
        elif tag == 0x28: usage_max = data                 # Local: Usage Max
        # Other items (designator/string indices, etc.) are irrelevant here.

    return fields


def _extract_bits(payload: bytes, bit_offset: int, bit_size: int) -> int:
    """Pull a little-endian bit field out of a report payload (HID packs
    LSB-first within the byte stream)."""
    value = 0
    for b in range(bit_size):
        byte_i = (bit_offset + b) // 8
        if byte_i >= len(payload):
            break
        bit_i = (bit_offset + b) % 8
        if payload[byte_i] & (1 << bit_i):
            value |= (1 << b)
    return value


# ── Adapter ───────────────────────────────────────────────────────────────────

class USBUPSAdapter(BaseAdapter):
    REQUIREMENTS = [
        {
            "service": "USB HID Power Device",
            "transport": "usb",
            "port": 0,
            "description": "UPS connected by USB to the host; the container must "
                           "have the USB device passed through (--device) and "
                           "permission to open its hidraw node.",
            "required": True,
        },
    ]

    def __init__(self, hostname: str, credentials: dict):
        super().__init__(hostname, credentials)
        creds = credentials or {}
        self.vid = self._parse_id(creds.get("usb_vid"), _DEFAULT_VID)
        self.pid = self._parse_id(creds.get("usb_pid"), _DEFAULT_PID)
        # When True, only the configured VID:PID is opened; when False (no IDs
        # set) we auto-detect the first device exposing the Power Device page.
        self._pinned = bool(creds.get("usb_vid") or creds.get("usb_pid"))
        self.nominal_watts = self._parse_id(creds.get("nominal_real_power"),
                                            _DEFAULT_NOMINAL_WATTS)
        # Low-battery thresholds for state derivation when the UPS doesn't set
        # the BelowRemainingCapacityLimit flag itself.
        self.low_charge_pct = self._parse_id(creds.get("low_charge_pct"), 20)
        self.low_runtime_sec = self._parse_id(creds.get("low_runtime_sec"), 300)
        # Per-poll read cache (one USB open per poll cycle; both cache keys reuse).
        self._reading: dict | None = None
        self._read_lock = asyncio.Lock()

    @staticmethod
    def _parse_id(raw, default):
        if raw is None or raw == "":
            return default
        try:
            # Accept "0x06da", "06da" (hex for VID/PID), or plain ints/decimals.
            if isinstance(raw, str) and (raw.lower().startswith("0x")):
                return int(raw, 16)
            return int(raw)
        except (ValueError, TypeError):
            return default

    def get_supported_cache_keys(self) -> list[str]:
        # `metrics` carries the numeric time-series the poller persists to the
        # history table; `status` is the latest snapshot for the cards/dashboard.
        return ["status", "metrics"]

    async def fetch(self, cache_key: str) -> Any:
        reading = await self._read_all()
        if cache_key == "status":  return self._status(reading)
        if cache_key == "metrics": return self._metrics(reading)
        raise ValueError(f"Unknown cache key: {cache_key!r}")

    async def execute_action(self, action: dict) -> dict:
        # No write actions in Phase 1. Battery test / beep toggle could map to
        # HID Output reports later (Test=0x00850058, AudibleAlarmControl), but
        # this unit reports instcmds unsupported, so we don't expose buttons.
        return {"error": f"Action {action.get('type')!r} not supported for USB UPS"}

    async def close(self) -> None:
        self._reading = None

    # ── USB read ──────────────────────────────────────────────────────────────

    async def _read_all(self) -> dict:
        """Open the UPS once, read every interesting usage, cache for the poll
        cycle. Runs the blocking hidapi calls in a thread."""
        async with self._read_lock:
            if self._reading is not None:
                return self._reading
            loop = asyncio.get_running_loop()
            self._reading = await loop.run_in_executor(None, self._read_all_sync)
            return self._reading

    def _open_device(self, hid):
        """Return an opened hid.device for the configured/auto-detected UPS, or
        raise with a clear message. Auto-detect picks the first enumerated
        device whose descriptor exposes the Power Device usage page."""
        dev = hid.device()
        if self._pinned:
            dev.open(self.vid, self.pid)
            return dev, (self.vid, self.pid)
        # Try the default identity first (cheap), then scan everything.
        candidates = [(self.vid, self.pid, None)]
        for info in hid.enumerate():
            candidates.append((info["vendor_id"], info["product_id"],
                               info.get("path")))
        last_exc = None
        for vid, pid, path in candidates:
            try:
                d = hid.device()
                if path:
                    d.open_path(path)
                else:
                    d.open(vid, pid)
            except Exception as exc:
                last_exc = exc
                continue
            try:
                desc = self._get_descriptor(d)
                if desc and any((f.usage >> 16) in (PAGE_POWER, PAGE_BATTERY)
                                for f in parse_report_descriptor(desc)):
                    return d, (vid, pid)
            except Exception as exc:
                last_exc = exc
            d.close()
        raise RuntimeError(
            "No USB HID Power Device found. Check the UPS is plugged in, passed "
            "through to the container, and not a megatec/serial UPS. "
            f"Last error: {last_exc}")

    @staticmethod
    def _get_descriptor(dev) -> bytes:
        """cython-hidapi >= 0.14 exposes get_report_descriptor(); normalise its
        return (list[int] or bytes) to bytes."""
        raw = dev.get_report_descriptor()
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw)
        return bytes(raw or [])

    def _read_all_sync(self) -> dict:
        try:
            import hid  # cython-hidapi; imported lazily so the app still boots
        except ImportError as exc:        # without libhidapi (e.g. on a dev box)
            raise RuntimeError(
                "hidapi not installed — `pip install hidapi` and ensure "
                "libhidapi is present (apt: libhidapi-libusb0).") from exc

        # Serialise the whole open→read→close against any other USB session
        # (poll vs refresh vs diagnostics) and retry a few times to ride out a
        # transient EBUSY on open OR a transient read error mid-cycle — hidraw
        # GET_REPORT calls occasionally fail and shouldn't surface as the
        # device "going offline". The retry covers BOTH open and read; an
        # earlier version only retried the open, so a read hiccup propagated
        # straight up as "read error".
        last_exc: Exception | None = None
        with _USB_LOCK:
            for attempt in range(4):
                dev = None
                try:
                    dev, (vid, pid) = self._open_device(hid)
                    return self._read_from_device(dev, vid, pid)
                except Exception as exc:
                    last_exc = exc
                    time.sleep(0.3)
                finally:
                    if dev is not None:
                        try:
                            dev.close()
                        except Exception:
                            pass
        raise last_exc or RuntimeError("USB UPS read failed")

    def _read_from_device(self, dev, vid, pid) -> dict:
        """Read every interesting usage from an already-open hid.device. Split
        out from _read_all_sync so diagnostics can reuse the same open handle
        (hidraw is exclusive on Linux — re-opening mid-call would fail)."""
        # Static descriptor → parse once per (vid,pid), then reuse.
        fields = _FIELDS_CACHE.get((vid, pid))
        if fields is None:
            fields = parse_report_descriptor(self._get_descriptor(dev))
            _FIELDS_CACHE[(vid, pid)] = fields
        # Map usage → preferred field (feature beats input beats output).
        by_usage: dict[int, HidField] = {}
        rank = {"feature": 0, "input": 1, "output": 2}
        for f in fields:
            cur = by_usage.get(f.usage)
            if cur is None or rank[f.report_type] < rank[cur.report_type]:
                by_usage[f.usage] = f

        # Precompute report byte lengths per (report_id, type).
        report_len: dict[tuple[int, str], int] = {}
        for f in fields:
            key = (f.report_id, f.report_type)
            end = (f.bit_offset + f.bit_size + 7) // 8
            report_len[key] = max(report_len.get(key, 0), end)

        cache: dict[tuple[int, str], bytes | None] = {}

        def read_payload(field: HidField) -> bytes | None:
            key = (field.report_id, field.report_type)
            if key in cache:
                return cache[key]
            length = report_len.get(key, 8) + 1   # +1 for the report-id byte
            payload = None
            try:
                if field.report_type == "feature":
                    raw = dev.get_feature_report(field.report_id, length)
                elif field.report_type == "input" and hasattr(dev, "get_input_report"):
                    raw = dev.get_input_report(field.report_id, length)
                else:
                    raw = None
                if raw:
                    # Numbered reports (report_id > 0) echo the id as raw[0];
                    # un-numbered reports (id 0) have no prefix byte, so don't
                    # strip one or we'd drop a real data byte and misalign every
                    # bit offset.
                    payload = bytes(raw[1:]) if field.report_id else bytes(raw)
            except Exception as exc:
                logger.debug("UPS read report %s failed: %s", key, exc)
            cache[key] = payload
            return payload

        def value(usage: int, physical: bool = False):
            f = by_usage.get(usage)
            if f is None:
                return None
            payload = read_payload(f)
            if payload is None:
                return None
            raw = _extract_bits(payload, f.bit_offset, f.bit_size)
            if f.logical_min < 0:
                raw = _signed(raw, f.bit_size)
            # Unit-exponent handling: only physical-unit usages (V/A/W/Hz/°C)
            # are scaled, and only by NEGATIVE exponents. Percentages and
            # seconds (PercentLoad, RemainingCapacity, RunTimeToEmpty) are
            # dimensionless / seconds per the PDC spec, so their raw logical
            # value IS the human value. PowerWalker/Phoenixtec firmwares emit
            # bogus POSITIVE exponents (observed: exp 7 on voltage → ×10^7), so
            # we clamp to <= 0 — a well-behaved UPS using exp -1 (raw 2300 →
            # 230.0 V) still scales correctly, while the bogus +7 is ignored.
            if physical and f.unit_exp < 0:
                return round(raw * (10 ** f.unit_exp), 3)
            return raw

        def flag(usage: int):
            v = value(usage)
            return None if v is None else bool(v)

        return {
            "vid": vid, "pid": pid,
            "load_pct":      value(U_PERCENT_LOAD),
            "active_power":  value(U_ACTIVE_POWER, physical=True),
            "config_active_power": value(U_CONFIG_ACTIVE_PW, physical=True),
            "charge_pct":    value(U_REMAINING_CAP),
            "runtime_sec":   value(U_RUNTIME_TO_EMPTY),
            "input_voltage": value(U_VOLTAGE, physical=True),
            "config_voltage": value(U_CONFIG_VOLTAGE, physical=True),
            "frequency":     value(U_FREQUENCY, physical=True),
            "temperature":   value(U_TEMPERATURE, physical=True),
            "ac_present":        flag(U_AC_PRESENT),
            "charging":          flag(U_CHARGING),
            "discharging":       flag(U_DISCHARGING),
            "below_cap_limit":   flag(U_BELOW_CAP_LIMIT),
            "need_replacement":  flag(U_NEED_REPLACEMENT),
            "shutdown_imminent": flag(U_SHUTDOWN_IMMINENT),
            "overload":          flag(U_OVERLOAD),
            "battery_present":   flag(U_BATTERY_PRESENT),
            "mfr":     dev_get_string(dev, "get_manufacturer_string"),
            "model":   dev_get_string(dev, "get_product_string"),
            "serial":  dev_get_string(dev, "get_serial_number_string"),
        }

    # ── Shaping ─────────────────────────────────────────────────────────────

    def _watts(self, r: dict) -> float | None:
        """Real power. Prefer the UPS's own live ActivePower; otherwise derive
        from load % × rated real power.

        The rating is the **configured** `nominal_real_power` (default 1320 W),
        NOT the descriptor's ConfigActivePower. Trusting the descriptor here
        produced 6.7 W instead of ~850 W on the VI-2200: its ConfigActivePower
        is absent and the nearby ConfigApparentPower (VA) reads as a tiny
        scaled value. An explicitly-set rating must always win; the descriptor
        value is only a last resort when nothing is configured."""
        if r.get("active_power") is not None:
            return round(float(r["active_power"]), 1)
        load = r.get("load_pct")
        if load is None:
            return None
        nominal = self.nominal_watts or r.get("config_active_power") or _DEFAULT_NOMINAL_WATTS
        return round(float(load) / 100.0 * float(nominal), 1)

    def _state(self, r: dict) -> tuple[str, str]:
        """Derive (state, human label). Robust to UPSs that don't set every
        flag: AC-present false OR discharging true ⇒ on battery; low battery is
        the explicit flag OR a charge/runtime threshold."""
        ac = r.get("ac_present")
        discharging = r.get("discharging")
        on_battery = (ac is False) or (discharging is True)
        charge = r.get("charge_pct")
        runtime = r.get("runtime_sec")
        low = (r.get("below_cap_limit") is True
               or r.get("shutdown_imminent") is True
               or (charge is not None and charge <= self.low_charge_pct)
               or (runtime is not None and runtime <= self.low_runtime_sec))
        if on_battery and low:
            return "low_battery", "On Battery — LOW"
        if on_battery:
            return "on_battery", "On Battery"
        if r.get("charging"):
            return "online", "Online — Charging"
        return "online", "Online"

    @staticmethod
    def _runtime_text(seconds) -> str | None:
        if seconds is None:
            return None
        s = int(seconds)
        return f"{s // 60}m {s % 60:02d}s"

    def _status(self, r: dict) -> dict:
        state, label = self._state(r)
        return {
            "online": True,           # readable ⇒ reachable (dashboard dot)
            "state": state,
            "state_label": label,
            "mfr": r.get("mfr"),
            "model": r.get("model"),
            "serial": r.get("serial"),
            "load_pct": r.get("load_pct"),
            "watts": self._watts(r),
            "charge_pct": r.get("charge_pct"),
            "runtime_sec": r.get("runtime_sec"),
            "runtime_text": self._runtime_text(r.get("runtime_sec")),
            "input_voltage": r.get("input_voltage"),
            "nominal_voltage": r.get("config_voltage"),   # ConfigVoltage = rated mains, not battery
            "frequency": r.get("frequency"),
            "temperature": r.get("temperature"),
            "flags": {
                "ac_present": r.get("ac_present"),
                "charging": r.get("charging"),
                "discharging": r.get("discharging"),
                "low_battery": r.get("below_cap_limit"),
                "need_replacement": r.get("need_replacement"),
                "overload": r.get("overload"),
                "shutdown_imminent": r.get("shutdown_imminent"),
            },
            "usb": f"{r.get('vid', 0):04x}:{r.get('pid', 0):04x}",
            "source": "usb-hid",
        }

    def _metrics(self, r: dict) -> dict:
        """Numeric series the poller writes to the time-series table. Only
        include values we actually read (None ⇒ omitted so we don't graph
        zeros for unsupported usages)."""
        out = {
            "load_pct": r.get("load_pct"),
            "watts": self._watts(r),
            "charge_pct": r.get("charge_pct"),
            "runtime_sec": r.get("runtime_sec"),
            "input_voltage": r.get("input_voltage"),
        }
        return {k: v for k, v in out.items() if isinstance(v, (int, float))}

    # ── Preflight (USB open test instead of a network probe) ──────────────────

    async def preflight(self) -> list[dict]:
        req = self.requirements()[0]
        try:
            reading = await self._read_all()
        except Exception as exc:
            return [{**req, "ok": False,
                     "detail": f"{type(exc).__name__}: {exc}"}]
        finally:
            self._reading = None
        bits = []
        if reading.get("charge_pct") is not None:
            bits.append(f"charge {reading['charge_pct']}%")
        if reading.get("load_pct") is not None:
            bits.append(f"load {reading['load_pct']}%")
        if reading.get("runtime_sec") is not None:
            bits.append(f"runtime {int(reading['runtime_sec'])}s")
        detail = ("UPS responded over USB HID ("
                  + (", ".join(bits) if bits else "no standard usages decoded — "
                     "may be a megatec/serial UPS")
                  + ")")
        ok = bool(bits)
        return [{**req, "ok": ok, "detail": detail}]


    # ── Diagnostics ───────────────────────────────────────────────────────────

    async def diagnostics(self) -> dict:
        """Dump the raw HID report descriptor + every decoded usage and its
        current value. The web UI / a curious operator uses this to confirm a
        *new* UPS model is covered (or see exactly which usages are missing)
        without reading code — the USB analogue of the snmp-walk endpoint."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._diagnostics_sync)

    def _diagnostics_sync(self) -> dict:
        import hid
        # Same process-wide lock as _read_all_sync — a diagnostics call must not
        # open the device while a poll holds it (that EBUSY was what made the
        # device "disappear" mid-test).
        with _USB_LOCK:
            return self._diagnostics_locked(hid)

    def _diagnostics_locked(self, hid) -> dict:
        dev, (vid, pid) = self._open_device(hid)
        try:
            desc = self._get_descriptor(dev)
            fields = parse_report_descriptor(desc)
            usages = []
            for f in sorted(fields, key=lambda x: (x.usage, x.report_id)):
                usages.append({
                    "usage": f"0x{f.usage:08x}",
                    "page": f"0x{f.usage >> 16:02x}",
                    "report_id": f.report_id,
                    "report_type": f.report_type,
                    "bit_offset": f.bit_offset,
                    "bit_size": f.bit_size,
                    "logical_min": f.logical_min,
                    "logical_max": f.logical_max,
                    "unit_exp": f.unit_exp,
                })
            return {
                "usb": f"{vid:04x}:{pid:04x}",
                "descriptor_hex": desc.hex(),
                "descriptor_len": len(desc),
                "field_count": len(fields),
                "fields": usages,
                "reading": self._read_from_device(dev, vid, pid),
            }
        finally:
            try:
                dev.close()
            except Exception:
                pass


def dev_get_string(dev, method_name: str):
    """Call a hidapi string accessor defensively — some backends raise instead
    of returning '' when the descriptor lacks the string."""
    try:
        s = getattr(dev, method_name)()
        return s.strip() if s else None
    except Exception:
        return None
