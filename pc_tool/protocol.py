"""
Pico USB Sniffer - streaming protocol definitions and USB decoding helpers.

Keep in sync with firmware/protocol.h
"""
from __future__ import annotations

import struct

MAGIC = 0xA5
MAGIC_B = bytes([MAGIC])

REC_INFO = 0x01
REC_START = 0x02
REC_STOP = 0x03
REC_PACKET = 0x10
REC_RESET = 0x11
REC_KEEPALIVE = 0x12
REC_SYNCERR = 0x13
REC_FOLD = 0x20
REC_STATUS = 0x30
REC_DROP = 0x31
REC_TEXT = 0x40
REC_HOST_EVENT = 0x41

# (min_len, max_len) of the payload, used for validation / resync
LEN_LIMITS = {
    REC_INFO: (14, 256),
    REC_START: (13, 32),
    REC_STOP: (9, 32),
    REC_PACKET: (12, 12 + 1100),
    REC_RESET: (8, 8),
    REC_KEEPALIVE: (8, 8),
    REC_SYNCERR: (12, 12),
    REC_FOLD: (33, 33 + 6 * 8),
    REC_STATUS: (40, 64),
    REC_DROP: (16, 16),
    REC_TEXT: (0, 1024),
    REC_HOST_EVENT: (9, 1024),
}
LIMIT_MIN = [None] * 256
LIMIT_MAX = [None] * 256
for _t, (_a, _b) in LEN_LIMITS.items():
    LIMIT_MIN[_t] = _a
    LIMIT_MAX[_t] = _b

# packet flags
PKT_ERR_STUFF = 0x0001
PKT_ERR_CRC = 0x0002
PKT_ERR_PID = 0x0004
PKT_ERR_SYNC = 0x0008
PKT_ERR_NBIT = 0x0010
PKT_ERR_SIZE = 0x0020
PKT_TRUNCATED = 0x0040

FLAG_NAMES = [
    (PKT_ERR_STUFF, "STUFF"),
    (PKT_ERR_CRC, "CRC"),
    (PKT_ERR_PID, "PID"),
    (PKT_ERR_SYNC, "SYNC"),
    (PKT_ERR_NBIT, "NBIT"),
    (PKT_ERR_SIZE, "SIZE"),
    (PKT_TRUNCATED, "TRUNC"),
]

# host event codes (REC_HOST_EVENT: u64 host_time_us, u8 code, text)
HE_SESSION = 1
HE_SEGMENT = 2  # written right before a start command is sent
HE_DISCONNECT = 3
HE_RECONNECT = 4
HE_USER_STOP = 5
HE_NOTE = 6

# USB PIDs
PID_OUT, PID_IN, PID_SOF, PID_SETUP = 1, 9, 5, 13
PID_DATA0, PID_DATA1, PID_DATA2, PID_MDATA = 3, 11, 7, 15
PID_ACK, PID_NAK, PID_STALL, PID_NYET = 2, 10, 14, 6
PID_PRE, PID_SPLIT, PID_PING, PID_RSVD = 12, 8, 4, 0

PID_NAMES = {
    PID_OUT: "OUT", PID_IN: "IN", PID_SOF: "SOF", PID_SETUP: "SETUP",
    PID_DATA0: "DATA0", PID_DATA1: "DATA1", PID_DATA2: "DATA2", PID_MDATA: "MDATA",
    PID_ACK: "ACK", PID_NAK: "NAK", PID_STALL: "STALL", PID_NYET: "NYET",
    PID_PRE: "PRE/ERR", PID_SPLIT: "SPLIT", PID_PING: "PING", PID_RSVD: "RESERVED",
}
TOKEN_PIDS = frozenset((PID_OUT, PID_IN, PID_SETUP, PID_PING))
DATA_PIDS = frozenset((PID_DATA0, PID_DATA1, PID_DATA2, PID_MDATA))
HS_PIDS = frozenset((PID_ACK, PID_NAK, PID_STALL, PID_NYET))

# lookup tables indexed by PID for the hot path
IS_TOKEN = [p in TOKEN_PIDS for p in range(16)]
IS_DATA = [p in DATA_PIDS for p in range(16)]
IS_HS = [p in HS_PIDS for p in range(16)]


def build_record(rtype: int, payload: bytes) -> bytes:
    return struct.pack("<BBH", MAGIC, rtype, len(payload)) + payload


def flags_str(flags: int) -> str:
    return ",".join(name for bit, name in FLAG_NAMES if flags & bit)


# ---------------------------------------------------------------------------
# CRC helpers (used by the demo generator)
# ---------------------------------------------------------------------------
def crc5_usb(value: int, nbits: int = 11) -> int:
    crc = 0x1F
    for i in range(nbits):
        bit = (value >> i) & 1
        if ((crc >> 4) & 1) ^ bit:
            crc = ((crc << 1) ^ 0x05) & 0x1F
        else:
            crc = (crc << 1) & 0x1F
    crc ^= 0x1F
    # transmitted MSB first -> reverse 5 bits for LSB-first packing
    rev = 0
    for i in range(5):
        if crc & (1 << i):
            rev |= 1 << (4 - i)
    return rev


def crc16_usb(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc ^ 0xFFFF


def make_token(pid: int, addr: int, ep: int, fs: bool = True) -> bytes:
    v = (addr & 0x7F) | ((ep & 0xF) << 7)
    v |= crc5_usb(v) << 11
    return bytes([0x80 if fs else 0x81, pid | ((~pid & 0xF) << 4), v & 0xFF, v >> 8])


def make_sof(frame: int, fs: bool = True) -> bytes:
    v = frame & 0x7FF
    v |= crc5_usb(v) << 11
    return bytes([0x80 if fs else 0x81, PID_SOF | ((~PID_SOF & 0xF) << 4), v & 0xFF, v >> 8])


def make_data(pid: int, payload: bytes, fs: bool = True) -> bytes:
    crc = crc16_usb(payload)
    return bytes([0x80 if fs else 0x81, pid | ((~pid & 0xF) << 4)]) + payload + bytes([crc & 0xFF, crc >> 8])


def make_hs(pid: int, fs: bool = True) -> bytes:
    return bytes([0x80 if fs else 0x81, pid | ((~pid & 0xF) << 4)])


def packet_record(ts: int, data: bytes, flags: int = 0) -> bytes:
    nbits = len(data) * 8 + len(data) // 6 + 3
    return build_record(REC_PACKET, struct.pack("<QHH", ts, nbits, flags) + data)


# ---------------------------------------------------------------------------
# Formatting / decoding helpers
# ---------------------------------------------------------------------------
def fmt_time(us: int) -> str:
    """Data Center style: m:ss.mmm.uuu (h:mm:ss.mmm.uuu above one hour)"""
    neg = us < 0
    if neg:
        us = -us
    s, u = divmod(us, 1_000_000)
    ms, u = divmod(u, 1000)
    m, s = divmod(s, 60)
    if m >= 60:
        h, m = divmod(m, 60)
        out = f"{h}:{m:02d}:{s:02d}.{ms:03d}.{u:03d}"
    else:
        out = f"{m}:{s:02d}.{ms:03d}.{u:03d}"
    return "-" + out if neg else out


class DurStr(str):
    """formatted duration that also keeps the exact value (for the CSV export)"""
    us = None


def fmt_dur(us: float) -> str:
    if us < 1000:
        s = f"{us:.2f} us" if us < 100 else f"{us:.0f} us"
    elif us < 1_000_000:
        s = f"{us / 1000:.3f} ms"
    else:
        s = f"{us / 1_000_000:.3f} s"
    s = DurStr(s)
    s.us = us
    return s


def hexs(b: bytes, limit: int = 64) -> str:
    if len(b) > limit:
        return b[:limit].hex(" ").upper() + " ..."
    return b.hex(" ").upper()


def fmt_len(n: int) -> str:
    return f"{n} B"


def hexdump8(b: bytes) -> str:
    """Data Center style dump: 8 bytes per line, offset / hex / ASCII columns."""
    head = "Offset  " + " ".join(f"{i:2d}" for i in range(8)) + "   ASCII"
    lines = [head]
    for i in range(0, len(b), 8):
        chunk = b[i:i + 8]
        hx = chunk.hex(" ").upper()
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append(f"0x{i:04X}  {hx:<23}   {asc}")
    return "\n".join(lines)


def hexdump(b: bytes, base: int = 0) -> str:
    lines = []
    for i in range(0, len(b), 16):
        chunk = b[i:i + 16]
        hx = chunk.hex(" ").upper()
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append(f"{base + i:04X}:  {hx:<47}  {asc}")
    return "\n".join(lines)


def token_fields(data: bytes):
    """returns (addr, ep) of a token packet (SYNC, PID, b0, b1)"""
    v = data[2] | (data[3] << 8)
    return v & 0x7F, (v >> 7) & 0xF


STD_REQUESTS = {
    0x00: "GET_STATUS", 0x01: "CLEAR_FEATURE", 0x03: "SET_FEATURE", 0x05: "SET_ADDRESS",
    0x06: "GET_DESCRIPTOR", 0x07: "SET_DESCRIPTOR", 0x08: "GET_CONFIGURATION",
    0x09: "SET_CONFIGURATION", 0x0A: "GET_INTERFACE", 0x0B: "SET_INTERFACE", 0x0C: "SYNCH_FRAME",
}
DESC_TYPES = {
    1: "Device", 2: "Configuration", 3: "String", 4: "Interface", 5: "Endpoint",
    6: "Device Qualifier", 7: "Other Speed", 8: "Interface Power", 0x0B: "IAD", 0x0F: "BOS",
    0x21: "HID", 0x22: "HID Report", 0x23: "HID Physical", 0x29: "Hub",
}
HID_REQUESTS = {0x01: "GET_REPORT", 0x02: "GET_IDLE", 0x03: "GET_PROTOCOL",
                0x09: "SET_REPORT", 0x0A: "SET_IDLE", 0x0B: "SET_PROTOCOL"}
CDC_REQUESTS = {0x20: "SET_LINE_CODING", 0x21: "GET_LINE_CODING", 0x22: "SET_CONTROL_LINE_STATE",
                0x23: "SEND_BREAK"}
RECIPIENTS = {0: "Device", 1: "Interface", 2: "Endpoint", 3: "Other"}
REQ_TYPES = {0: "Standard", 1: "Class", 2: "Vendor", 3: "Reserved"}


def decode_setup(p: bytes) -> str:
    """p = 8 byte setup payload"""
    if len(p) < 8:
        return "SETUP (short)"
    bm, breq = p[0], p[1]
    wval = p[2] | (p[3] << 8)
    widx = p[4] | (p[5] << 8)
    wlen = p[6] | (p[7] << 8)
    direction = "IN" if bm & 0x80 else "OUT"
    rtype = (bm >> 5) & 3
    recip = bm & 0x1F
    if rtype == 0:
        name = STD_REQUESTS.get(breq, f"Request 0x{breq:02X}")
        if breq == 0x06 or breq == 0x07:
            dt = DESC_TYPES.get(wval >> 8, f"0x{wval >> 8:02X}")
            idx = wval & 0xFF
            extra = f" {dt}" + (f" #{idx}" if idx or (wval >> 8) == 3 else "")
            if (wval >> 8) == 3 and idx:
                extra += f" lang=0x{widx:04X}"
            return f"{name}{extra} len={wlen}"
        if breq == 0x05:
            return f"SET_ADDRESS addr={wval}"
        if breq == 0x09:
            return f"SET_CONFIGURATION cfg={wval}"
        if breq == 0x0B:
            return f"SET_INTERFACE itf={widx} alt={wval}"
        return f"{name} {RECIPIENTS.get(recip, '?')} wValue=0x{wval:04X} wIndex=0x{widx:04X} len={wlen}"
    if rtype == 1:
        if breq in HID_REQUESTS and recip == 1:
            n = HID_REQUESTS[breq]
        elif breq in CDC_REQUESTS:
            n = CDC_REQUESTS[breq]
        else:
            n = f"Class req 0x{breq:02X}"
        return f"{n} ({RECIPIENTS.get(recip, '?')} {direction}) wValue=0x{wval:04X} wIndex=0x{widx:04X} len={wlen}"
    return (f"{REQ_TYPES[rtype]} req 0x{breq:02X} ({RECIPIENTS.get(recip, '?')} {direction}) "
            f"wValue=0x{wval:04X} wIndex=0x{widx:04X} len={wlen}")


def setup_details(p: bytes) -> str:
    if len(p) < 8:
        return ""
    bm = p[0]
    return (f"bmRequestType=0x{bm:02X} ({'Device->Host' if bm & 0x80 else 'Host->Device'}, "
            f"{REQ_TYPES[(bm >> 5) & 3]}, {RECIPIENTS.get(bm & 0x1F, 'Reserved')})\n"
            f"bRequest=0x{p[1]:02X}\nwValue=0x{p[2] | p[3] << 8:04X}\n"
            f"wIndex=0x{p[4] | p[5] << 8:04X}\nwLength={p[6] | p[7] << 8}")
