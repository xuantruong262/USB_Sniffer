"""
Pico USB Sniffer - export a capture to Wireshark (.pcapng).

Every captured USB packet is written as one frame using the USB 2.0 link
layer encapsulations (Wireshark dissector "usbll", Wireshark >= 3.6):
    LINKTYPE_USB_2_0_LOW_SPEED  = 293
    LINKTYPE_USB_2_0_FULL_SPEED = 294
Frame data = PID byte .. CRC (the SYNC byte is not included).

Wireshark rebuilds transactions / control transfers from these packets and
decodes descriptors, HID, mass storage... like for a usbmon capture.

Notes
  * timestamps are absolute (host clock at capture start + device time), 1 us
  * packets with decode errors are written as received and get a comment
  * bus reset / dropped packets / capture start-stop are added as comments
    on the next frame
  * SOF / IN-NAK folded by the firmware do not exist as packets and are not
    written (the summary is put in a comment); capture with Fold off to get
    every packet in Wireshark
"""
from __future__ import annotations

import struct

import capture as C
import protocol as P

LINKTYPE_USB_2_0_LOW_SPEED = 293
LINKTYPE_USB_2_0_FULL_SPEED = 294


def _opt(code: int, value: bytes) -> bytes:
    pad = (-len(value)) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\0" * pad


def _opts(*items) -> bytes:
    body = b"".join(items)
    return body + struct.pack("<HH", 0, 0) if body else b""


def _block(btype: int, body: bytes) -> bytes:
    body += b"\0" * ((-len(body)) % 4)
    n = len(body) + 12
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


def shb(app: str) -> bytes:
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    body += _opts(_opt(4, app.encode()))  # shb_userappl
    return _block(0x0A0D0D0A, body)


def idb(linktype: int, name: str, desc: str = "", snaplen: int = 0) -> bytes:
    body = struct.pack("<HHI", linktype, 0, snaplen)
    # if_name, if_description, if_tsresol = 10^-6
    body += _opts(_opt(2, name.encode()), *([_opt(3, desc.encode())] if desc else []), _opt(9, b"\x06"))
    return _block(1, body)


def epb(iface: int, ts_us: int, data: bytes, comment: str | None = None) -> bytes:
    ts_us &= 0xFFFFFFFFFFFFFFFF
    body = struct.pack("<IIIII", iface, ts_us >> 32, ts_us & 0xFFFFFFFF, len(data), len(data))
    body += data + b"\0" * ((-len(data)) % 4)
    if comment:
        body += _opts(_opt(1, comment.encode("utf-8")[:60000]))
    return _block(6, body)


def _iter_file(path, chunk=4 << 20):
    """(offset, type, payload) for every record of a capture file"""
    with open(path, "rb") as f:
        f.seek(C.HEADER_LEN)
        base = C.HEADER_LEN
        buf = b""
        while True:
            data = f.read(chunk)
            if not data:
                break
            buf += data
            p = 0
            n = len(buf)
            while n - p >= 4:
                if buf[p] != P.MAGIC:
                    p += 1
                    continue
                ln = buf[p + 2] | (buf[p + 3] << 8)
                if p + 4 + ln > n:
                    break
                yield base + p, buf[p + 1], buf[p + 4:p + 4 + ln]
                p += 4 + ln
            base += p
            buf = buf[p:]


def export_pcapng(store: C.CaptureStore, path: str, progress=None) -> dict:
    """write the whole capture to a pcapng file. progress(done, total) -> False cancels.
    returns statistics"""
    import os
    with store.lock:
        if store._wf:
            store._wf.flush()
    total = os.path.getsize(store.path)
    host0 = store.session_host0 or 0
    stats = {"packets": 0, "errors": 0, "folded_sof": 0, "folded_nak": 0, "comments": 0, "cancelled": False}
    ifaces = {}  # fs(bool) -> interface id
    pending = []
    out = open(path, "wb", buffering=1 << 20)
    try:
        out.write(shb("Pico USB Sniffer"))
        seg = None
        seg_i = -1
        k = 0
        for off, t, pl in _iter_file(store.path):
            k += 1
            if progress and k % 20000 == 0 and not progress(off, total):
                stats["cancelled"] = True
                break
            # current time segment (device clock -> display clock)
            while seg_i + 1 < len(store.seg_off) and store.seg_off[seg_i + 1] <= off:
                seg_i += 1
                seg = (store.seg_dev0[seg_i], store.seg_base[seg_i], store.seg_fs[seg_i])
            if t == P.REC_PACKET:
                if seg is None:
                    continue
                ts, nbits, flags = struct.unpack_from("<QHH", pl, 0)
                data = bytes(pl[13:])  # drop the SYNC byte
                if not data:
                    continue
                fs = seg[2]
                if fs not in ifaces:
                    ifaces[fs] = len(ifaces)
                    out.write(idb(LINKTYPE_USB_2_0_FULL_SPEED if fs else LINKTYPE_USB_2_0_LOW_SPEED,
                                  "Pico USB Sniffer " + ("Full Speed" if fs else "Low Speed")))
                notes = pending
                pending = []
                if flags:
                    stats["errors"] += 1
                    notes.append(f"sniffer: packet error {P.flags_str(flags)} ({nbits} bits)")
                out.write(epb(ifaces[fs], host0 + ts - seg[0] + seg[1], data, "; ".join(notes) or None))
                stats["packets"] += 1
                stats["comments"] += bool(notes)
                continue
            if t == P.REC_FOLD:
                sof = struct.unpack_from("<I", pl, 16)[0]
                n = pl[32]
                naks = struct.unpack_from("<I", pl, 28)[0] + sum(
                    struct.unpack_from("<I", pl, 33 + 6 * i + 2)[0] for i in range(n))
                stats["folded_sof"] += sof
                stats["folded_nak"] += naks
                continue
            if t == P.REC_RESET:
                pending.append("Bus Reset")
            elif t == P.REC_DROP:
                _ts, tot, delta = struct.unpack_from("<QII", pl, 0)
                pending.append(f"sniffer: {delta} packets lost here (device buffer overflow)")
            elif t == P.REC_SYNCERR:
                pending.append("sniffer: sync error (wrong speed?)")
            elif t == P.REC_START:
                pending.append("capture started (" + ("Full" if pl[8] else "Low") + " Speed)")
            elif t == P.REC_STOP:
                pending.append("capture stopped")
            elif t == P.REC_HOST_EVENT and pl[8] in (P.HE_DISCONNECT, P.HE_RECONNECT):
                pending.append("sniffer " + bytes(pl[9:]).decode("utf-8", "replace"))
    finally:
        out.close()
    return stats
