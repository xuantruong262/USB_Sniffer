"""
Pico USB Sniffer - export a capture as USBPcap transfers (.pcapng, LINKTYPE_USBPCAP 249),
the layout Wireshark records on Windows. Filters, columns and scripts written for such
files (usb.src == "1.14.1", usbhid.data, usb.urb_type ...) work unchanged.

Every transfer becomes two frames, as in a USBPcap file:
  submit    host -> device   OUT data / SETUP packet
  complete  device -> host   IN data / status

What is different from a capture made on the PC, because the source is the bus:
  * submit = first token of the transfer that went through, complete = its last packet
    (on a PC: the times the driver queued / finished the request)
  * transfers that are NAKed all the time never complete, so they are not written;
    SOF, NAK and packets with errors have no USBPcap equivalent
    (export_pcap.py writes every packet)
  * IRP ids are a running number, bus id is 1
  * on interrupt endpoints and unknown bulk endpoints one transaction = one transfer

Wireshark needs the descriptors to dissect HID (usbhid.data). If the enumeration is not in
the capture they are added at the start, as USBPcap does, marked with a packet comment:
from a reference file if exactly one device in it has the endpoints seen on the bus,
else generic HID descriptors with VID / PID 0000.
"""
from __future__ import annotations

import heapq
import os
import struct

import capture as C
import protocol as P
import usbdecode as U
from export_pcap import epb, idb, shb

LINKTYPE_USBPCAP = 249
BUS = 1
ISO, INTERRUPT, CONTROL, BULK = range(4)  # USBPcap transfer types
DESC_TYPE = (CONTROL, ISO, BULK, INTERRUPT)  # bmAttributes of an endpoint descriptor -> USBPcap
ST_OK = 0
ST_STALL = 0xC0000004            # USBD_STATUS_STALL_PID
FN_CONTROL = 0x0008
FN_BULK_INT = 0x0009
REF_READ = 4 << 20               # descriptors are in the first frames of a USBPcap file

_STD_FN = {  # (bRequest, recipient) -> URB_FUNCTION_*
    (0x00, 0): 0x13, (0x00, 1): 0x14, (0x00, 2): 0x15, (0x01, 0): 0x10, (0x01, 1): 0x11, (0x01, 2): 0x12,
    (0x03, 0): 0x0D, (0x03, 1): 0x0E, (0x03, 2): 0x0F, (0x06, 0): 0x0B, (0x06, 1): 0x28, (0x06, 2): 0x24,
    (0x07, 0): 0x0C, (0x07, 1): 0x29, (0x07, 2): 0x25, (0x08, 0): 0x26, (0x09, 0): 0x00, (0x0A, 1): 0x27,
    (0x0B, 1): 0x01,
}
_CLASS_FN = (0x1A, 0x1B, 0x1C, 0x1F)
_VENDOR_FN = (0x17, 0x18, 0x19, 0x20)


def urb_function(setup: bytes) -> int:
    typ, recip = (setup[0] >> 5) & 3, setup[0] & 0x1F
    if typ == 0:
        return _STD_FN.get((setup[1], recip), FN_CONTROL)
    if typ == 1 or typ == 2:
        # the class / vendor "device" function is also what Windows reports for other recipients > 3
        return (_CLASS_FN if typ == 1 else _VENDOR_FN)[min(recip, 3)]
    return FN_CONTROL


def frame(irp, status, function, complete, dev, ep, transfer, data=b"", stage=None) -> bytes:
    hl = 27 if stage is None else 28
    b = struct.pack("<HQIHBHHBBI", hl, irp, status, function, int(complete), BUS, dev, ep, transfer, len(data))
    return b + (b"" if stage is None else bytes([stage])) + data


# ---------------------------------------------------------------------------
# descriptors
# ---------------------------------------------------------------------------
def parse_config(cfg: bytes):
    """-> ({endpoint address: transfer type}, {interface classes})"""
    eps, classes = {}, set()
    p = 0
    while p + 2 <= len(cfg) and cfg[p] >= 2:
        d = cfg[p:p + cfg[p]]
        if d[1] == 4 and len(d) >= 9:
            classes.add(d[5])
        elif d[1] == 5 and len(d) >= 7:
            eps[d[2]] = DESC_TYPE[d[3] & 3]
        p += cfg[p]
    return eps, classes


def is_complete(dev, cfg) -> bool:
    return bool(dev and len(dev) >= 18 and cfg and len(cfg) >= 9 and len(cfg) >= U.u16(cfg, 2))


def generic_hid(eps, interface, low_speed):
    """minimal HID device / configuration descriptors with the endpoints seen on the bus"""
    mps = 8 if low_speed else 64
    dev = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0, 0, 0, mps, 0, 0, 0, 0, 0, 0, 1)
    body = bytes([9, 4, interface & 0xFF, 0, len(eps), 3, 0, 0, 0])
    body += bytes([9, 0x21, 0x11, 0x01, 0, 1, 0x22, 0, 0])
    for e in sorted(eps, key=lambda a: (not a & 0x80, a)):
        body += struct.pack("<BBBBHB", 7, 5, e, DESC_TYPE.index(INTERRUPT), mps, 1)
    return dev, struct.pack("<BBHBBBBB", 9, 2, 9 + len(body), 1, 1, 0, 0x80, 50) + body


def load_reference(path):
    """[(label, device descriptor, configuration descriptor)] of a USBPcap .pcapng or a .pusb file"""
    name = os.path.basename(path)
    found = {}
    if path.lower().endswith(".pusb"):
        st = C.CaptureStore(path, create=False)
        try:
            st.load()
            found = {a: (d["device"], d["config"]) for a, d in st.devices.items()}
        finally:
            st.close()
    else:
        with open(path, "rb") as f:
            blob = f.read(REF_READ)
        if blob[:4] != b"\x0a\x0d\x0d\x0a" or blob[8:12] != b"\x4d\x3c\x2b\x1a":
            raise ValueError(f"{name} is not a pcapng file")
        links = []
        p = 0
        while p + 12 <= len(blob):
            t, n = struct.unpack_from("<II", blob, p)
            if n < 12 or n % 4 or p + n > len(blob):
                break
            if t == 1:
                links.append(struct.unpack_from("<H", blob, p + 8)[0])
            elif t == 6:
                i, _h, _l, cap = struct.unpack_from("<IIII", blob, p + 8)
                d = blob[p + 28:p + 28 + cap]
                if i < len(links) and links[i] == LINKTYPE_USBPCAP and len(d) > 30 and d[22] == CONTROL and d[16] & 1:
                    dev, data = U.u16(d, 19), d[U.u16(d, 0):]
                    old = found.get(dev, (None, None))
                    if len(data) >= 18 and data[0] == 18 and data[1] == 1:
                        found[dev] = (data[:18], old[1])
                    elif len(data) >= 9 and data[0] == 9 and data[1] == 2 and len(data) >= U.u16(data, 2):
                        found[dev] = (old[0], data[:U.u16(data, 2)])
            p += n
        if LINKTYPE_USBPCAP not in links:
            raise ValueError(f"{name} is not a USBPcap capture")
    out = [(f"{U.u16(d, 8):04X}:{U.u16(d, 10):04X} from {name}", bytes(d), bytes(c))
           for d, c in found.values() if is_complete(d, c)]
    if not out:
        raise ValueError(f"no device with complete descriptors in {name}")
    return out


def bus_endpoints(store):
    """{device: {endpoint addresses}} (without endpoint 0) and the devices with mass storage traffic"""
    out, msc = {}, set()
    for i in range(store.row_count()):
        k, dev = store.r_kind[i], store.r_dev[i]
        if dev == C.NONE:
            continue
        if k == C.K_CTRL:
            out.setdefault(dev, set())
        elif k == C.K_TXN:
            e, fl = store.r_ep[i], store.r_flags[i]
            if e and not fl & C.RF_ERROR:
                out.setdefault(dev, set()).add(e | (0x80 if fl & C.RF_IN else 0))
        elif k == C.K_MSC:
            msc.add(dev)
            out.setdefault(dev, set())
    return out, msc


def missing_descriptors(store):
    """addresses whose descriptors are not in the capture and that would be added"""
    eps, msc = bus_endpoints(store)
    return sorted(a for a, e in eps.items() if e and a not in msc and not _learned(store, a))


def _learned(store, a):
    d = store.devices.get(a)
    return (d["device"], d["config"]) if d and is_complete(d["device"], d["config"]) else None


def _interface_of(store, dev):
    for i in range(store.row_count()):
        if store.r_kind[i] == C.K_CTRL and store.r_dev[i] == dev:
            txns = store._assemble(i)[0]
            p = txns[0].payload if txns else None
            if p and len(p) >= 8 and p[0] & 0x7F == 0x21:  # class request to an interface
                return p[4]
    return 0


# ---------------------------------------------------------------------------
class _Writer:
    def __init__(self, store, out, stats):
        self.st, self.out, self.stats = store, out, stats
        self.host0 = store.session_host0 or 0
        self.heap = []
        self.seq = 0
        self.irp = 0
        self.notes = []       # comments for the next transfer
        self.lost = 0         # undecodable packets since the last transfer
        self.ep_type = {}

    def add(self, ts, data, comment=None):
        heapq.heappush(self.heap, (round(ts), self.seq, data, comment))
        self.seq += 1

    def flush(self, upto=None):
        """write what can no longer be preceded by another frame"""
        h = self.heap
        while h and (upto is None or h[0][0] <= upto):
            ts, _s, data, comment = heapq.heappop(h)
            self.out.write(epb(0, self.host0 + ts, data, comment))
            self.stats["frames"] += 1
            self.stats["comments"] += comment is not None

    def _comment(self):
        n = self.notes
        if self.lost:
            n.append(f"sniffer: {self.lost} packet(s) with errors before this transfer")
        self.notes, self.lost = [], 0
        return "; ".join(n) or None

    def transfer(self, t0, t1, dev, ep, data, status=ST_OK, kind=None):
        """bulk / interrupt transfer; ep is the endpoint address"""
        if kind is None:
            kind = self.ep_type.get((dev, ep), INTERRUPT)
        self.irp += 1
        is_in = ep & 0x80
        self.add(t0, frame(self.irp, ST_OK, FN_BULK_INT, False, dev, ep, kind, b"" if is_in else data),
                 self._comment())
        self.add(max(t1, t0), frame(self.irp, status, FN_BULK_INT, True, dev, ep, kind, data if is_in else b""))
        self.stats["transfers"] += 1

    def control(self, t0, t1, dev, setup, data, status=ST_OK, irp=None, comment=None):
        """t1 None: never completed"""
        if irp is None:
            self.irp += 1
            irp = self.irp
        is_in = setup[0] & 0x80
        ep = 0x80 if is_in else 0
        fn = urb_function(setup)
        self.add(t0, frame(irp, ST_OK, fn, False, dev, ep, CONTROL, setup + (b"" if is_in else data), 0),
                 comment or self._comment())
        if t1 is not None:
            self.add(max(t1, t0), frame(irp, status, 0 if fn == 0 else FN_CONTROL, True, dev, ep, CONTROL,
                                        data if is_in else b"", 3), comment)
        self.stats["transfers"] += 1

    def descriptors(self, ts, dev, dd, cfg, comment):
        for setup, data in ((struct.pack("<BBHHH", 0x80, 6, 0x0100, 0, 18), dd),
                            (struct.pack("<BBHHH", 0x80, 6, 0x0200, 0, len(cfg)), cfg),
                            (struct.pack("<BBHHH", 0x00, 9, cfg[5], 0, 0), b"")):
            self.control(ts, ts, dev, setup, data, irp=0, comment=comment)
            self.stats["transfers"] -= 1


def _end(t):
    p = t.pkts[-1]
    return p["ts"] + p["dur"]


def _write_txn(w, t, kind=None):
    ep = t.ep | (0x80 if t.pid == P.PID_IN else 0)
    if t.hs == P.PID_STALL:
        w.transfer(t.ts, _end(t), t.dev, ep, t.payload or b"", ST_STALL, kind)
    elif t.dpid >= 0 and t.payload is not None and not t.err and (
            t.hs == P.PID_ACK or w.ep_type.get((t.dev, ep)) == ISO):
        if t.hs != P.PID_ACK:
            w.stats["skipped"] += 1  # isochronous: would need the iso packet header
        else:
            w.transfer(t.ts, _end(t), t.dev, ep, t.payload, kind=kind)
    elif t.hs != P.PID_NAK:
        w.stats["skipped"] += 1
        w.lost += 1


def _write_ctrl(w, sel, state):
    p = sel[0].payload if sel and sel[0].pid == P.PID_SETUP else None
    if p is None or len(p) < 8:
        w.stats["skipped"] += 1
        w.lost += 1
        return
    setup = p[:8]
    dpid = P.PID_IN if setup[0] & 0x80 else P.PID_OUT
    data = b"".join(t.payload for t in sel[1:] if t.pid == dpid and t.hs == P.PID_ACK and t.payload)
    data = data[:U.u16(setup, 6)]
    if state == 2:
        w.notes.append("sniffer: control transfer not completed in the capture")
    w.control(sel[0].ts, None if state == 2 else _end(sel[-1]), sel[0].dev, setup, data,
              ST_STALL if state == 1 else ST_OK)


def _write_msc(w, sel):
    """CBW, data phase and CSW are one transfer each"""
    cur = []

    def done():
        if cur:
            ep = cur[0].ep | (0x80 if cur[0].pid == P.PID_IN else 0)
            data = b"".join(t.payload for t in cur if t.payload and t.hs == P.PID_ACK)
            w.transfer(cur[0].ts, _end(cur[-1]), cur[0].dev, ep, data,
                       ST_STALL if cur[-1].hs == P.PID_STALL else ST_OK, BULK)
            cur.clear()

    for t in sel:
        if t.hs == P.PID_NAK:
            continue
        single = (t.pid == P.PID_OUT and U.is_cbw(t.payload)) or (t.pid == P.PID_IN and U.is_csw(t.payload))
        if t.hs == P.PID_STALL or (t.hs == P.PID_ACK and t.payload is not None and not t.err):
            if cur and (single or cur[0].pid != t.pid):
                done()
            cur.append(t)
            if single or t.hs == P.PID_STALL:
                done()
        else:
            w.stats["skipped"] += 1
            w.lost += 1
    done()


def export_usbpcap(store, path, progress=None, descriptors="generic", reference=None) -> dict:
    """descriptors: "generic" (reference device if one fits, else generic HID) or "none".
    reference: list from load_reference(). progress(done, total) -> False cancels."""
    stats = {"frames": 0, "transfers": 0, "skipped": 0, "errors": 0, "comments": 0, "descriptors": [],
             "cancelled": False}
    total = store.row_count()
    out = open(path, "wb", buffering=1 << 20)
    try:
        out.write(shb("Pico USB Sniffer"))
        out.write(idb(LINKTYPE_USBPCAP, "Pico USB Sniffer", "Pico USB Sniffer (transfers rebuilt from the bus)", 65535))
        w = _Writer(store, out, stats)
        eps, msc = bus_endpoints(store)
        add = []
        for a in sorted(eps):
            known = _learned(store, a)
            if known:
                w.ep_type.update({(a, e): t for e, t in parse_config(known[1])[0].items()})
            elif descriptors != "none" and eps[a] and a not in msc:
                fit = []
                for label, dd, cfg in reference or ():
                    ref_eps, classes = parse_config(cfg)
                    if 3 in classes and eps[a] <= set(ref_eps):
                        fit.append((label, dd, cfg))
                if len(fit) == 1:
                    label, dd, cfg = fit[0]
                else:
                    label = "generic HID, VID/PID 0000"
                    dd, cfg = generic_hid(eps[a], _interface_of(store, a), not store.fs)
                w.ep_type.update({(a, e): t for e, t in parse_config(cfg)[0].items()})
                stats["descriptors"].append(f"device {a}: {label}")
                add.append((a, dd, cfg, f"Not captured: descriptors added by the sniffer tool ({label})"))
        for i in range(total):
            if progress and i % 2000 == 0 and not progress(i, total):
                stats["cancelled"] = True
                break
            kind, fl = store.r_kind[i], store.r_flags[i]
            if kind in (C.K_TXN, C.K_CTRL, C.K_MSC):
                if kind == C.K_TXN and fl & C.RF_NAK:
                    continue
                sel = store._filter_txns(i, store._assemble(i, 1 << 62)[0])
                if not sel:
                    continue
                if add:
                    for a in add:
                        w.descriptors(sel[0].ts, *a)
                    add = []
                w.flush(sel[0].ts - 1)
                if kind == C.K_CTRL:
                    _write_ctrl(w, sel, store.r_aux[i] >> 28)
                elif kind == C.K_MSC:
                    _write_msc(w, sel)
                else:
                    _write_txn(w, sel[-1])
            elif kind == C.K_PACKET:
                if fl & C.RF_ERROR:
                    stats["errors"] += 1
                    w.lost += 1
            elif kind == C.K_RESET:
                w.notes.append("Bus Reset")
            elif kind == C.K_DROP:
                w.notes.append("sniffer: " + store.top_node(i).cols[9])
            elif kind == C.K_SYNCERR:
                w.notes.append("sniffer: sync error (wrong speed?)")
            elif kind == C.K_EVENT:
                blob = store._read(store.r_off[i], store.r_len[i])
                if blob[1] == P.REC_HOST_EVENT and blob[12] in (P.HE_DISCONNECT, P.HE_RECONNECT):
                    w.notes.append("sniffer " + blob[13:].decode("utf-8", "replace"))
        w.flush()
    finally:
        out.close()
    return stats
