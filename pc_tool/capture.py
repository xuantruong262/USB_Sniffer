"""
Pico USB Sniffer - capture storage and protocol analyzer (Data Center style).

Design for multi-hour captures:
  * every record received is appended to a capture file on disk immediately
    (the file is the capture: nothing is lost if the app crashes)
  * the analyzer groups packets into a 3 level hierarchy, like Total Phase
    Data Center:
        transfer (control request / mass-storage command / SOF group)
          -> transaction (token + data + handshake, NAK retries merged as POLL)
               -> packet
  * only the top level is indexed in memory: each row is a *span* of the
    capture file plus a few bytes of metadata (~24 bytes/row). Transactions
    and packets are rebuilt lazily from the file when a row is shown or
    expanded, so memory does not grow with the number of packets.
"""
from __future__ import annotations

import os
import struct
import threading
import time
from array import array
from bisect import bisect_right

import protocol as P
import usbdecode as U

FILE_MAGIC = b"PUSBSNF1"
FILE_HEADER = FILE_MAGIC + struct.pack("<II", 1, 0)  # 16 bytes
HEADER_LEN = len(FILE_HEADER)

# row kinds
K_TXN = 1        # transaction (possibly with merged NAK polls)
K_FOLD = 3       # firmware fold summary (SOF / IN-NAK)
K_RESET = 4
K_KEEPALIVE = 5
K_PACKET = 6     # stray / error packet
K_EVENT = 7
K_SYNCERR = 8
K_DROP = 9
K_CTRL = 10      # control transfer
K_MSC = 11       # mass storage bulk-only command
K_SOFGRP = 12    # run of raw SOF packets (fold off)
K_KAGRP = 13     # run of raw LS keep-alives (fold off)

# row flags
RF_ERROR = 0x01
RF_NAK = 0x02
RF_SETUP = 0x04
RF_STALL = 0x08
RF_IDLE = 0x10
RF_INCOMPLETE = 0x20
RF_IN = 0x40
RF_OUT = 0x80

COLUMNS = ["Sp", "Index", "m:s.ms.us", "Dur", "Len", "Err", "Dev", "Ep", "Record", "Summary"]
COL_RECORD = 8
NONE = 255

POLL_TIMEOUT_US = 100_000       # NAK-only poll groups are closed after 100 ms
POLL_SPAN_MAX = 256 << 10
CTRL_IDLE_US = 1_000_000
CTRL_MAX_US = 5_000_000
MSC_IDLE_US = 3_000_000
MSC_MAX_US = 30_000_000
GRP_IDLE_US = 100_000
SOFGRP_MAX = 1000
CTRL_DATA_CAP = 4096
CHILD_READ_MAX = 8 << 20
MAX_CHILDREN = 5000
MAX_PKT_HEX = 1100  # bytes shown in the Summary of a packet row

# host markers written while the device keeps streaming: they can land between
# two packets of one transaction and must not split it
PASSIVE_EVENTS = frozenset((P.HE_USER_STOP, P.HE_NOTE))

_U64 = struct.Struct("<Q")
_PKT_HDR = struct.Struct("<QHH")

PID_IN, PID_OUT, PID_SETUP, PID_SOF = P.PID_IN, P.PID_OUT, P.PID_SETUP, P.PID_SOF
PID_ACK, PID_NAK, PID_STALL = P.PID_ACK, P.PID_NAK, P.PID_STALL
IS_TOKEN, IS_DATA, IS_HS = P.IS_TOKEN, P.IS_DATA, P.IS_HS


def host_us() -> int:
    return time.time_ns() // 1000


class RowFilter:
    def __init__(self, dev=-1, ep=-1, hide_idle=False, hide_nak=False, errors_only=False):
        self.dev = dev
        self.ep = ep
        self.hide_idle = hide_idle
        self.hide_nak = hide_nak
        self.errors_only = errors_only

    def is_pass_all(self):
        return self.dev < 0 and self.ep < 0 and not (self.hide_idle or self.hide_nak or self.errors_only)


class Txn:
    """one transaction: token [+ data] [+ handshake]"""
    __slots__ = ("off", "end", "ts", "pkt", "pid", "dev", "ep", "dpid", "dlen", "payload", "hs", "err", "pkts")

    def __init__(self, off, end, ts, pkt, pid, dev, ep):
        self.off = off
        self.end = end
        self.ts = ts
        self.pkt = pkt
        self.pid = pid
        self.dev = dev
        self.ep = ep
        self.dpid = -1
        self.dlen = 0
        self.payload = None
        self.hs = -1
        self.err = 0
        self.pkts = None


class _Poll:
    __slots__ = ("first", "last", "count", "parent", "row")


class _Group:
    __slots__ = ("kind", "row", "dev", "ep", "in_ep", "off", "end", "t0", "last", "dlen", "flags", "setup",
                 "dir_in", "wlen", "data", "status", "count", "f1", "f2", "open")

    def __init__(self, kind):
        self.kind = kind
        self.open = True
        self.dlen = 0
        self.flags = 0
        self.count = 0
        self.status = 3
        self.in_ep = 0
        self.data = None
        self.setup = None


def txn_flags(t: Txn) -> int:
    f = 0
    if t.pid == PID_IN:
        f |= RF_IN
    elif t.pid == PID_OUT:
        f |= RF_OUT
    elif t.pid == PID_SETUP:
        f |= RF_SETUP
    if t.err:
        f |= RF_ERROR
    if t.hs == PID_NAK:
        f |= RF_NAK
    elif t.hs == PID_STALL:
        f |= RF_STALL
    elif t.hs < 0:
        f |= RF_INCOMPLETE
    return f


# ---------------------------------------------------------------------------
# lazy view objects (GUI side)
# ---------------------------------------------------------------------------
class Node:
    """a displayable item below the top level (or a top level row)"""
    __slots__ = ("cols", "cat", "flags", "kids", "info")

    def __init__(self, cols, cat="", flags=0, kids=None, info=None):
        self.cols = cols
        self.cat = cat
        self.flags = flags
        self.kids = kids  # None or callable -> list[Node]
        self.info = info


class PTxn:
    """transaction with the NAK retries that preceded it"""
    __slots__ = ("final", "naks")

    def __init__(self, final, naks):
        self.final = final
        self.naks = naks

    @property
    def first(self):
        return self.naks[0] if self.naks else self.final

    @property
    def nak_only(self):
        return self.final.hs == PID_NAK


def merge_polls(txns):
    """NAK'd attempts are merged into the next attempt of the same token"""
    out = []
    pend = {}
    for t in txns:
        if t.hs == PID_NAK and t.pid != PID_SETUP:
            for p in [p for p in pend if p != t.pid]:
                n = pend.pop(p)
                out.append(PTxn(n[-1], n))
            pend.setdefault(t.pid, []).append(t)
            continue
        for p in [p for p in pend if p != t.pid]:
            n = pend.pop(p)
            out.append(PTxn(n[-1], n))
        out.append(PTxn(t, pend.pop(t.pid, [])))
    for n in pend.values():
        out.append(PTxn(n[-1], n))
    out.sort(key=lambda x: x.first.off)
    return out


# ---------------------------------------------------------------------------
class CaptureStore:
    """Capture file + row index. Thread model: one writer thread (feed /
    host_event), GUI thread reads (row_count / top_node / children)."""

    def __init__(self, path: str, create: bool = True):
        self.path = path
        self.lock = threading.RLock()
        if create:
            self._wf = open(path, "wb", buffering=1 << 20)
            self._wf.write(FILE_HEADER)
            self._wf.flush()
        else:
            self._wf = None
        self._rf = open(path, "rb")
        if not create:
            if self._rf.read(HEADER_LEN)[:8] != FILE_MAGIC:
                self._rf.close()
                raise ValueError("not a Pico USB Sniffer capture file")
        self.write_pos = HEADER_LEN

        # row index (one entry per top level row)
        self.r_off = array("q")    # file offset of the first record of the row
        self.r_len = array("I")    # span length in the file
        self.r_kind = array("B")
        self.r_flags = array("B")
        self.r_dev = array("B")
        self.r_ep = array("B")     # MSC: out ep | in ep << 4
        self.r_aux = array("I")    # polls / data length + state / SOF count + frames
        self.r_pkt = array("I")    # global index of the first packet of the row
        self.visible_rows = 0

        # parser state
        self._buf = bytearray()
        self._suspect = 0
        self.garbage_bytes = 0
        self.bytes_in = 0
        self.records = 0
        self.packets = 0

        # analyzer state
        self._t = None
        self._idle_txn = None
        self._idle_since = 0.0
        self._polls = {}
        self._ctrl = {}
        self._msc = {}
        self._msc_in = {}
        self._grp = None  # open SOF / keep-alive group
        self._open = {}   # reserved rows not final yet
        self._now = 0
        self._next_check = 0

        # statistics (Data Center "Statistics" pane)
        self.st_pid = {}        # device address (-1 = no address, e.g. SOF) -> packets per PID [16]
        self.st_err = [0] * 16  # packet error flag bit -> packets
        self.st_err_pkts = 0
        self.st_ctrl = {}       # device address -> [std, class, vendor, rsvd, dev, itf, ep, other]
        self.st_keepalive = 0
        self.st_reset = 0
        self.st_syncerr = 0

        # learned devices: addr -> dict
        self.devices = {}
        self.dev_version = 0

        # time segments: (file_offset_of_START, device_start_ts, display_base_us, fs)
        self.seg_off = []
        self.seg_dev0 = []
        self.seg_base = []
        self.seg_fs = []
        self.session_host0 = None
        self._last_segment_host = None
        self.fs = True

        # device state
        self.info = None
        self.status = None
        self.device_dropped = 0
        self.device_running = False
        self.last_stop_seen = 0

        self._cache = {}

    # ------------------------------------------------------------------ write
    def close_writer(self):
        with self.lock:
            self._flush_all()
            if self._wf:
                self._wf.flush()
                self._wf.close()
                self._wf = None
            self._update_visible()

    def close(self):
        self.close_writer()
        try:
            self._rf.close()
        except Exception:
            pass

    def host_event(self, code: int, text: str):
        payload = _U64.pack(host_us()) + bytes([code]) + text.encode("utf-8", "replace")[:1000]
        raw = P.build_record(P.REC_HOST_EVENT, payload)
        with self.lock:
            off = self.write_pos
            if self._wf:
                self._wf.write(raw)
                self._wf.flush()
            self.write_pos += len(raw)
            self._on_record(raw, 0, P.REC_HOST_EVENT, len(payload), off)
            self._update_visible()

    def feed(self, data: bytes):
        """Live data from the device: parse, persist, index."""
        with self.lock:
            self.bytes_in += len(data)
            self._parse(data, write=True)
            if self._wf:
                self._wf.flush()
            self._update_visible()

    def idle(self):
        """No data for a while: close a pending transaction so it is shown."""
        # the rest of a transaction may still be in flight (split USB
        # transfer): only close it once it has been pending for 100 ms
        with self.lock:
            t = self._t
            if t is None:
                return
            now = time.monotonic()
            if self._idle_txn is not t:
                self._idle_txn = t
                self._idle_since = now
            elif now - self._idle_since > 0.1:
                self._idle_txn = None
                self._txn_done()
                self._update_visible()

    def load(self, progress=None, chunk=4 << 20):
        """Index an existing capture file."""
        size = os.path.getsize(self.path)
        with open(self.path, "rb") as f:
            f.seek(HEADER_LEN)
            done = HEADER_LEN
            while True:
                data = f.read(chunk)
                if not data:
                    break
                with self.lock:
                    self._parse(data, write=False)
                done += len(data)
                if progress and not progress(done, size):
                    break
        with self.lock:
            self._flush_all()
            self._update_visible()

    def _update_visible(self):
        self.visible_rows = min(self._open) if self._open else len(self.r_off)

    def _parse(self, data: bytes, write: bool):
        buf = self._buf
        buf += data
        n = len(buf)
        p = 0
        seg = 0  # start of the current clean segment (to be written as-is)
        base = self.write_pos  # file offset of buf[seg]
        lmin, lmax = P.LIMIT_MIN, P.LIMIT_MAX
        magic = P.MAGIC
        on_packet = self._on_packet
        while n - p >= 4:
            if buf[p] != magic:
                q = buf.find(P.MAGIC_B, p + 1)
                if q < 0:
                    q = n
                if write and p > seg:
                    self._wf.write(buf[seg:p])
                base += p - seg
                self.garbage_bytes += q - p
                self._suspect = 3
                p = seg = q
                continue
            t = buf[p + 1]
            ln = buf[p + 2] | (buf[p + 3] << 8)
            mn = lmin[t]
            end = p + 4 + ln
            bad = mn is None or ln < mn or ln > lmax[t]
            if not bad and self._suspect:
                # resynchronising: only accept records that chain into another
                # valid header (filters 0xA5 bytes inside payloads)
                if end + 4 > n:
                    break
                t2 = buf[end + 1]
                ln2 = buf[end + 2] | (buf[end + 3] << 8)
                m2 = lmin[t2]
                if buf[end] != magic or m2 is None or ln2 < m2 or ln2 > lmax[t2]:
                    bad = True
                else:
                    self._suspect -= 1
            if bad:
                if write and p > seg:
                    self._wf.write(buf[seg:p])
                base += p - seg
                self.garbage_bytes += 1
                self._suspect = 3
                p = seg = p + 1
                continue
            if end > n:
                break
            off = base + (p - seg)
            if t == P.REC_PACKET:
                on_packet(buf, p, ln, off)
            else:
                self._on_record(buf, p, t, ln, off)
            self.records += 1
            p = end
        if write and p > seg:
            self._wf.write(buf[seg:p])
        self.write_pos = base + (p - seg)
        del buf[:p]

    # ------------------------------------------------------------ row index
    def _new_row(self, kind, off, ln, flags, dev, ep, aux, pkt, grp=False):
        if not grp and self._grp is not None:
            self._close_grp()
        self.r_off.append(off)
        self.r_len.append(min(ln, 0xFFFFFFFF))
        self.r_kind.append(kind)
        self.r_flags.append(flags & 0xFF)
        self.r_dev.append(dev & 0xFF if dev >= 0 else NONE)
        self.r_ep.append(ep & 0xFF if ep >= 0 else NONE)
        self.r_aux.append(aux & 0xFFFFFFFF)
        self.r_pkt.append(pkt & 0xFFFFFFFF)
        return len(self.r_off) - 1

    def _reserve(self, kind, off, flags, dev, ep, pkt, grp=False):
        r = self._new_row(kind, off, 0, flags, dev, ep, 0, pkt, grp)
        self._open[r] = True
        return r

    def _fill(self, r, ln, aux, flags, ep=None):
        self.r_len[r] = min(max(ln, 0), 0xFFFFFFFF)
        self.r_aux[r] = aux & 0xFFFFFFFF
        self.r_flags[r] = flags & 0xFF
        if ep is not None:
            self.r_ep[r] = ep & 0xFF
        self._open.pop(r, None)
        self._cache.pop(r, None)

    # ------------------------------------------------------------ statistics
    def _cnt(self, dev, pid, n=1):
        c = self.st_pid.get(dev)
        if c is None:
            c = self.st_pid[dev] = [0] * 16
            self.dev_version += 1  # new address on the bus -> Navigator lists it
        c[pid] += n

    def _cnt_err(self, flags):
        self.st_err_pkts += 1
        for b in range(16):
            if flags >> b & 1:
                self.st_err[b] += 1

    # --------------------------------------------------------------- analyzer
    def _on_packet(self, buf, p, ln, off):
        idx = self.packets
        self.packets = idx + 1
        ts = _U64.unpack_from(buf, p + 4)[0]
        if ts > self._now:
            self._now = ts
            if ts >= self._next_check:
                self._next_check = ts + 10_000
                self._timeouts()
        flags = buf[p + 14] | (buf[p + 15] << 8)
        size = ln - 12
        end = off + 4 + ln
        t = self._t
        if flags or size < 2:
            self._cnt_err(flags or P.PKT_ERR_SIZE)
            if t is not None:
                t.end = end
                t.err |= flags or P.PKT_ERR_SIZE
                return
            self._new_row(K_PACKET, off, 4 + ln, RF_ERROR, -1, -1, 0, idx)
            return
        pid = buf[p + 17] & 0x0F
        if IS_TOKEN[pid] and size >= 4:
            if t is not None:
                self._txn_done()
            v = buf[p + 18] | (buf[p + 19] << 8)
            self._cnt(v & 0x7F, pid)
            self._t = Txn(off, end, ts, idx, pid, v & 0x7F, (v >> 7) & 0xF)
            return
        if IS_DATA[pid]:
            self._cnt(t.dev if t is not None else -1, pid)
            if t is not None and t.dpid < 0 and t.hs < 0:
                t.dpid = pid
                t.dlen = size - 4
                if t.ep == 0 or t.dlen == 31 or t.dlen == 13:
                    t.payload = bytes(buf[p + 18:p + 2 + ln])
                t.end = end
                return
            if t is not None:
                self._txn_done()
            self._new_row(K_PACKET, off, 4 + ln, 0, -1, -1, 0, idx)
            return
        if IS_HS[pid]:
            self._cnt(t.dev if t is not None else -1, pid)
            if t is not None and t.hs < 0:
                t.hs = pid
                t.end = end
                self._txn_done()
                return
            if t is not None:
                self._txn_done()
            self._new_row(K_PACKET, off, 4 + ln, 0, -1, -1, 0, idx)
            return
        self._cnt(-1, pid)
        if t is not None:
            self._txn_done()
        if pid == PID_SOF and size >= 4:
            frame = (buf[p + 18] | (buf[p + 19] << 8)) & 0x7FF
            g = self._grp
            if g is not None and (g.kind != K_SOFGRP or g.count >= SOFGRP_MAX):
                self._close_grp()
                g = None
            if g is None:
                g = _Group(K_SOFGRP)
                g.off = off
                g.t0 = ts
                g.f1 = frame
                g.row = self._reserve(K_SOFGRP, off, RF_IDLE, -1, -1, idx, grp=True)
                self._grp = g
            g.end = end
            g.last = ts
            g.count += 1
            g.f2 = frame
            return
        self._new_row(K_PACKET, off, 4 + ln, 0, -1, -1, 0, idx)

    def _close_grp(self):
        g = self._grp
        self._grp = None
        if g.kind == K_SOFGRP:
            aux = min(g.count, 1023) | (g.f1 << 10) | (g.f2 << 21)
        else:
            aux = g.count
        self._fill(g.row, g.end - g.off, aux, RF_IDLE)

    def _txn_done(self):
        t = self._t
        self._t = None
        pid = t.pid
        if t.hs == PID_NAK and pid != PID_SETUP:
            key = t.dev | (t.ep << 7) | (pid << 11)
            pg = self._polls.get(key)
            if pg is not None and pg.parent is None and t.ts - pg.first.ts > POLL_TIMEOUT_US:
                self._flush_poll(key)
                pg = None
            if pg is None:
                self._close_other_polls(t.dev, t.ep, pid)
                pg = _Poll()
                pg.first = t
                pg.count = 0
                pg.parent = self._owner(t)
                pg.row = -1
                if pg.parent is None:
                    pg.row = self._reserve(K_TXN, t.off, txn_flags(t), t.dev, t.ep, t.pkt)
                self._polls[key] = pg
            pg.count += 1
            pg.last = t
            par = pg.parent
            if par is not None:
                if par.open:
                    par.end = t.end
                    par.last = t.ts
            elif t.end - pg.first.off > POLL_SPAN_MAX:
                self._flush_poll(key)
            return
        if pid == PID_SETUP:
            self._close_other_polls(t.dev, t.ep, -1)
            self._ctrl_start(t)
            return
        self._close_other_polls(t.dev, t.ep, pid)
        pg = self._polls.pop(t.dev | (t.ep << 7) | (pid << 11), None) if self._polls else None
        self._deliver(t, pg)

    def _close_other_polls(self, dev, ep, pid):
        if not self._polls:
            return
        for p in (PID_IN, PID_OUT, P.PID_PING):
            if p != pid:
                k = dev | (ep << 7) | (p << 11)
                if k in self._polls:
                    self._flush_poll(k)

    def _flush_poll(self, key):
        """close a NAK-only poll group"""
        pg = self._polls.pop(key)
        t = pg.last
        par = pg.parent
        if par is not None:
            if par.open:
                self._grp_add(par, t)
                return
            self._new_row(K_TXN, pg.first.off, t.end - pg.first.off, txn_flags(t), t.dev, t.ep, pg.count,
                          pg.first.pkt)
            return
        self._fill(pg.row, t.end - pg.first.off, pg.count, txn_flags(t))

    def _owner(self, t):
        if t.ep == 0:
            return self._ctrl.get(t.dev)
        g = self._msc.get(t.dev)
        if g is not None:
            if t.pid == PID_OUT and t.ep == g.ep:
                return g
            if t.pid == PID_IN and (g.in_ep == 0 or t.ep == g.in_ep):
                return g
        return None

    def _deliver(self, t, pg):
        polls = pg.count if pg is not None else 0
        if pg is not None and pg.row >= 0:
            self._fill(pg.row, t.end - pg.first.off, polls, txn_flags(t))
            return
        if t.pid == PID_OUT and t.ep and t.hs == PID_ACK and U.is_cbw(t.payload):
            self._msc_start(t)
            return
        grp = pg.parent if (pg is not None and pg.parent is not None and pg.parent.open) else self._owner(t)
        if grp is not None:
            self._grp_add(grp, t)
            return
        first = pg.first if pg is not None else t
        self._new_row(K_TXN, first.off, t.end - first.off, txn_flags(t), t.dev, t.ep, polls, first.pkt)

    # control transfers
    def _ctrl_start(self, t):
        old = self._ctrl.get(t.dev)
        if old is not None:
            self._ctrl_close(old, 2)
        g = _Group(K_CTRL)
        g.dev = t.dev
        g.ep = 0
        g.off = t.off
        g.end = t.end
        g.t0 = g.last = t.ts
        g.flags = RF_SETUP
        if t.err or t.hs != PID_ACK:
            g.flags |= RF_ERROR
        p = t.payload
        if p is not None and len(p) >= 8:
            c = self.st_ctrl.get(t.dev)
            if c is None:
                c = self.st_ctrl[t.dev] = [0] * 8
            c[(p[0] >> 5) & 3] += 1
            c[4 + min(p[0] & 0x1F, 3)] += 1
            s = U.Setup(p)
            g.setup = p[:8]
            g.dir_in = s.dir_in
            g.wlen = s.len
        else:
            g.dir_in = False
            g.wlen = 0
            g.flags |= RF_ERROR
        g.data = bytearray()
        g.row = self._reserve(K_CTRL, t.off, g.flags, t.dev, 0, t.pkt)
        self._ctrl[t.dev] = g

    def _grp_add(self, g, t):
        g.end = t.end
        g.last = t.ts
        if t.err:
            g.flags |= RF_ERROR
        if g.kind == K_CTRL:
            if t.hs == PID_STALL:
                g.flags |= RF_STALL
                self._ctrl_close(g, 1)
                return
            status_pid = PID_OUT if (g.dir_in and g.wlen > 0) else PID_IN
            if t.pid == status_pid:
                if t.hs == PID_ACK:
                    self._ctrl_close(g, 0)
            elif g.wlen > 0 and t.hs == PID_ACK and t.dpid >= 0:
                g.dlen += t.dlen
                if t.payload and len(g.data) < CTRL_DATA_CAP:
                    g.data += t.payload
            return
        # mass storage
        if t.hs == PID_STALL:
            g.flags |= RF_STALL
            return
        if t.pid == PID_IN and t.hs == PID_ACK and U.is_csw(t.payload):
            g.in_ep = t.ep
            self._msc_in[g.dev] = t.ep
            self._msc_close(g, t.payload[12] & 3)
            return
        if t.hs == PID_ACK and t.dpid >= 0:
            g.dlen += t.dlen

    def _ctrl_close(self, g, state):
        if self._ctrl.get(g.dev) is g:
            del self._ctrl[g.dev]
        g.open = False
        self._drop_child_polls(g)
        f = g.flags
        if state == 1:
            f |= RF_STALL
        elif state == 2:
            f |= RF_INCOMPLETE
        self._fill(g.row, g.end - g.off, min(g.dlen, 0x0FFFFFFF) | (state << 28), f)
        if state == 0 and g.setup is not None:
            try:
                self._learn(g)
            except Exception:
                pass

    def _drop_child_polls(self, g):
        if self._polls:
            for k in [k for k, pg in self._polls.items() if pg.parent is g]:
                del self._polls[k]

    # mass storage
    def _msc_start(self, t):
        old = self._msc.get(t.dev)
        if old is not None:
            self._msc_close(old, 3)
        g = _Group(K_MSC)
        g.dev = t.dev
        g.ep = t.ep
        g.in_ep = self._msc_in.get(t.dev, 0)
        g.off = t.off
        g.end = t.end
        g.t0 = g.last = t.ts
        g.flags = RF_OUT
        if t.err:
            g.flags |= RF_ERROR
        g.row = self._reserve(K_MSC, t.off, g.flags, t.dev, g.ep | (g.in_ep << 4), t.pkt)
        self._msc[t.dev] = g

    def _msc_close(self, g, status):
        if self._msc.get(g.dev) is g:
            del self._msc[g.dev]
        g.open = False
        self._drop_child_polls(g)
        f = g.flags
        if status == 2:
            f |= RF_ERROR
        elif status == 3:
            f |= RF_INCOMPLETE
        self._fill(g.row, g.end - g.off, min(g.dlen, 0x3FFFFFFF) | (status << 30), f, g.ep | (g.in_ep << 4))

    def _timeouts(self):
        now = self._now
        if self._polls:
            for k in [k for k, pg in self._polls.items()
                      if pg.parent is None and now - pg.first.ts > POLL_TIMEOUT_US]:
                self._flush_poll(k)
        if self._ctrl:
            for g in [g for g in self._ctrl.values() if now - g.last > CTRL_IDLE_US or now - g.t0 > CTRL_MAX_US]:
                self._ctrl_close(g, 2)
        if self._msc:
            for g in [g for g in self._msc.values() if now - g.last > MSC_IDLE_US or now - g.t0 > MSC_MAX_US]:
                self._msc_close(g, 3)
        g = self._grp
        if g is not None and now - g.last > GRP_IDLE_US:
            self._close_grp()

    def _flush_all(self):
        if self._t is not None:
            self._txn_done()
        for k in list(self._polls):
            if k in self._polls:
                self._flush_poll(k)
        for g in list(self._ctrl.values()):
            self._ctrl_close(g, 2)
        for g in list(self._msc.values()):
            self._msc_close(g, 3)
        if self._grp is not None:
            self._close_grp()

    def _dev(self, a):
        d = self.devices.get(a)
        if d is None:
            d = {"addr": a, "device": None, "config": None, "strings": {}, "hid": {}, "cfg": None,
                 "max_lun": None, "speed": "FS" if self.fs else "LS"}
            self.devices[a] = d
        return d

    def _learn(self, g):
        s = U.Setup(g.setup)
        data = bytes(g.data)
        if s.type == 0 and s.req == 0x06 and data:
            dt, di = s.val >> 8, s.val & 0xFF
            d = self._dev(g.dev)
            if dt == 1:
                if d["device"] is None or len(data) >= len(d["device"]):
                    d["device"] = data
            elif dt == 2:
                if d["config"] is None or len(data) >= len(d["config"]):
                    d["config"] = data
            elif dt == 3 and di:
                d["strings"][di] = U.string_of(data)
            elif dt == 0x22:
                d["hid"][s.idx] = data
            else:
                return
            self.dev_version += 1
        elif s.type == 0 and s.req == 0x05:
            new = s.val & 0x7F
            old = self.devices.pop(g.dev, None)
            if old is not None and new != g.dev:
                old["addr"] = new
                self.devices[new] = old
            else:
                self._dev(new)
            self.dev_version += 1
        elif s.type == 0 and s.req == 0x09:
            self._dev(g.dev)["cfg"] = s.val
            self.dev_version += 1
        elif s.type == 1 and s.req == 0xFE and data:
            self._dev(g.dev)["max_lun"] = data[0]
            self.dev_version += 1

    def _on_record(self, buf, p, t, ln, off):
        rl = 4 + ln
        pk = self.packets
        if t == P.REC_STATUS:
            v = struct.unpack_from("<QIIIIIIII", buf, p + 4)
            self.status = v
            self.device_dropped = v[2]
            if v[0] > self._now:
                self._now = v[0]
                self._timeouts()
            return
        passive = t == P.REC_HOST_EVENT and buf[p + 12] in PASSIVE_EVENTS
        if self._t is not None and not passive:
            self._txn_done()
        if t == P.REC_FOLD:
            t2 = _U64.unpack_from(buf, p + 12)[0]
            if t2 > self._now:
                self._now = t2
            n = buf[p + 4 + 32]
            q = p + 4
            sof, _f1, _f2, ka, other = struct.unpack_from("<IHHII", buf, q + 16)
            if sof:
                self._cnt(-1, PID_SOF, sof)
            self.st_keepalive += ka
            if other:
                self._cnt(-1, PID_IN, other)
                self._cnt(-1, PID_NAK, other)
            for k in range(n):
                a, _e, cnt = struct.unpack_from("<BBI", buf, q + 33 + 6 * k)
                self._cnt(a, PID_IN, cnt)
                self._cnt(a, PID_NAK, cnt)
            dev = ep = -1
            if n == 1:
                dev = buf[p + 4 + 33]
                ep = buf[p + 4 + 34]
            self._new_row(K_FOLD, off, rl, RF_IDLE, dev, ep, 0, pk)
            if t2 >= self._next_check:
                self._next_check = t2 + 10_000
                self._timeouts()
        elif t == P.REC_KEEPALIVE:
            ts = _U64.unpack_from(buf, p + 4)[0]
            if ts > self._now:
                self._now = ts
            g = self._grp
            if g is not None and (g.kind != K_KAGRP or g.count >= SOFGRP_MAX):
                self._close_grp()
                g = None
            if g is None:
                g = _Group(K_KAGRP)
                g.off = off
                g.t0 = ts
                g.row = self._reserve(K_KAGRP, off, RF_IDLE, -1, -1, pk, grp=True)
                self._grp = g
            g.end = off + rl
            g.last = ts
            g.count += 1
            self.st_keepalive += 1
        elif t == P.REC_RESET:
            self.st_reset += 1
            self._flush_all()
            self._new_row(K_RESET, off, rl, 0, -1, -1, 0, pk)
        elif t == P.REC_SYNCERR:
            self.st_syncerr += 1
            self._new_row(K_SYNCERR, off, rl, RF_ERROR, -1, -1, 0, pk)
        elif t == P.REC_DROP:
            self._new_row(K_DROP, off, rl, RF_ERROR, -1, -1, 0, pk)
        elif t == P.REC_START:
            self._flush_all()
            dev0 = _U64.unpack_from(buf, p + 4)[0]
            self.fs = bool(buf[p + 12])
            self._now = dev0
            self._next_check = 0
            seg_host = self._last_segment_host
            if not self.seg_off:
                display_base = 0
                if self.session_host0 is None:
                    self.session_host0 = seg_host
            elif seg_host is not None and self.session_host0 is not None:
                display_base = seg_host - self.session_host0
            else:
                display_base = self.seg_base[-1]
            self.seg_off.append(off)
            self.seg_dev0.append(dev0)
            self.seg_base.append(display_base)
            self.seg_fs.append(self.fs)
            self.device_running = True
            self._new_row(K_EVENT, off, rl, 0, -1, -1, 0, pk)
        elif t == P.REC_STOP:
            self._flush_all()
            self.device_running = False
            self.last_stop_seen += 1
            self._new_row(K_EVENT, off, rl, 0, -1, -1, 0, pk)
        elif t == P.REC_INFO:
            self.info = bytes(buf[p + 4:p + rl])
            self._new_row(K_EVENT, off, rl, 0, -1, -1, 0, pk)
        elif t == P.REC_TEXT:
            self._new_row(K_EVENT, off, rl, RF_ERROR if b"WARN" in buf[p + 4:p + rl] else 0, -1, -1, 0, pk)
        elif t == P.REC_HOST_EVENT:
            if not passive:
                self._flush_all()
            ht = _U64.unpack_from(buf, p + 4)[0]
            code = buf[p + 12]
            if code == P.HE_SESSION and self.session_host0 is None:
                self.session_host0 = ht
            if code == P.HE_SEGMENT:
                self._last_segment_host = ht
                if self.session_host0 is None:
                    self.session_host0 = ht
            flags = RF_ERROR if code == P.HE_DISCONNECT else 0
            self._new_row(K_EVENT, off, rl, flags, -1, -1, 0, pk)

    # ===================================================================
    # reading side (lazy)
    # ===================================================================
    def row_count(self) -> int:
        return self.visible_rows

    def _read(self, off, ln) -> bytes:
        with self.lock:
            if self._wf:
                self._wf.flush()
        self._rf.seek(off)
        return self._rf.read(ln)

    def _seg_for(self, off):
        i = bisect_right(self.seg_off, off) - 1
        if i < 0:
            return (0, 0, self.fs)
        return self.seg_dev0[i], self.seg_base[i], self.seg_fs[i]

    @staticmethod
    def _rel(ts, seg):
        return ts - seg[0] + seg[1]

    @staticmethod
    def iter_records(blob: bytes):
        p = 0
        n = len(blob)
        while n - p >= 4:
            if blob[p] != P.MAGIC:
                p += 1
                continue
            t = blob[p + 1]
            ln = blob[p + 2] | (blob[p + 3] << 8)
            if p + 4 + ln > n:
                break
            yield p, t, blob[p + 4:p + 4 + ln]
            p += 4 + ln

    def _assemble(self, rid, limit=CHILD_READ_MAX):
        """rebuild transactions / packets of a row span.
        returns (txns, items) where items is [("txn", Txn) | ("pkt", dict) | ("rec", type, payload)]"""
        off = self.r_off[rid]
        ln = min(self.r_len[rid], limit)
        blob = self._read(off, ln)
        seg = self._seg_for(off)
        bt = (1 / 12.0) if seg[2] else (1 / 1.5)
        idx = self.r_pkt[rid]
        txns = []
        items = []
        cur = None

        def done():
            nonlocal cur
            txns.append(cur)
            items.append(("txn", cur))
            cur = None

        for p, t, pl in self.iter_records(blob):
            if t == P.REC_PACKET:
                ts, nbits, flags = _PKT_HDR.unpack_from(pl, 0)
                d = bytes(pl[12:])
                pid = d[1] & 0xF if len(d) >= 2 else -1
                pk = {"idx": idx, "ts": self._rel(ts, seg), "dur": nbits * bt, "nbits": nbits, "flags": flags,
                      "data": d, "pid": pid}
                idx += 1
                if flags or len(d) < 2:
                    if cur is not None:
                        cur.pkts.append(pk)
                        cur.err |= flags or P.PKT_ERR_SIZE
                        cur.end = off + p + 4 + len(pl)
                        continue
                    items.append(("pkt", pk))
                    continue
                if IS_TOKEN[pid] and len(d) >= 4:
                    if cur is not None:
                        done()
                    a, e = P.token_fields(d)
                    cur = Txn(off + p, off + p + 4 + len(pl), pk["ts"], pk["idx"], pid, a, e)
                    cur.pkts = [pk]
                    continue
                if IS_DATA[pid] and cur is not None and cur.dpid < 0 and cur.hs < 0:
                    cur.dpid = pid
                    cur.dlen = len(d) - 4
                    cur.payload = d[2:-2]
                    cur.pkts.append(pk)
                    cur.end = off + p + 4 + len(pl)
                    continue
                if IS_HS[pid] and cur is not None and cur.hs < 0:
                    cur.hs = pid
                    cur.pkts.append(pk)
                    cur.end = off + p + 4 + len(pl)
                    done()
                    continue
                if cur is not None:
                    done()
                items.append(("pkt", pk))
            elif t != P.REC_STATUS and not (t == P.REC_HOST_EVENT and pl[8] in PASSIVE_EVENTS):
                if cur is not None:
                    done()
                items.append(("rec", t, bytes(pl)))
        if cur is not None:
            done()
        return txns, items, seg

    # ------------------------------------------------------------- columns
    @staticmethod
    def _sp(seg):
        return "FS" if seg[2] else "LS"

    def _pkt_node(self, pk, sp):
        d = pk["data"]
        pid = pk["pid"]
        name = P.PID_NAMES.get(pid, "?") if len(d) >= 2 else "Invalid"
        dev = ep = ""
        # like Data Center: Len / Summary are the packet bytes on the wire, PID .. CRC (no SYNC)
        raw = d[1:]
        ln = P.fmt_len(len(raw)) if raw else ""
        summ = P.hexs(raw, MAX_PKT_HEX)
        cat = "pkt"
        if pid in P.TOKEN_PIDS and len(d) >= 4:
            a, e = P.token_fields(d)
            dev, ep = str(a), str(e)
            cat = {PID_IN: "in", PID_OUT: "out", PID_SETUP: "setup"}.get(pid, "pkt")
        elif pid == PID_SOF and len(d) >= 4:
            cat = "idle"
        elif pid in P.DATA_PIDS and len(d) >= 4:
            cat = "data"
        elif pid in P.HS_PIDS:
            cat = "nak" if pid == PID_NAK else ("err" if pid == PID_STALL else "hs")
        err = P.flags_str(pk["flags"])
        fl = RF_ERROR if pk["flags"] else 0
        cols = (sp, str(pk["idx"]), P.fmt_time(pk["ts"]), P.fmt_dur(pk["dur"]), ln, err, dev, ep,
                f"{name} packet", summ)
        return Node(cols, cat, fl, None, ("pkt", pk))

    @staticmethod
    def _txn_dur(first, final):
        lp = final.pkts[-1]
        return lp["ts"] + lp["dur"] - first.ts

    def _ptxn_cols(self, pt: PTxn, sp, record_prefix=""):
        f, t = pt.first, pt.final
        tname = P.PID_NAMES.get(t.pid, "?")
        nn = len(pt.naks)
        rec = f"{tname} txn"
        if pt.nak_only:
            rec += " [NAK]" if nn <= 1 else f" [{nn} POLL]"
        else:
            if nn:
                rec += f" [{nn} POLL]"
            if t.hs == PID_STALL:
                rec += " [STALL]"
            elif t.hs < 0:
                rec += " [no handshake]" if t.dpid >= 0 else " [no response]"
        if t.pid == PID_SETUP and t.payload is not None:
            summ = P.hexs(t.payload)
        elif t.dpid >= 0:
            summ = P.hexs(t.payload, 48) if t.payload else "ZLP"
        elif pt.nak_only:
            summ = "NAK"
        else:
            summ = P.PID_NAMES.get(t.hs, "")
        errs = set()
        for x in (pt.naks + [t]):
            for pk in x.pkts:
                if pk["flags"]:
                    errs.add(P.flags_str(pk["flags"]))
        ln = P.fmt_len(t.dlen) if t.dpid >= 0 else ""
        cols = (sp, str(f.pkt), P.fmt_time(f.ts), P.fmt_dur(self._txn_dur(f, t)), ln, ",".join(sorted(errs)),
                str(t.dev), str(t.ep), record_prefix + rec, summ)
        fl = txn_flags(t)
        if pt.nak_only:
            fl |= RF_NAK
        cat = {PID_IN: "in", PID_OUT: "out", PID_SETUP: "setup"}.get(t.pid, "pkt")
        return cols, cat, fl

    def _ptxn_node(self, pt: PTxn, sp, prefix=""):
        cols, cat, fl = self._ptxn_cols(pt, sp, prefix)

        def kids():
            out = []
            if pt.naks and not pt.nak_only:
                out.append(self._poll_node(pt.naks, sp))
            if pt.nak_only:
                if len(pt.naks) > 1:
                    return [self._poll_node(pt.naks, sp)]
                return [self._pkt_node(pk, sp) for pk in pt.final.pkts]
            out += [self._pkt_node(pk, sp) for pk in pt.final.pkts]
            return out

        return Node(cols, cat, fl, kids, ("txn", pt))

    def _poll_node(self, naks, sp):
        f, l = naks[0], naks[-1]
        tname = P.PID_NAMES.get(f.pid, "?")
        cols = (sp, str(f.pkt), P.fmt_time(f.ts), P.fmt_dur(self._txn_dur(f, l)), "", "", str(f.dev), str(f.ep),
                f"[{len(naks)} POLL]", f"{len(naks)} x {tname}-NAK")

        def kids():
            out = []
            for x in naks[:MAX_CHILDREN]:
                n = self._ptxn_node(PTxn(x, [x]), sp)
                out.append(n)
            if len(naks) > MAX_CHILDREN:
                out.append(Node(("", "", "", "", "", "", "", "", "...", f"{len(naks) - MAX_CHILDREN} more"), "idle"))
            return out

        return Node(cols, "nak", RF_NAK | RF_IDLE, kids, ("polls", naks))

    # --------------------------------------------------------------- render
    def render(self, i):
        return self.top_node(i).cols

    def top_node(self, i) -> Node:
        c = self._cache.get(i)
        if c is not None:
            return c
        try:
            r = self._top_node(i)
        except Exception as e:  # never break the view on a bad record
            r = Node(("", str(i), "", "", "", "ERR", "", "", "?", f"render error: {e}"), "err", RF_ERROR)
        if len(self._cache) > 4000:
            self._cache.clear()
        self._cache[i] = r
        return r

    def _filter_txns(self, rid, txns):
        k = self.r_kind[rid]
        dev = self.r_dev[rid]
        if k == K_CTRL:
            return [t for t in txns if t.dev == dev and t.ep == 0]
        if k == K_MSC:
            e = self.r_ep[rid]
            o, n = e & 0xF, e >> 4
            return [t for t in txns if t.dev == dev and t.ep and
                    ((t.pid == PID_OUT and t.ep == o) or (t.pid == PID_IN and (n == 0 or t.ep == n)))]
        ep = self.r_ep[rid]
        sel = [t for t in txns if t.dev == dev and t.ep == ep]
        if sel:
            pid = sel[-1].pid
            sel = [t for t in sel if t.pid == pid]
        return sel

    def _top_node(self, i) -> Node:
        kind = self.r_kind[i]
        off = self.r_off[i]
        fl = self.r_flags[i]
        seg = self._seg_for(off)
        sp = self._sp(seg)
        idx = str(self.r_pkt[i])

        if kind == K_TXN:
            txns, items, seg = self._assemble(i)
            sel = self._filter_txns(i, txns)
            if not sel:
                return Node((sp, idx, "", "", "", "", "", "", "?", "empty transaction"), "err", RF_ERROR)
            final = sel[-1]
            naks = [t for t in sel[:-1] if t.hs == PID_NAK]
            if final.hs == PID_NAK:
                naks = sel
            pt = PTxn(final, naks)
            n = self._ptxn_node(pt, sp)
            n.flags = fl
            return n

        if kind == K_CTRL:
            return self._ctrl_node(i, sp, idx, fl)
        if kind == K_MSC:
            return self._msc_node(i, sp, idx, fl)

        if kind in (K_SOFGRP, K_KAGRP):
            aux = self.r_aux[i]
            blob_tail = self._read(off + max(0, self.r_len[i] - 20), min(20, self.r_len[i]))
            t0 = _U64.unpack_from(self._read(off + 4, 8), 0)[0]
            t1 = t0
            if kind == K_SOFGRP and len(blob_tail) == 20 and blob_tail[0] == P.MAGIC:
                t1 = _U64.unpack_from(blob_tail, 4)[0]
            elif kind == K_KAGRP and len(blob_tail) >= 12 and blob_tail[-12] == P.MAGIC:
                t1 = _U64.unpack_from(blob_tail, len(blob_tail) - 8)[0]
            if kind == K_SOFGRP:
                cnt, f1, f2 = aux & 0x3FF, (aux >> 10) & 0x7FF, aux >> 21
                rec = f"[{cnt} SOF]"
                summ = f"[Frames: {f1} - {f2}]" if cnt > 1 else f"[Frame: {f1}]"
            else:
                cnt = aux
                rec = f"[{cnt} Keep-alive]"
                summ = "LS EOP"

            def kids():
                _, items, _s = self._assemble(i)
                out = []
                for it in items:
                    if it[0] == "pkt" and it[1]["pid"] == PID_SOF:
                        out.append(self._pkt_node(it[1], sp))
                    elif it[0] == "rec" and it[1] == P.REC_KEEPALIVE:
                        ts = self._rel(_U64.unpack_from(it[2], 0)[0], seg)
                        out.append(Node((sp, "", P.fmt_time(ts), "", "", "", "", "", "Keep-alive", "LS EOP"), "idle",
                                        RF_IDLE))
                return out

            cols = (sp, idx, P.fmt_time(self._rel(t0, seg)), P.fmt_dur(t1 - t0) if t1 > t0 else "",
                    "", "", "", "", rec, summ)
            return Node(cols, "idle", fl, kids, ("grp", kind))

        blob = self._read(off, self.r_len[i])
        t = blob[1]
        pl = blob[4:]

        if kind == K_PACKET:
            ts, nbits, flags = _PKT_HDR.unpack_from(pl, 0)
            d = bytes(pl[12:])
            pk = {"idx": self.r_pkt[i], "ts": self._rel(ts, seg), "dur": nbits * ((1 / 12.0) if seg[2] else (1 / 1.5)),
                  "nbits": nbits, "flags": flags, "data": d, "pid": d[1] & 0xF if len(d) >= 2 else -1}
            n = self._pkt_node(pk, sp)
            if flags:
                n.cols = n.cols[:8] + (n.cols[8].replace(" packet", " packet (error)"),) + n.cols[9:]
            n.flags |= fl
            return n

        ev = ("", idx) if kind != K_FOLD else (sp, idx)
        if kind == K_FOLD:
            t1, t2, sof, ff, fl_, ka, other, n = struct.unpack_from("<QQIHHIIB", pl, 0)
            parts = []
            recs = []
            total_nak = other
            eps = []
            for k in range(n):
                ad, ep_, cnt = struct.unpack_from("<BBI", pl, 33 + 6 * k)
                total_nak += cnt
                eps.append((ad, ep_, cnt))
            if sof:
                recs.append(f"[{sof} SOF]")
                parts.append(f"[Frames: {ff} - {fl_}]")
            if ka:
                recs.append(f"[{ka} Keep-alive]")
            if total_nak:
                recs.append(f"[{total_nak} IN-NAK]")
                parts.append("IN-NAK " + ", ".join(f"{a}/{e} x{c}" for a, e, c in eps)
                             + (f", other x{other}" if other else ""))
            dev = ep = ""
            if n == 1 and not other:
                dev, ep = str(eps[0][0]), str(eps[0][1])
            ts0 = P.fmt_time(self._rel(t1, seg))

            def kids():
                out = []
                if sof:
                    out.append(Node((sp, "", ts0, P.fmt_dur(t2 - t1), "", "", "", "", f"[{sof} SOF]",
                                     f"[Frames: {ff} - {fl_}]"), "idle", RF_IDLE))
                if ka:
                    out.append(Node((sp, "", ts0, "", "", "", "", "", f"[{ka} Keep-alive]", "LS EOP"), "idle", RF_IDLE))
                for a, e, c in eps:
                    out.append(Node((sp, "", "", "", "", "", str(a), str(e), f"IN txn [{c} POLL]",
                                     f"{c} x IN-NAK (folded by the sniffer)"), "nak", RF_NAK | RF_IDLE))
                if other:
                    out.append(Node((sp, "", "", "", "", "", "", "", f"IN txn [{other} POLL]", "other endpoints"),
                                    "nak", RF_NAK | RF_IDLE))
                return out

            return Node((sp, idx, ts0, P.fmt_dur(t2 - t1) if t2 > t1 else "", "", "", dev, ep, " ".join(recs) or "[idle]",
                         "; ".join(parts)), "idle", fl, kids, ("fold", bytes(pl)))
        if kind == K_RESET:
            ts = _U64.unpack_from(pl, 0)[0]
            return Node((sp, idx, P.fmt_time(self._rel(ts, seg)), "", "", "", "", "", "Bus Reset", "SE0 > 2.5 us"),
                        "reset", fl)
        if kind == K_KEEPALIVE:
            ts = _U64.unpack_from(pl, 0)[0]
            return Node((sp, idx, P.fmt_time(self._rel(ts, seg)), "", "", "", "", "", "Keep-alive", "LS EOP"),
                        "idle", fl)
        if kind == K_SYNCERR:
            ts, size = struct.unpack_from("<QI", pl, 0)
            return Node((sp, idx, P.fmt_time(self._rel(ts, seg)), "", "", "SYNC", "", "", "Sync error",
                         f"raw size 0x{size:08X} - wrong speed setting?"), "err", fl)
        if kind == K_DROP:
            ts, total, delta = struct.unpack_from("<QII", pl, 0)
            return Node((sp, idx, P.fmt_time(self._rel(ts, seg)), "", "", "DROP", "", "", "Packets lost",
                         f"{delta} packets dropped (device buffer overflow), total {total}"), "err", fl)
        # events
        if t == P.REC_START:
            ts, spd, fsof, fnak, auto, line = struct.unpack_from("<QBBBBB", pl, 0)
            ln = {0: "no idle state detected!", 1: "J=FS", 2: "J=LS"}.get(line, "?")
            return Node(("", idx, P.fmt_time(self._rel(ts, seg)), "", "", "", "", "", "Capture started",
                         f"{'Full' if spd else 'Low'} Speed{' (auto)' if auto else ''}, line {ln}, "
                         f"fold SOF={'on' if fsof else 'off'}, fold IN-NAK={'on' if fnak else 'off'}"), "event", fl)
        if t == P.REC_STOP:
            ts, reason = struct.unpack_from("<QB", pl, 0)
            return Node(("", idx, P.fmt_time(self._rel(ts, seg)), "", "", "", "", "", "Capture stopped",
                         "by command" if reason == 0 else "host disconnected"), "event", fl)
        if t == P.REC_INFO:
            proto, fw, clk, ring, dp, dm = struct.unpack_from("<HHIIBB", pl, 0)
            txt = bytes(pl[14:]).decode("ascii", "replace")
            return Node(("", idx, "", "", "", "", "", "", "Device info",
                         f"{txt}; proto v{proto} fw v{fw}, clk {clk / 1e6:.0f} MHz, ring {ring * 4 // 1024} KB, "
                         f"D+=GP{dp} D-=GP{dm}"), "event", fl)
        if t == P.REC_TEXT:
            return Node(("", idx, "", "", "", "", "", "", "Device message", bytes(pl).decode("utf-8", "replace")),
                        "event", fl)
        if t == P.REC_HOST_EVENT:
            ht = _U64.unpack_from(pl, 0)[0]
            code = pl[8]
            txt = bytes(pl[9:]).decode("utf-8", "replace")
            names = {P.HE_SESSION: "Session", P.HE_SEGMENT: "Start request", P.HE_DISCONNECT: "Disconnected",
                     P.HE_RECONNECT: "Reconnected", P.HE_USER_STOP: "Stop request", P.HE_NOTE: "Note"}
            wall = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ht / 1e6))
            rel = P.fmt_time(ht - self.session_host0) if self.session_host0 is not None else ""
            return Node(("", idx, rel, "", "", "ERR" if code == P.HE_DISCONNECT else "", "", "",
                         names.get(code, "Host event"), f"{wall}  {txt}"), "event", fl)
        return Node(ev + ("", "", "", "", "", "", f"record 0x{t:02X}", P.hexs(bytes(pl))), "event", fl)

    # control transfer row
    def _ctrl_node(self, i, sp, idx, fl):
        txns, items, seg = self._assemble(i)
        sel = self._filter_txns(i, txns)
        pts = merge_polls(sel)
        aux = self.r_aux[i]
        state = aux >> 28
        setup = None
        if sel and sel[0].pid == PID_SETUP and sel[0].payload is not None and len(sel[0].payload) >= 8:
            setup = U.Setup(sel[0].payload)
        data = bytearray()
        if setup is not None and setup.len:
            dpid = PID_IN if setup.dir_in else PID_OUT
            for t in sel[1:]:
                if t.pid == dpid and t.hs == PID_ACK and t.payload:
                    data += t.payload
        data = bytes(data)
        if setup is not None:
            rec = U.request_name(setup)
            summ = U.request_summary(setup, data)
        else:
            rec = "Control transfer"
            summ = "invalid SETUP"
        if state == 1:
            rec += " [STALL]"
        elif state == 2:
            rec += " [incomplete]"
        first = sel[0] if sel else None
        last = sel[-1] if sel else None
        dur = self._txn_dur(first, last) if first else 0
        errs = set()
        for t in sel:
            for pk in t.pkts:
                if pk["flags"]:
                    errs.add(P.flags_str(pk["flags"]))
        cols = (sp, idx, P.fmt_time(first.ts) if first else "", P.fmt_dur(dur), P.fmt_len(aux & 0x0FFFFFFF),
                ",".join(sorted(errs)), str(self.r_dev[i]), "0", rec, summ)

        def kids():
            return [self._ptxn_node(pt, sp) for pt in pts[:MAX_CHILDREN]]

        return Node(cols, "ctrl", fl, kids, ("ctrl", setup, data, state))

    # mass storage command row
    def _msc_node(self, i, sp, idx, fl):
        big = self.r_len[i] > CHILD_READ_MAX
        txns, items, seg = self._assemble(i)
        sel = self._filter_txns(i, txns)
        aux = self.r_aux[i]
        status = aux >> 30
        dlen = aux & 0x3FFFFFFF
        cbw = None
        raw_cbw = None
        if sel and sel[0].payload is not None and U.is_cbw(sel[0].payload):
            raw_cbw = sel[0].payload
            cbw = U.CBW(raw_cbw)
        csw = sel[-1].payload if sel and U.is_csw(sel[-1].payload) else None
        data = bytearray()
        for t in sel[1:-1] if csw is not None else sel[1:]:
            if t.hs == PID_ACK and t.payload and len(data) < (1 << 20):
                data += t.payload
        data = bytes(data)
        if cbw is not None:
            rec = f"{cbw.name} [{cbw.lun}]"
            st = U.CSW_STATUS.get(status, "no status")
            extra = U.scsi_data_summary(cbw, data) or U.cdb_summary(cbw)
            summ = f"{extra} ({st})" if extra else st
        else:
            rec = "Mass storage command"
            summ = ""
        if status == 3:
            rec += " [incomplete]"
        first, last = (sel[0], sel[-1]) if sel else (None, None)
        dur = self._txn_dur(first, last) if first else 0
        e = self.r_ep[i]
        cols = (sp, idx, P.fmt_time(first.ts) if first else "", P.fmt_dur(dur), P.fmt_len(dlen), "",
                str(self.r_dev[i]), str(e & 0xF), rec, summ)

        def kids():
            pts = merge_polls(sel)
            if not pts:
                return []
            out = [self._ptxn_node(pts[0], sp)]
            mid = pts[1:-1] if csw is not None else pts[1:]
            if len(mid) > 1:
                f0, l0 = mid[0].first, mid[-1].final
                n_bytes = sum(p.final.dlen for p in mid if p.final.hs == PID_ACK)
                cols2 = (sp, str(f0.pkt), P.fmt_time(f0.ts), P.fmt_dur(self._txn_dur(f0, l0)), P.fmt_len(n_bytes), "",
                         str(f0.dev), str(f0.ep), f"Data phase [{len(mid)} txn]",
                         f"{'IN' if mid[0].final.pid == PID_IN else 'OUT'} {n_bytes} bytes")
                out.append(Node(cols2, "in" if mid[0].final.pid == PID_IN else "out", 0,
                                lambda: [self._ptxn_node(p, sp) for p in mid[:MAX_CHILDREN]], ("data", data)))
            else:
                out += [self._ptxn_node(p, sp) for p in mid]
            if csw is not None:
                out.append(self._ptxn_node(pts[-1], sp))
            if big:
                out.append(Node(("", "", "", "", "", "", "", "", "...", "transfer truncated for display"), "idle"))
            return out

        return Node(cols, "msc", fl, kids, ("msc", raw_cbw, data, csw))

    # -------------------------------------------------------------- details
    def describe(self, node: Node):
        """-> (tree, hex bytes, hex title) for the detail panes"""
        info = node.info
        if not info:
            return [], b"", ""
        k = info[0]
        if k == "pkt":
            pk = info[1]
            d = pk["data"]
            pid = pk["pid"]
            f = [("PID", f"0x{d[1]:02X} {P.PID_NAMES.get(pid, '?')}" if len(d) >= 2 else "-", []),
                 ("Time", P.fmt_time(pk["ts"]), []),
                 ("Bits", f"{pk['nbits']} ({P.fmt_dur(pk['dur'])})", []),
                 ("Errors", P.flags_str(pk["flags"]) or "none", [])]
            if pid in P.TOKEN_PIDS and len(d) >= 4:
                a, e = P.token_fields(d)
                f += [("Address", str(a), []), ("Endpoint", str(e), []), ("CRC5", f"0x{d[3] >> 3:02X}", [])]
            elif pid == PID_SOF and len(d) >= 4:
                f += [("Frame", str(((d[3] << 8) | d[2]) & 0x7FF), []), ("CRC5", f"0x{d[3] >> 3:02X}", [])]
            elif pid in P.DATA_PIDS and len(d) >= 4:
                f += [("Data length", str(len(d) - 4), []), ("CRC16", f"0x{d[-2] | (d[-1] << 8):04X}", [])]
            f.append(("Raw (SYNC..)", P.hexs(d, 2000), []))
            raw = d[1:]  # PID .. CRC, as on the wire (Data Center "Details")
            return [(node.cols[8], "", f)], raw, f"{node.cols[8]} ({len(raw)} bytes)"
        if k == "txn":
            pt = info[1]
            t = pt.final
            f = [("Token", f"{P.PID_NAMES.get(t.pid, '?')} Addr={t.dev} Endp={t.ep}", []),
                 ("Data", (f"{P.PID_NAMES.get(t.dpid)} {t.dlen} bytes" if t.dpid >= 0 else "none"), []),
                 ("Handshake", P.PID_NAMES.get(t.hs, "none") if t.hs >= 0 else "none", [])]
            if pt.naks and not pt.nak_only:
                f.append(("NAK retries (POLL)", str(len(pt.naks)), []))
            tree = [(node.cols[8], "", f)]
            if t.pid == PID_SETUP and t.payload and len(t.payload) >= 8:
                s = U.Setup(t.payload)
                tree.append(("Setup packet", U.request_name(s), U.setup_tree(s)))
            if t.payload and U.is_cbw(t.payload):
                tree += U.cbw_tree(U.CBW(t.payload), t.payload)
            if t.payload and U.is_csw(t.payload):
                tree += U.csw_tree(t.payload)
            return tree, t.payload or b"", f"{P.PID_NAMES.get(t.dpid, 'data')} ({t.dlen} bytes)"
        if k == "polls":
            naks = info[1]
            return [("POLL", f"{len(naks)} NAK'd attempts", [
                ("First", P.fmt_time(naks[0].ts), []), ("Last", P.fmt_time(naks[-1].ts), [])])], b"", ""
        if k == "ctrl":
            _, setup, data, state = info
            tree = []
            if setup is not None:
                tree.append(("Setup packet", U.request_name(setup), U.setup_tree(setup)))
                st = {0: "Complete", 1: "STALL", 2: "Incomplete"}.get(state, "?")
                tree.append(("Status", st, []))
                if data:
                    if setup.type == 0 and setup.req == 6:
                        dt = setup.val >> 8
                        tree += U.descriptor_tree(dt, data, setup.val & 0xFF)
                    else:
                        tree.append(("Data stage", f"{len(data)} bytes", []))
            return tree, data, f"Data stage ({len(data)} bytes)"
        if k == "msc":
            _, raw, data, csw = info
            tree = []
            cbw = None
            if raw:
                cbw = U.CBW(raw)
                tree += U.cbw_tree(cbw, raw)
            if cbw is not None and data:
                tree += U.scsi_data_tree(cbw, data)
            if data:
                tree.append(("Data phase", f"{len(data)} bytes", []))
            if csw:
                tree += U.csw_tree(csw)
            return tree, data, f"Data phase ({len(data)} bytes)"
        if k == "data":
            return [("Data phase", f"{len(info[1])} bytes", [])], info[1], f"Data ({len(info[1])} bytes)"
        if k == "fold":
            return [("Folded idle traffic", node.cols[8], [("Detail", node.cols[9], [])])], b"", ""
        return [], b"", ""

    # ----------------------------------------------------------------- filter
    def match(self, i, f: RowFilter) -> bool:
        fl = self.r_flags[i]
        if f.errors_only and not (fl & RF_ERROR):
            return False
        if f.hide_idle and (fl & RF_IDLE):
            return False
        if f.hide_nak and (fl & RF_NAK):
            return False
        if f.dev >= 0 and self.r_dev[i] != f.dev:
            return False
        if f.ep >= 0:
            e = self.r_ep[i]
            if self.r_kind[i] == K_MSC:
                if f.ep != (e & 0xF) and f.ep != (e >> 4):
                    return False
            elif e != f.ep:
                return False
        return True

    # ---------------------------------------------------------- statistics
    _ST_GROUPS = (
        ("Tokens", (("IN", P.PID_IN), ("OUT", P.PID_OUT), ("SETUP", P.PID_SETUP), ("SOF", P.PID_SOF),
                    ("PING", P.PID_PING))),
        ("Handshakes", (("ACK", P.PID_ACK), ("NAK", P.PID_NAK), ("STALL", P.PID_STALL), ("NYET", P.PID_NYET))),
        ("Data", (("DATA0", P.PID_DATA0), ("DATA1", P.PID_DATA1), ("DATA2", P.PID_DATA2), ("MDATA", P.PID_MDATA))),
        ("Special", (("PRE/ERR", P.PID_PRE), ("SPLIT", P.PID_SPLIT), ("RESERVED", P.PID_RSVD))),
    )

    @classmethod
    def _st_packets(cls, c, extra_special=()):
        groups = []
        for gname, items in cls._ST_GROUPS:
            kids = [(n, c[pid], []) for n, pid in items]
            if gname == "Special":
                kids += list(extra_special)
            groups.append((gname, sum(k[1] for k in kids), kids))
        return ("Packets", sum(g[1] for g in groups), groups)

    @staticmethod
    def _st_ctrl(c):
        n = sum(c[:4])
        return ("Control Transfers", n, [
            ("By Type", n, [(k, c[i], []) for i, k in enumerate(("Standard", "Class", "Vendor", "Reserved"))]),
            ("By Recipient", n, [(k, c[4 + i], []) for i, k in enumerate(("Device", "Interface", "Endpoint",
                                                                          "Other"))]),
        ])

    def stats_tree(self):
        """-> [(name, count, kids)] for the Statistics pane: the whole bus, then each device."""
        with self.lock:
            pid = {k: list(v) for k, v in self.st_pid.items()}
            ctrl = {k: list(v) for k, v in self.st_ctrl.items()}
            err = list(self.st_err)
            err_pkts, ka, rst, serr = self.st_err_pkts, self.st_keepalive, self.st_reset, self.st_syncerr
            drop = self.device_dropped
            devs = dict(self.devices)
        tot = [sum(v[i] for v in pid.values()) for i in range(16)]
        ctot = [sum(v[i] for v in ctrl.values()) for i in range(8)]
        flags = [(name, err[bit.bit_length() - 1], []) for bit, name in P.FLAG_NAMES]
        errors = ("Errors", err_pkts + serr + drop, [
            ("Packets with errors", err_pkts, flags),
            ("Sync errors (firmware)", serr, []),
            ("Dropped by device", drop, []),
        ])
        bus = [self._st_packets(tot, [("Keep-alive (LS EOP)", ka, []), ("Bus reset", rst, [])]),
               self._st_ctrl(ctot), errors]
        out = [("All devices", sum(tot) + err_pkts, bus)]
        for a in sorted(k for k in pid if k >= 0):
            c = pid[a]
            title = f"Device {a}"
            dd = (devs.get(a) or {}).get("device")
            if dd and len(dd) >= 18:
                title += f"  ({U.u16(dd, 8):04X}:{U.u16(dd, 10):04X})"
            out.append((title, sum(c), [self._st_packets(c), self._st_ctrl(ctrl.get(a, [0] * 8))]))
        return out

    # ------------------------------------------------------------- devices
    def device_tree(self):
        out = []
        with self.lock:
            devs = sorted(self.devices.items())
        for a, d in devs:
            dd = d["device"]
            st = d["strings"]
            title = f"Device {a}"
            kids = []
            if dd and len(dd) >= 18:
                title += f"  VID {U.u16(dd, 8):04X} PID {U.u16(dd, 10):04X}"
                for name, si in (("Manufacturer", dd[14]), ("Product", dd[15]), ("Serial", dd[16])):
                    if si and si in st:
                        kids.append((name, st[si], []))
                prod = st.get(dd[15])
                if prod:
                    title += f"  \"{prod}\""
            if d["cfg"] is not None:
                kids.append(("Configuration", str(d["cfg"]), []))
            if d["max_lun"] is not None:
                kids.append(("Max LUN", str(d["max_lun"]), []))
            if dd:
                kids += U.descriptor_tree(1, dd)
            if d["config"]:
                kids += U.descriptor_tree(2, d["config"])
            for itf, rep in d["hid"].items():
                kids.append((f"HID Report Descriptor (interface {itf})", f"{len(rep)} bytes", U.hid_report_tree(rep)))
            other = [(f"String {k}", v, []) for k, v in sorted(st.items())]
            if other:
                kids.append(("Strings", "", other))
            out.append((title, "", kids))
        # addresses seen on the bus whose enumeration is not in this capture
        known = {a for a, _d in devs}
        for a in sorted(k for k in list(self.st_pid) if k >= 0 and k not in known):
            out.append((f"Device {a}", "Unknown device (enumeration not captured)", []))
        return out
