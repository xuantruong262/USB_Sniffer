"""
Pico USB Sniffer - CSV export in the layout of a Total Phase Data Center CSV.

  # comment lines, the last one is the column list
  Level,Sp,Index,m:s.ms.us,Dur,Len,Err,Dev,Ep,Record,Summary

Rules taken from a Data Center v8.10 export:
  * CRLF, UTF-8 without BOM, a value is quoted only when it contains a comma / quote
  * Index is unique: every record is numbered, also the ones inside a collapsed
    row, so a record keeps its Index whatever the filter / expansion is.
    (It is not the packet number shown in the Index column of the GUI.)
  * Record is indented by 3 spaces per level, "IN txn   [2 POLL]"
  * Dev / Ep are decimal with at least 2 digits, Len is "34 B"
  * Dur is "2.833 us" or "1.031.833 ms" (ms.us.ns)
  * transaction / packet data is cut after 24 bytes (one "..." character)
    unless full_data is set
  * [N SOF] and [N IN-NAK] are separate records without children

Err uses the Data Center letters (Total Phase, "Transaction Window"):
  0 bad bit-stuff   B bad signals (SYNC)   C bad CRC   I invalid PID / sequence
  L improper packet length   P partial last byte   S buffer (truncated / lost)
  U unexpected (connection to the sniffer lost)

A record folded by the firmware only has the time of its first and last packet,
so the single SOF / IN-NAK inside it have no individual times: capture with the
Fold options off when they matter.
"""
from __future__ import annotations

import csv
import re
import struct
import time

import capture as C
import protocol as P

DATA_LIMIT = 24
COLUMNS = ["Level", "Sp", "Index", "m:s.ms.us", "Dur", "Len", "Err", "Dev", "Ep", "Record", "Summary"]
ERR_CODES = {"STUFF": "0", "CRC": "C", "PID": "I", "SYNC": "B", "NBIT": "P", "SIZE": "L", "TRUNC": "S",
             "DROP": "S", "ERR": "U"}
# host / device notes that Data Center has no record for: written as comments
NOTE_RECORDS = ("Session", "Start request", "Stop request", "Device info", "Device message")


class Cancelled(Exception):
    pass


def fmt_dur(us) -> str:
    if us is None:
        return ""
    a, b = divmod(round(us * 1000), 1000)
    if a < 1000:
        return f"{a}.{b:03d} us"
    if a < 1_000_000:
        return f"{a // 1000}.{a % 1000:03d}.{b:03d} ms"
    return f"{a // 1_000_000}.{a // 1000 % 1000:03d}.{a % 1000:03d} s"


def fmt_addr(s: str) -> str:
    return f"{int(s):02d}" if s.isdigit() else s


def fmt_err(names: str) -> str:
    return "".join(sorted({ERR_CODES.get(n, "U") for n in names.split(",") if n}))


def _frames(a, b, n):
    return f"[Frames: {a} - {b}] " if n > 1 else f"[Frame: {a}] "


class Exporter:
    def __init__(self, store, full_data=False):
        self.st = store
        self.limit = None if full_data else DATA_LIMIT
        self.index = 0

    # ----------------------------------------------------------- formatting
    def _hex(self, b) -> str:
        if not b:
            return ""
        if self.limit is not None and len(b) > self.limit:
            return bytes(b[:self.limit]).hex(" ").upper() + "…"
        return bytes(b).hex(" ").upper()

    @staticmethod
    def _in_naks(node):
        """number of IN-NAK if the record is only that ([N IN-NAK], no children), else 0"""
        k = node.info[0] if node.info else ""
        if k == "polls" and node.info[1][0].pid == P.PID_IN:
            return len(node.info[1])
        if k == "txn" and node.info[1].nak_only and node.info[1].final.pid == P.PID_IN:
            return max(1, len(node.info[1].naks))
        return 0

    def _row(self, level, node, dur=-1, record=None, summary=None, err=None, addr=None):
        c = node.cols
        ln, rec, summ = c[4], c[8], c[9]
        kind = node.info[0] if node.info else ""
        naks = self._in_naks(node)
        if naks:
            rec, summ, ln = f"[{naks} IN-NAK]", "", ""
        elif kind == "txn":
            rec = rec.replace(" [", "   [")
            t = node.info[1].final
            summ = self._hex(t.payload) if t.dpid >= 0 else ""
        elif kind == "pkt":
            rec = rec.replace(" (error)", "")
            summ = self._hex(node.info[1]["data"][1:])
        elif kind == "polls":
            rec, summ = f"[{len(node.info[1])} {P.PID_NAMES.get(node.info[1][0].pid, '?')}-NAK]", ""
        if dur == -1:
            dur = getattr(c[3], "us", None)
        dev, ep = addr or (c[6], c[7])  # DATA / handshake packets: address of their transaction
        return [level, c[0], self.index, c[2], fmt_dur(dur), ln, fmt_err(c[5]) if err is None else err,
                fmt_addr(dev), fmt_addr(ep), "   " * level + (rec if record is None else record),
                summ if summary is None else summary]

    # ------------------------------------------------------------ tree walk
    def _tree(self, node, level, shown, expanded, err=None, addr=None):
        """number the record and everything below it; yield the rows to write.
        expanded: True = all levels, None = collapsed, dict = {child position: its expansion}"""
        if shown:
            yield self._row(level, node, err=err, addr=addr)
        self.index += 1
        kind = node.info[0] if node.info else ""
        if not node.kids or kind == "grp" or self._in_naks(node):
            return
        if kind == "txn" and expanded is None:
            # hidden packets are only counted, same numbers as the walk below
            pt = node.info[1]
            if pt.naks and not (pt.nak_only and len(pt.naks) == 1):
                self.index += 1
                if pt.final.pid != P.PID_IN:
                    self.index += sum(1 + len(t.pkts) for t in pt.naks[:C.MAX_CHILDREN])
                    self.index += len(pt.naks) > C.MAX_CHILDREN
                if pt.nak_only:
                    return
            self.index += len(pt.final.pkts)
            return
        own = (node.cols[6], node.cols[7]) if kind == "txn" else None
        for pos, kid in enumerate(node.kids()):
            sub = True if expanded is True else (expanded or {}).get(pos)
            yield from self._tree(kid, level + 1, shown and expanded is not None, sub, addr=own)

    # ---------------------------------------------------------- special rows
    def _fold(self, i, shown):
        st = self.st
        pl = st._read(st.r_off[i], st.r_len[i])[4:]
        t1, t2, sof, f1, f2, ka, other, n = struct.unpack_from("<QQIHHIIB", pl, 0)
        seg = st._seg_for(st.r_off[i])
        ts = P.fmt_time(st._rel(t1, seg))
        span = t2 - t1 if t2 > t1 else None
        recs = []
        if sof:
            recs.append((sof, "", "", f"[{sof} SOF]", _frames(f1, f2, sof)))
        if ka:
            recs.append((ka, "", "", f"[{ka} Keep-alive]", ""))
        for k in range(n):
            a, e, cnt = struct.unpack_from("<BBI", pl, 33 + 6 * k)
            recs.append((cnt, f"{a:02d}", f"{e:02d}", f"[{cnt} IN-NAK]", ""))
        if other:
            recs.append((other, "", "", f"[{other} IN-NAK]", ""))
        for cnt, dev, ep, rec, summ in recs:
            if shown:
                yield [0, st._sp(seg), self.index, ts, fmt_dur(span if cnt > 1 else None), "", "", dev, ep, rec, summ]
            self.index += 1

    def _sof_group(self, i, node, shown):
        st = self.st
        off, ln, aux = st.r_off[i], st.r_len[i], st.r_aux[i]
        cnt, f1, f2 = aux & 0x3FF, (aux >> 10) & 0x7FF, aux >> 21
        dur = None
        tail = st._read(off + max(0, ln - 20), min(20, ln))  # the last SOF packet record
        if len(tail) == 20 and tail[0] == P.MAGIC and tail[1] == P.REC_PACKET:
            t0 = struct.unpack("<Q", st._read(off + 4, 8))[0]
            t1, nbits = struct.unpack_from("<QH", tail, 4)
            dur = t1 - t0 + nbits / (12.0 if st._seg_for(off)[2] else 1.5)
        if shown:
            yield self._row(0, node, dur, f"[{cnt} SOF]", _frames(f1, f2, cnt))
        self.index += 1

    def _wall(self, rel_us):
        h = self.st.session_host0
        return "" if h is None else time.strftime("[%m/%d/%y %H:%M:%S]", time.localtime((h + rel_us) / 1e6))

    def _is_note(self, i, node):
        return node.cols[8] in NOTE_RECORDS and not (self.st.r_flags[i] & C.RF_ERROR)

    def _event(self, i, node, shown):
        st = self.st
        if self._is_note(i, node):
            return  # in the header comments, not a record
        if shown:
            blob = st._read(st.r_off[i], st.r_len[i])
            if blob[1] in (P.REC_START, P.REC_STOP):
                rel = st._rel(struct.unpack_from("<Q", blob, 4)[0], st._seg_for(st.r_off[i]))
                yield self._row(0, node, summary=self._wall(rel))
            else:
                yield self._row(0, node)
        self.index += 1

    # -------------------------------------------------------------- output
    def header(self):
        st = self.st
        out = ["Pico USB Sniffer", "CSV layout: Total Phase Data Center", ""]
        for i in range(st.row_count()):
            if st.r_kind[i] == C.K_EVENT:
                n = st.top_node(i)
                if self._is_note(i, n) or n.cols[8] == "Capture started":
                    out.append(re.sub(r"[\r\n]+", " ", f"{n.cols[8]}: {n.cols[9]}"))
        return out + ["", ",".join(COLUMNS)]

    def rows(self, row_ids=None, expanded=None, progress=None):
        """row_ids: ascending rows to write (None = all). expanded(k) -> expansion of the k-th of them."""
        st = self.st
        ids = range(st.row_count()) if row_ids is None else row_ids
        last = ids[-1] + 1 if len(ids) else 0
        k = 0
        for i in range(last):
            if progress and i % 2000 == 0 and not progress(i, last):
                raise Cancelled
            shown = ids[k] == i
            exp = expanded(k) if shown and expanded else None
            if shown:
                k += 1
            kind = st.r_kind[i]
            if kind == C.K_FOLD:
                yield from self._fold(i, shown)
                continue
            if not shown and kind in (C.K_SOFGRP, C.K_KAGRP, C.K_PACKET):
                self.index += 1
                continue
            node = st.top_node(i)
            if kind == C.K_SOFGRP:
                yield from self._sof_group(i, node, shown)
            elif kind == C.K_EVENT:
                yield from self._event(i, node, shown)
            elif kind == C.K_PACKET:
                # a valid handshake / data packet without its token: invalid sequence
                pid = node.info[1]["pid"]
                stray = not node.cols[5] and (pid in P.HS_PIDS or pid in P.DATA_PIDS)
                yield from self._tree(node, 0, shown, exp, "I" if stray else None)
            else:
                yield from self._tree(node, 0, shown, exp)


def export_csv(store, path, row_ids=None, expanded=None, full_data=False, progress=None) -> int:
    """-> number of rows written. Raises Cancelled (progress returned False) or OSError."""
    ex = Exporter(store, full_data)
    n = 0
    with open(path, "w", encoding="utf-8", newline="") as f:
        for ln in ex.header():
            f.write(f"# {ln}".rstrip() + "\r\n")
        w = csv.writer(f, lineterminator="\r\n")
        for row in ex.rows(row_ids, expanded, progress):
            w.writerow(row)
            n += 1
    return n
