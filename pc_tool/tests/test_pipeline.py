"""Headless tests for protocol parsing / analyzer / capture store (no Qt, no hardware).

Run:  python tests/test_pipeline.py
"""
import os
import random
import re
import struct
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import protocol as P  # noqa: E402
import capture as C  # noqa: E402
import sources as S  # noqa: E402

FW = os.path.join(os.path.dirname(os.path.dirname(HERE)), "firmware", "usb_sniffer.c")
TMP = tempfile.mkdtemp()


def fw_tables():
    src = open(FW, encoding="utf-8").read()

    def tab(name):
        m = re.search(name + r"\[256\] = \{(.*?)\};", src, re.S)
        return [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", m.group(1))]

    return tab("crc16_usb_tab"), tab("crc5_usb_tab")


def test_crc_compat():
    t16, t5 = fw_tables()

    def fw_crc16(d):
        crc = 0xFFFF
        for b in d:
            crc = t16[(crc ^ b) & 0xFF] ^ (crc >> 8)
        return crc

    def fw_crc5(d):
        crc = 0xFF
        for b in d:
            crc = t5[(crc ^ b) & 0xFF] ^ (crc >> 8)
        return crc

    for _ in range(2000):
        a, e = random.randrange(128), random.randrange(16)
        tok = P.make_token(P.PID_IN, a, e)
        assert fw_crc5(tok[2:]) == 0x09, (a, e, tok.hex())
        assert P.token_fields(tok) == (a, e)
        sof = P.make_sof(random.randrange(2048))
        assert fw_crc5(sof[2:]) == 0x09
        pl = bytes(random.getrandbits(8) for _ in range(random.randrange(65)))
        d = P.make_data(P.PID_DATA1, pl)
        assert fw_crc16(d[2:]) == 0xB001
    print("crc compat OK (python generator matches firmware checker)")


# ---------------------------------------------------------------------------
def demo_stream(fold, steady_us=2_000_000, seed=3):
    rnd = random.Random(seed)
    b = S.DemoBus(1_000_000, fold, fold, rnd)
    b.out += P.build_record(P.REC_INFO, struct.pack("<HHIIBB", 1, 2, 120_000_000, 32768, 10, 11) + b"test")
    b.out += P.build_record(P.REC_START, struct.pack("<QBBBBB", 1_000_000, 1, fold, fold, 1, 1))
    S.demo_enumeration(b)
    S.demo_steady(b, rnd, steady_us, {})
    b.fold_flush()
    b.out += P.build_record(P.REC_STOP, struct.pack("<QB", b.t, 0))
    return bytes(b.out)


def feed_chunks(store, data, rnd, garbage=False):
    p = 0
    while p < len(data):
        n = rnd.randrange(1, 5000)
        chunk = data[p:p + n]
        if garbage and rnd.random() < 0.1:
            chunk = bytes([0xA5, 0x77, 0x01]) + chunk  # invalid header -> resync
        store.feed(chunk)
        if rnd.random() < 0.2:
            store.idle()  # serial read timeouts happen at random points
        p += n


def walk(node, depth=0):
    yield depth, node
    if node.kids:
        for k in node.kids():
            yield from walk(k, depth + 1)


def tree_of(st):
    return [[(d, n.cols) for d, n in walk(st.top_node(i))] for i in range(st.row_count())]


def make_store(data, name, garbage=False, seed=5):
    st = C.CaptureStore(os.path.join(TMP, name))
    st.host_event(P.HE_SESSION, "test")
    feed_chunks(st, data, random.Random(seed), garbage)
    st.close_writer()
    return st


def test_hierarchy():
    for fold in (True, False):
        st = make_store(demo_stream(fold, 500_000), f"h{int(fold)}.pusb")
        tops = [st.top_node(i) for i in range(st.row_count())]
        recs = [n.cols[8] for n in tops]
        summ = {n.cols[8] + " | " + n.cols[9] for n in tops}

        def has(rec, text=""):
            return any(s.startswith(rec) and text in s for s in summ)

        assert has("Get Device Descriptor", "VID=1209 PID=0001"), summ
        assert has("Set Address", "New address 5")
        assert has("Get Configuration Descriptor", "[HID, Mass Storage]")
        assert has("Get String Descriptor", '"Pico Demo"')
        assert has("Get String Descriptor", "Languages: 0x0409")
        assert has("Get Device Qualifier Descriptor [STALL]")
        assert has("Set Configuration", "Configuration=1")
        assert has("Get HID Report Descriptor", "63 bytes")
        assert has("Get Max LUN", "Max LUN = 0")
        assert has("Inquiry [0]", "PICODEMO Virtual Disk 1.00 (Passed)")
        assert has("Test Unit Ready [0]", "Failed")
        assert has("Request Sense [0]", "Unit Attention")
        assert has("Read Capacity(10) [0]", "Block=512")
        assert has("Read(10) [0]", "Blocks=8")
        assert "Bus Reset" in recs
        # hierarchy of a control transfer with 28 NAK polls in the data stage
        i = next(k for k, n in enumerate(tops) if '"Pico Demo"' in n.cols[9])
        kids = tops[i].kids()
        assert [k.cols[8] for k in kids] == ["SETUP txn", "IN txn [28 POLL]", "OUT txn"], [k.cols[8] for k in kids]
        assert [k.cols[8] for k in kids[1].kids()] == ["[28 POLL]", "IN packet", "DATA1 packet", "ACK packet"]
        assert len(kids[1].kids()[0].kids()) == 28
        assert [k.cols[8] for k in kids[0].kids()] == ["SETUP packet", "DATA0 packet", "ACK packet"]
        # mass storage command: CBW, data phase, CSW
        i = next(k for k, n in enumerate(tops) if n.cols[8] == "Read(10) [0]" and "Blocks=8" in n.cols[9])
        kids = tops[i].kids()
        assert kids[0].cols[8] == "OUT txn" and kids[1].cols[8] == "Data phase [64 txn]", [k.cols[8] for k in kids]
        assert kids[1].cols[4] == "4096 B" and tops[i].cols[4] == "4096 B"
        # details / descriptors decode without errors
        for n in tops:
            for _d, x in walk(n):
                st.describe(x)
        dev = st.devices[5]
        assert dev["strings"] == {1: "Pico Demo", 2: "Demo Keyboard + Disk", 3: "DEMO123456"}, dev["strings"]
        assert st.device_tree()[0][0].startswith("Device 5  VID 1209 PID 0001")
        # packet indices are global and increasing
        pk = [int(n.cols[1]) for n in tops if n.cols[1]]
        assert pk == sorted(pk)
        if not fold:
            assert any(r.startswith("[") and "SOF]" in r for r in recs)
            assert st.garbage_bytes == 0
        print(f"hierarchy OK (fold={fold}): {len(tops)} rows, {st.packets} packets")
        st.close()


def test_poll_and_interleave():
    """standalone poll merging and transfer ordering with interleaved traffic"""
    out = bytearray()
    t = 1000
    out += P.build_record(P.REC_START, struct.pack("<QBBBBB", t, 1, 0, 0, 0, 1))
    # 5 NAK then data on dev 2 ep 1
    for _ in range(5):
        out += P.packet_record(t, P.make_token(P.PID_IN, 2, 1))
        out += P.packet_record(t + 3, P.make_hs(P.PID_NAK))
        t += 100
    out += P.packet_record(t, P.make_token(P.PID_IN, 2, 1))
    out += P.packet_record(t + 3, P.make_data(P.PID_DATA0, b"\x01\x02"))
    out += P.packet_record(t + 9, P.make_hs(P.PID_ACK))
    t += 100
    # control transfer on dev 1 with an interrupt transaction of dev 2 in the middle
    out += P.packet_record(t, P.make_token(P.PID_SETUP, 1, 0))
    out += P.packet_record(t + 3, P.make_data(P.PID_DATA0, bytes([0x80, 6, 0, 1, 0, 0, 18, 0])))
    out += P.packet_record(t + 12, P.make_hs(P.PID_ACK))
    t += 50
    out += P.packet_record(t, P.make_token(P.PID_IN, 2, 1))
    out += P.packet_record(t + 3, P.make_data(P.PID_DATA1, b"\x03"))
    out += P.packet_record(t + 9, P.make_hs(P.PID_ACK))
    t += 50
    out += P.packet_record(t, P.make_token(P.PID_IN, 1, 0))
    out += P.packet_record(t + 3, P.make_data(P.PID_DATA1, S.DEMO_DEVICE))
    out += P.packet_record(t + 20, P.make_hs(P.PID_ACK))
    part1 = bytes(out)
    out = bytearray()
    t += 50
    out += P.packet_record(t, P.make_token(P.PID_OUT, 1, 0))
    out += P.packet_record(t + 3, P.make_data(P.PID_DATA1, b""))
    out += P.packet_record(t + 9, P.make_hs(P.PID_ACK))
    t += 100
    # NAK-only polling for > 100 ms closes as one [N POLL] row
    for _ in range(300):
        out += P.packet_record(t, P.make_token(P.PID_IN, 2, 1))
        out += P.packet_record(t + 3, P.make_hs(P.PID_NAK))
        t += 1000
    out += P.build_record(P.REC_STOP, struct.pack("<QB", t, 0))

    st = C.CaptureStore(os.path.join(TMP, "p.pusb"))
    st.feed(part1)
    st.idle()
    vis = [st.top_node(i).cols[8] for i in range(st.row_count())]
    # control transfer still open: nothing after it may be visible yet
    assert vis == ["Capture started", "IN txn [5 POLL]"], vis
    st.feed(bytes(out))
    st.close_writer()
    rows = [st.top_node(i).cols for i in range(st.row_count())]
    recs = [r[8] for r in rows]
    assert recs[:4] == ["Capture started", "IN txn [5 POLL]", "Get Device Descriptor", "IN txn"], recs
    assert rows[1][9] == "01 02" and rows[3][9] == "03"
    polls = [r for r in rows if r[8].endswith("POLL]") and r[9] == "NAK"]
    assert polls and sum(int(r[8].split("[")[1].split()[0]) for r in polls) == 300, recs
    assert all(int(r[8].split("[")[1].split()[0]) <= 101 for r in polls)
    times = [r[2] for r in rows if r[2]]
    assert times == sorted(times), times
    st.close()
    print("poll merge / interleaving / live visibility OK:", recs[:5], f"+ {len(polls)} NAK-only poll rows")


def test_stop_marker():
    """the host "stop requested" marker may land anywhere: no transaction / transfer is split by it"""
    recs = [P.build_record(P.REC_START, struct.pack("<QBBBBB", 1000, 1, 0, 0, 0, 1))]
    t = 2000
    for tok, pid, data in ((P.make_token(P.PID_SETUP, 1, 0), P.PID_DATA0, bytes([0x80, 6, 0, 1, 0, 0, 18, 0])),
                           (P.make_token(P.PID_IN, 1, 0), P.PID_DATA1, S.DEMO_DEVICE),
                           (P.make_token(P.PID_OUT, 1, 0), P.PID_DATA1, b""),
                           (P.make_token(P.PID_OUT, 1, 1), P.PID_DATA0, bytes(range(64)))):
        recs += [P.packet_record(t, tok), P.packet_record(t + 3, P.make_data(pid, data)),
                 P.packet_record(t + 50, P.make_hs(P.PID_ACK))]
        t += 100
    end = P.build_record(P.REC_STOP, struct.pack("<QB", t, 0))
    want = ["Capture started", "Get Device Descriptor", "OUT txn", "Capture stopped"]
    for cut in range(1, len(recs) + 1):
        st = C.CaptureStore(os.path.join(TMP, "s.pusb"))
        st.feed(b"".join(recs[:cut]))
        st.host_event(P.HE_USER_STOP, "stop requested by user")
        st.feed(b"".join(recs[cut:]) + end)
        st.close_writer()
        st2 = C.CaptureStore(st.path, create=False)
        st2.load()
        for x in (st, st2):
            tops = [x.top_node(i) for i in range(x.row_count())]
            assert [n.cols[8] for n in tops if n.cols[8] != "Stop request"] == want, (cut, [n.cols[8] for n in tops])
            assert sum(n.cols[8] == "Stop request" for n in tops) == 1
            assert not any(f & C.RF_ERROR for f in x.r_flags), cut
            out = next(n for n in tops if n.cols[8] == "OUT txn")
            assert [k.cols[8] for k in out.kids()] == ["OUT packet", "DATA0 packet", "ACK packet"], cut
            ctrl = next(n for n in tops if n.cols[8] == "Get Device Descriptor")
            assert [len(k.kids()) for k in ctrl.kids()] == [3, 3, 3], cut
            x.close()
    print(f"stop marker OK: {len(recs)} positions")


def test_roundtrip_and_resync():
    data = demo_stream(False, 1_500_000, seed=9)
    st = make_store(data, "r.pusb")
    live = tree_of(st)
    st2 = C.CaptureStore(st.path, create=False)
    st2.load()
    again = tree_of(st2)
    assert len(live) == len(again)
    for a, b in zip(live, again):
        assert [(d, c[1:]) for d, c in a] == [(d, c[1:]) for d, c in b], (a[0], b[0])
    st.close()
    st2.close()
    print(f"roundtrip OK: {len(live)} rows identical live vs reopened (all levels)")

    g = make_store(data, "g.pusb", garbage=True)
    assert g.garbage_bytes > 0
    n = g.row_count()
    for i in range(n):
        for _d, x in walk(g.top_node(i)):
            g.describe(x)
    assert abs(n - len(live)) <= max(10, len(live) * 0.05), (n, len(live))
    g.close()
    print(f"resync OK: {g.garbage_bytes} corrupt bytes skipped, rows {n} vs {len(live)}")


def read_pcapng(path):
    """independent minimal pcapng reader (spec: draft-ietf-opsawg-pcapng)"""
    blob = open(path, "rb").read()
    p = 0
    ifaces, frames = [], []
    while p < len(blob):
        bt, n = struct.unpack_from("<II", blob, p)
        assert n % 4 == 0 and n >= 12 and struct.unpack_from("<I", blob, p + n - 4)[0] == n, (p, bt, n)
        body = blob[p + 8:p + n - 4]
        if bt == 0x0A0D0D0A:
            assert struct.unpack_from("<IHH", body, 0) == (0x1A2B3C4D, 1, 0)
        elif bt == 1:
            ifaces.append(struct.unpack_from("<H", body, 0)[0])
            assert b"\x09\x00\x01\x00\x06" in body  # if_tsresol = 6 (us)
        elif bt == 6:
            iface, hi, lo, cap, orig = struct.unpack_from("<IIIII", body, 0)
            data = body[20:20 + cap]
            o = 20 + cap + (-cap) % 4
            comment = None
            while o + 4 <= len(body):
                code, ln = struct.unpack_from("<HH", body, o)
                if code == 0:
                    break
                if code == 1:
                    comment = body[o + 4:o + 4 + ln].decode()
                o += 4 + ln + (-ln) % 4
            frames.append((iface, (hi << 32) | lo, data, comment))
        p += n
    return ifaces, frames


def test_wireshark_export():
    import export_pcap
    st = make_store(demo_stream(False, 500_000), "w.pusb")
    out = os.path.join(TMP, "w.pcapng")
    s = export_pcap.export_pcapng(st, out)
    ifaces, frames = read_pcapng(out)
    assert ifaces == [export_pcap.LINKTYPE_USB_2_0_FULL_SPEED]
    assert s["packets"] == len(frames) == st.packets, (s, len(frames), st.packets)
    ts = [f[1] for f in frames]
    assert ts == sorted(ts) and ts[0] > 1_700_000_000 * 10 ** 6  # absolute time, monotonic
    bad_crc = 0
    for _i, _t, d, _c in frames:
        pid = d[0] & 0xF
        assert (d[0] >> 4) == (~pid & 0xF), d.hex()  # PID check nibble (no SYNC byte)
        if pid in P.DATA_PIDS:
            bad_crc += P.crc16_usb(d[1:-2]) != (d[-2] | d[-1] << 8)
    comments = [c for *_x, c in frames if c]
    assert any("Bus Reset" in c for c in comments)
    assert bad_crc == 0  # the demo marks its error packet with a flag only
    assert s["errors"] == sum("packet error CRC" in c for c in comments) >= 1, s
    st.close()
    st = make_store(demo_stream(True, 500_000), "w2.pusb")
    s2 = export_pcap.export_pcapng(st, out)
    assert s2["folded_sof"] > 0 and s2["packets"] == st.packets
    st.close()
    print(f"wireshark export OK: {len(frames)} frames, linktype 294, {len(comments)} comments; "
          f"folded capture: {s2['folded_sof']} SOF / {s2['folded_nak']} IN-NAK not exported")


def test_usbpcap_export():
    """USBPcap layout: header, submit / complete pairs, payloads equal to the capture"""
    import export_usbpcap as X
    out = os.path.join(TMP, "u.pcapng")

    def read(store, **kw):
        s = X.export_usbpcap(store, out, **kw)
        ifaces, frames = read_pcapng(out)
        assert ifaces == [X.LINKTYPE_USBPCAP] and len(frames) == s["frames"]
        ts = [f[1] for f in frames]
        assert ts == sorted(ts)
        rows = []
        for _i, t, d, c in frames:
            hl, irp, st_, fn, info, bus, dev, ep, tr, n = struct.unpack_from("<HQIHBHHBBI", d)
            assert hl == (28 if tr == X.CONTROL else 27) and len(d) == hl + n and bus == 1, d.hex()
            rows.append({"irp": irp, "st": st_, "fn": fn, "done": info, "dev": dev, "ep": ep, "tr": tr, "data": d[hl:],
                         "stage": d[27] if hl == 28 else None, "c": c, "ts": t})
        seen = {}
        for r in rows:
            if r["irp"]:
                seen.setdefault(r["irp"], []).append(r)
        for v in seen.values():
            assert [r["done"] for r in v] in ([0, 1], [0]), v
            a, b = v[0], v[-1]
            assert (a["dev"], a["ep"], a["tr"]) == (b["dev"], b["ep"], b["tr"])
            if a["tr"] == X.CONTROL:
                assert a["stage"] == 0 and len(a["data"]) >= 8 and (b is a or b["stage"] == 3)
            elif a["ep"] & 0x80:
                assert not a["data"]
            else:
                assert not b["data"]
        return s, rows

    # the demo has the enumeration: nothing added, endpoint types from its descriptors
    st = make_store(demo_stream(False, 500_000), "u.pusb")
    assert X.missing_descriptors(st) == []
    s, rows = read(st)
    assert not s["descriptors"] and not any("Not captured" in (r["c"] or "") for r in rows)
    types = {(r["ep"], r["tr"]) for r in rows}
    assert types >= {(0x80, X.CONTROL), (0x81, X.INTERRUPT), (0x02, X.BULK), (0x83, X.BULK)}, types
    want = []
    for i in range(st.row_count()):
        if st.r_kind[i] == C.K_TXN:
            t = st.top_node(i).info[1].final
            if t.pid == P.PID_IN and t.hs == P.PID_ACK and not t.err:
                want.append(t.payload)
    assert want and [r["data"] for r in rows if r["tr"] == X.INTERRUPT and r["done"]] == want
    assert any(len(r["data"]) == 4096 for r in rows if r["tr"] == X.BULK)  # data phase = one transfer
    get_dev = [r for r in rows if r["fn"] == 0x0B and r["data"][:4] == bytes([0x80, 6, 0, 1])]
    assert get_dev and any(r["done"] and r["data"] == S.DEMO_DEVICE for r in rows)
    demo_ref = X.load_reference(st.path)
    st.close()
    # folding makes no difference to the transfers
    st = make_store(demo_stream(True, 500_000), "u2.pusb")
    assert [r["data"] for r in read(st)[1]] and X.missing_descriptors(st) == []
    st.close()

    # only HID traffic, no enumeration: descriptors are added and marked
    b = bytearray(P.build_record(P.REC_START, struct.pack("<QBBBBB", 1000, 1, 1, 1, 0, 1)))
    t = 2000
    for k in range(6):
        b += P.packet_record(t, P.make_token(P.PID_IN, 14, 1)) + P.packet_record(t + 3, P.make_hs(P.PID_NAK))
        b += P.packet_record(t + 10, P.make_token(P.PID_OUT, 14, 1))
        b += P.packet_record(t + 13, P.make_data(P.PID_DATA0 if k % 2 else P.PID_DATA1, bytes([k] * 64)))
        b += P.packet_record(t + 60, P.make_hs(P.PID_ACK))
        b += P.packet_record(t + 100, P.make_token(P.PID_IN, 14, 1))
        b += P.packet_record(t + 103, P.make_data(P.PID_DATA0 if k % 2 else P.PID_DATA1, bytes([1, k] * 17)))
        b += P.packet_record(t + 130, P.make_hs(P.PID_ACK))
        t += 1000
    # a stalled endpoint, then a corrupt packet
    b += P.packet_record(t, P.make_token(P.PID_IN, 14, 1)) + P.packet_record(t + 3, P.make_hs(P.PID_STALL))
    b += P.packet_record(t + 100, P.make_token(P.PID_OUT, 14, 1))
    b += P.packet_record(t + 103, P.make_data(P.PID_DATA0, b"bad"), P.PKT_ERR_CRC)
    b += P.packet_record(t + 130, P.make_hs(P.PID_ACK))
    b += P.build_record(P.REC_STOP, struct.pack("<QB", t + 200, 0))
    st = make_store(bytes(b), "u3.pusb")
    assert X.missing_descriptors(st) == [14]
    s, rows = read(st)
    assert len(s["descriptors"]) == 1 and "generic" in s["descriptors"][0]
    assert all("Not captured" in r["c"] and r["irp"] == 0 for r in rows[:6]) and s["transfers"] == 13, s
    assert X.is_complete(rows[1]["data"], rows[3]["data"])
    assert X.parse_config(rows[3]["data"]) == ({0x81: X.INTERRUPT, 0x01: X.INTERRUPT}, {3})
    assert [r["data"] for r in rows if r["ep"] == 1 and not r["done"]] == [bytes([k] * 64) for k in range(6)]
    assert [r["data"] for r in rows if r["ep"] == 0x81 and r["done"]][:6] == [bytes([1, k] * 17) for k in range(6)]
    assert [r["st"] for r in rows if r["st"]] == [X.ST_STALL] and s["skipped"] == 1
    s, rows = read(st, descriptors="none")
    assert not s["descriptors"] and rows[0]["irp"] == 1
    # reference: used only if exactly one device fits (the demo device has no OUT endpoint 1)
    assert "generic" in read(st, reference=demo_ref)[0]["descriptors"][0]
    good = [("ABCD:1234 from x", *X.generic_hid({0x81, 0x01}, 0, False))]
    assert "ABCD:1234" in read(st, reference=demo_ref + good)[0]["descriptors"][0]
    assert "generic" in read(st, reference=good + good)[0]["descriptors"][0]  # ambiguous
    st.close()
    print(f"usbpcap export OK: {s['transfers']} HID transfers, reference matching")


def test_csv_export():
    """Data Center layout, unique Index independent of filter / expansion"""
    import csv
    import re
    import export_csv as E

    def read(path):
        raw = open(path, "rb").read()
        assert raw.count(b"\n") == raw.count(b"\r\n") and not raw.startswith(b"\xef\xbb\xbf")
        lines = raw.decode("utf-8").split("\r\n")[:-1]
        head = [x for x in lines if x.startswith("#")]
        assert head[-1] == "# Level,Sp,Index,m:s.ms.us,Dur,Len,Err,Dev,Ep,Record,Summary"
        return list(csv.reader(lines[len(head):]))

    dur = re.compile(r"^(\d{1,3}\.\d{3} us|\d{1,3}\.\d{3}\.\d{3} (ms|s)|)$")
    assert E.fmt_dur(2.8333) == "2.833 us" and E.fmt_dur(1031.833) == "1.031.833 ms"
    assert E.fmt_dur(999.9996) == "1.000.000 ms" and E.fmt_err("CRC,STUFF") == "0C"
    out = os.path.join(TMP, "x.csv")
    for fold in (False, True):
        st = make_store(demo_stream(fold, 500_000), f"c{int(fold)}.pusb")
        E.export_csv(st, out, expanded=lambda k: True)
        full = read(out)
        assert [int(r[2]) for r in full] == list(range(len(full)))  # every record once, no gap
        E.export_csv(st, out)
        top = read(out)
        assert top == [r for r in full if r[0] == "0"]  # collapsed records keep the same Index
        ids = [i for i in range(st.row_count()) if i % 3 == 1]
        E.export_csv(st, out, ids)
        flt = read(out)
        assert flt and {tuple(r) for r in flt} <= {tuple(r) for r in top}
        k = next(i for i in range(st.row_count()) if st.top_node(i).cols[8].startswith("Get Device"))
        E.export_csv(st, out, expanded=lambda i: {0: {}} if i == k else None)
        part = read(out)
        assert {r[0] for r in part} == {"0", "1", "2"} and {tuple(r) for r in part} <= {tuple(r) for r in full}
        for r in full:
            assert len(r) == 11 and dur.match(r[4]), r
            assert re.match(r"^(\d+ B|)$", r[5]) and re.match(r"^(\d{2,3}|)$", r[7]), r
            assert r[9].startswith("   " * int(r[0])), r
            assert r[0] == "0" or (r[7] and r[8]), r  # child records carry Dev / Ep
            assert len(r[10].rstrip("\u2026").split()) <= 24 or not r[9].strip().endswith(("txn", "packet")), r
        assert any(r[10].endswith("\u2026") for r in full)
        E.export_csv(st, out, expanded=lambda k: True, full_data=True)
        assert not any("\u2026" in r[10] for r in read(out) if r[9].strip().endswith(("txn", "packet")))
        st.close()
    print(f"csv export OK: {len(full)} records, {len(top)} top level")


def test_throughput():
    data = demo_stream(False, 20_000_000, seed=2)
    st = C.CaptureStore(os.path.join(TMP, "b.pusb"))
    t0 = time.perf_counter()
    p = 0
    while p < len(data):
        st.feed(data[p:p + 65536])
        p += 65536
    dt = time.perf_counter() - t0
    st.close_writer()
    rows = st.row_count()
    t1 = time.perf_counter()
    for i in range(0, rows, max(1, rows // 2000)):
        st.top_node(i)
    rt = (time.perf_counter() - t1) / min(rows, 2000)
    st.close()
    print(f"throughput: {len(data) / dt / 1e6:.1f} MB/s ({st.packets / dt / 1e3:.0f} k packets/s), "
          f"{rows} rows, index {rows * 24 / 1e6:.2f} MB, render {rt * 1e6:.0f} us/row "
          f"(USB FS CDC max is ~1 MB/s)")


if __name__ == "__main__":
    test_crc_compat()
    test_hierarchy()
    test_poll_and_interleave()
    test_stop_marker()
    test_roundtrip_and_resync()
    test_wireshark_export()
    test_usbpcap_export()
    test_csv_export()
    test_throughput()
    print("ALL OK")
