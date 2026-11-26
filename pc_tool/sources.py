"""
Pico USB Sniffer - data sources: the Pico over USB CDC, or a synthetic demo.
"""
from __future__ import annotations

import random
import struct
import threading
import time

import protocol as P
from capture import CaptureStore


class SerialWorker(threading.Thread):
    """Reads the Pico CDC port continuously and feeds the store."""

    def __init__(self, port, store: CaptureStore, speed="A", fold_sof=True, fold_nak=True,
                 auto_reconnect=True, log=None):
        super().__init__(daemon=True)
        self.port = port
        self.store = store
        self.speed = speed
        self.fold_sof = fold_sof
        self.fold_nak = fold_nak
        self.auto_reconnect = auto_reconnect
        self.log = log or (lambda s: None)
        self._stop_evt = threading.Event()
        self.ser = None
        self.error = None
        self.connected = False
        self.reconnects = 0

    def stop(self):
        self._stop_evt.set()

    def _cmd_start(self):
        return b"S" + self.speed.encode() + (b"1" if self.fold_sof else b"0") + (b"1" if self.fold_nak else b"0")

    def _open(self):
        import serial
        ser = serial.Serial()
        ser.port = self.port
        ser.baudrate = 115200  # ignored by CDC
        ser.timeout = 0.02
        ser.write_timeout = 1
        ser.dtr = True
        ser.rts = True
        ser.open()
        try:
            ser.set_buffer_size(rx_size=8 << 20, tx_size=4096)
        except Exception:
            pass
        self.ser = ser
        ser.write(b"P")
        time.sleep(0.15)
        ser.reset_input_buffer()
        ser.write(b"I")
        self.store.host_event(P.HE_SEGMENT, f"start on {self.port}: {self._cmd_start().decode()}")
        ser.write(self._cmd_start())
        self.connected = True

    def _close(self):
        self.connected = False
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None

    def run(self):
        import serial
        self.store.host_event(P.HE_SESSION, f"capture session on {self.port}")
        first = True
        while not self._stop_evt.is_set():
            try:
                self._open()
                if not first:
                    self.reconnects += 1
                    self.store.host_event(P.HE_RECONNECT, f"reconnected to {self.port}")
                    self.log(f"Reconnected to {self.port}")
                first = False
                last_rx = time.monotonic()
                while not self._stop_evt.is_set():
                    data = self.ser.read(1 << 16)
                    if data:
                        self.store.feed(data)
                        last_rx = time.monotonic()
                        continue
                    self.store.idle()
                    if time.monotonic() - last_rx > 3.0:
                        raise serial.SerialException("no data from device for 3 s")
            except Exception as e:  # serial errors, device unplugged ...
                self._close()
                if self._stop_evt.is_set():
                    break
                self.store.host_event(P.HE_DISCONNECT, str(e))
                self.log(f"Device error: {e}")
                if not self.auto_reconnect:
                    self.error = str(e)
                    return
                if first:
                    first = False
                # wait for the port to come back
                while not self._stop_evt.wait(1.0):
                    try:
                        from serial.tools import list_ports
                        if any(p.device == self.port for p in list_ports.comports()):
                            break
                    except Exception:
                        break
        # graceful stop
        if self.ser:
            try:
                self.store.host_event(P.HE_USER_STOP, "stop requested by user")
                stops = self.store.last_stop_seen
                self.ser.write(b"P")
                t0 = time.monotonic()
                while time.monotonic() - t0 < 2.0:
                    data = self.ser.read(1 << 16)
                    if data:
                        self.store.feed(data)
                    if self.store.last_stop_seen != stops:
                        break
            except Exception:
                pass
            self._close()




# ---------------------------------------------------------------------------
# Demo: synthetic bus (enumeration, HID keyboard, mass storage), emitted the
# same way the firmware does (SOF / IN-NAK folding, ep0 never folded)
# ---------------------------------------------------------------------------
DEMO_DEVICE = bytes([0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x09, 0x12, 0x01, 0x00, 0x00, 0x01,
                     0x01, 0x02, 0x03, 0x01])
HID_REPORT = bytes.fromhex(
    "05010906a101050719e029e71500250175019508810295017508810195057501050819012905910295017503"
    "91019506750815002565050719002965 8100c0".replace(" ", ""))
DEMO_CONFIG = (bytes([0x09, 0x02, 57, 0, 2, 1, 0, 0x80, 50])
               + bytes([0x09, 0x04, 0, 0, 1, 0x03, 0x01, 0x01, 0])
               + bytes([0x09, 0x21, 0x11, 0x01, 0, 1, 0x22, len(HID_REPORT), 0])
               + bytes([0x07, 0x05, 0x81, 0x03, 8, 0, 10])
               + bytes([0x09, 0x04, 1, 0, 2, 0x08, 0x06, 0x50, 0])
               + bytes([0x07, 0x05, 0x02, 0x02, 64, 0, 0])
               + bytes([0x07, 0x05, 0x83, 0x02, 64, 0, 0]))


def _str_desc(s):
    b = s.encode("utf-16-le")
    return bytes([len(b) + 2, 3]) + b


DEMO_STRINGS = {0: bytes([4, 3, 0x09, 0x04]), 1: _str_desc("Pico Demo"), 2: _str_desc("Demo Keyboard + Disk"),
                3: _str_desc("DEMO123456")}
INQUIRY = bytes([0, 0x80, 4, 2, 31, 0, 0, 0]) + b"PICODEMO" + b"Virtual Disk    " + b"1.00"
SENSE = bytes([0x70, 0, 6, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x28, 0, 0, 0, 0, 0])


class DemoBus:
    """emits packet records with realistic timing and firmware-style folding"""

    def __init__(self, t0, fold_sof, fold_nak, rnd):
        self.out = bytearray()
        self.t = t0
        self.next_sof = t0
        self.frame = 0
        self.fold_sof = fold_sof
        self.fold_nak = fold_nak
        self.rnd = rnd
        self.fold = None
        self.toggle = {}
        self.pkts = 0
        self.tag = 1

    # -- firmware style folding
    def _fold_open(self, ts):
        f = self.fold
        if f is not None and ts - f["t1"] > 100_000:
            self.fold_flush()
            f = None
        if f is None:
            f = self.fold = {"t1": ts, "t2": ts, "sof": 0, "f1": 0, "f2": 0, "eps": {}}
        f["t2"] = ts
        return f

    def fold_flush(self):
        f = self.fold
        if f is None:
            return
        self.fold = None
        eps = list(f["eps"].items())[:8]
        pl = struct.pack("<QQIHHIIB", f["t1"], f["t2"], f["sof"], f["f1"], f["f2"], 0, 0, len(eps))
        for (a, e), c in eps:
            pl += struct.pack("<BBI", a, e, c)
        self.out += P.build_record(P.REC_FOLD, pl)

    def _emit(self, data, flags=0):
        self.fold_flush()
        self.out += P.packet_record(self.t, data, flags)
        self.t += (len(data) * 8 * 7 // 6 + 3) // 12 + 1
        self.pkts += 1

    def sync(self):
        """emit the SOFs due before the next transaction"""
        while self.t >= self.next_sof:
            ts = self.next_sof
            self.frame = (self.frame + 1) & 0x7FF
            if self.fold_sof:
                f = self._fold_open(ts)
                if f["sof"] == 0:
                    f["f1"] = self.frame
                f["f2"] = self.frame
                f["sof"] += 1
            else:
                self.t = max(self.t, ts)  # a transaction may have crossed the frame boundary
                self._emit(P.make_sof(self.frame))
            self.next_sof += 1000
            self.t = max(self.t, ts + 2)

    def idle_until(self, t):
        while self.next_sof <= t:
            self.t = max(self.t, self.next_sof)
            self.sync()
        self.t = max(self.t, t)

    def wait(self, us):
        self.idle_until(self.t + us)

    # -- transactions
    def _dpid(self, dev, ep, d):
        k = (dev, ep, d)
        v = self.toggle.get(k, 0)
        self.toggle[k] = v ^ 1
        return P.PID_DATA1 if v else P.PID_DATA0

    def in_nak(self, dev, ep):
        self.sync()
        if self.fold_nak and ep != 0:
            f = self._fold_open(self.t)
            f["eps"][(dev, ep)] = f["eps"].get((dev, ep), 0) + 1
            self.t += 4
            return
        self._emit(P.make_token(P.PID_IN, dev, ep))
        self._emit(P.make_hs(P.PID_NAK))

    def setup(self, dev, payload):
        self.sync()
        self.toggle[(dev, 0, 0)] = 1
        self.toggle[(dev, 0, 1)] = 1
        self._emit(P.make_token(P.PID_SETUP, dev, 0))
        self._emit(P.make_data(P.PID_DATA0, payload))
        self._emit(P.make_hs(P.PID_ACK))

    def txn_in(self, dev, ep, payload, naks=0, hs=P.PID_ACK):
        for _ in range(naks):
            self.in_nak(dev, ep)
            self.wait(self.rnd.randint(20, 120))
        self.sync()
        self._emit(P.make_token(P.PID_IN, dev, ep))
        if hs == P.PID_STALL:
            self._emit(P.make_hs(P.PID_STALL))
            return
        self._emit(P.make_data(self._dpid(dev, ep, 1), payload))
        self._emit(P.make_hs(P.PID_ACK))

    def txn_out(self, dev, ep, payload, naks=0):
        while True:
            self.sync()
            self._emit(P.make_token(P.PID_OUT, dev, ep))
            pid = self.toggle.get((dev, ep, 0), 0)
            self._emit(P.make_data(P.PID_DATA1 if pid else P.PID_DATA0, payload))
            if naks:
                self._emit(P.make_hs(P.PID_NAK))
                naks -= 1
                self.wait(50)
                continue
            self.toggle[(dev, ep, 0)] = pid ^ 1
            self._emit(P.make_hs(P.PID_ACK))
            return

    def control(self, dev, bm, req, val, idx, ln, data=None, naks=0, mps=64, stall=False):
        self.setup(dev, struct.pack("<BBHHH", bm, req, val, idx, ln))
        self.wait(30)
        if bm & 0x80:
            if stall:
                self.txn_in(dev, 0, b"", naks=naks, hs=P.PID_STALL)
                self.wait(200)
                return
            d = (data or b"")[:ln]
            chunks = [d[i:i + mps] for i in range(0, len(d), mps)] or [b""]
            if len(d) and len(d) % mps == 0 and len(d) < ln:
                chunks.append(b"")
            for k, c in enumerate(chunks):
                self.txn_in(dev, 0, c, naks=naks if k == 0 else 0)
                self.wait(15)
            self.sync()
            self._emit(P.make_token(P.PID_OUT, dev, 0))
            self._emit(P.make_data(P.PID_DATA1, b""))
            self._emit(P.make_hs(P.PID_ACK))
        else:
            d = data or b""
            for i in range(0, len(d), mps):
                self.txn_out(dev, 0, d[i:i + mps])
            self.wait(20)
            for _ in range(naks):
                self.in_nak(dev, 0)
                self.wait(40)
            self.sync()
            self._emit(P.make_token(P.PID_IN, dev, 0))
            if stall:
                self._emit(P.make_hs(P.PID_STALL))
                self.wait(200)
                return
            self._emit(P.make_data(P.PID_DATA1, b""))
            self._emit(P.make_hs(P.PID_ACK))
        self.wait(200)

    def scsi(self, dev, cdb, data_in=b"", dlen=None, status=0, naks=0):
        tag = self.tag
        self.tag += 1
        dlen = len(data_in) if dlen is None else dlen
        cbw = b"USBC" + struct.pack("<IIBBB", tag, dlen, 0x80 if dlen else 0, 0, len(cdb)) + cdb.ljust(16, b"\0")
        self.txn_out(dev, 2, cbw)
        self.wait(30)
        for i in range(0, len(data_in), 64):
            self.txn_in(dev, 3, data_in[i:i + 64], naks=naks if i == 0 else 0)
            self.wait(8)
        self.txn_in(dev, 3, b"USBS" + struct.pack("<IIB", tag, max(0, dlen - len(data_in)), status),
                    naks=1 if not data_in else 0)
        self.wait(100)


def demo_enumeration(b: DemoBus):
    b.out += P.build_record(P.REC_RESET, struct.pack("<Q", b.t))
    b.wait(20_000)
    b.control(0, 0x80, 6, 0x0100, 0, 64, DEMO_DEVICE, naks=3)
    b.out += P.build_record(P.REC_RESET, struct.pack("<Q", b.t))
    b.wait(15_000)
    b.control(0, 0x00, 5, 5, 0, 0)
    b.wait(2_000)
    b.control(5, 0x80, 6, 0x0100, 0, 18, DEMO_DEVICE)
    b.control(5, 0x80, 6, 0x0200, 0, 9, DEMO_CONFIG)
    b.control(5, 0x80, 6, 0x0200, 0, 255, DEMO_CONFIG, naks=2)
    b.control(5, 0x80, 6, 0x0300, 0, 255, DEMO_STRINGS[0])
    for i in (2, 1, 3):
        b.control(5, 0x80, 6, 0x0300 | i, 0x0409, 255, DEMO_STRINGS[i], naks=(i % 2) * 28)
    b.control(5, 0x80, 6, 0x0600, 0, 10, None, stall=True)
    b.control(5, 0x00, 9, 1, 0, 0)
    b.control(5, 0x21, 0x0A, 0, 0, 0)
    b.control(5, 0x81, 6, 0x2200, 0, len(HID_REPORT) + 64, HID_REPORT)
    b.control(5, 0x21, 0x09, 0x0200, 0, 1, b"\x00")
    b.control(5, 0xA1, 0xFE, 0, 1, 1, b"\x00", naks=1)
    b.scsi(5, bytes([0x12, 0, 0, 0, 36, 0]), INQUIRY)
    b.scsi(5, bytes(6), status=1)
    b.scsi(5, bytes([0x03, 0, 0, 0, 18, 0]), SENSE)
    b.scsi(5, bytes(6))
    b.scsi(5, bytes([0x25]) + bytes(9), struct.pack(">II", 0x3FFFF, 512))
    b.scsi(5, bytes([0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0]), bytes(510) + b"\x55\xaa", naks=4)


def demo_steady(b: DemoBus, rnd, us, state):
    """us of steady state traffic: keyboard polling, disk reads, rare errors"""
    end = b.t + us
    while b.t < end:
        if rnd.random() < 0.15:
            key = rnd.randint(4, 0x27)
            b.txn_in(5, 1, bytes([0, 0, key, 0, 0, 0, 0, 0]))
            b.wait(rnd.randint(500, 1500))
            b.txn_in(5, 1, bytes(8))
        else:
            b.in_nak(5, 1)
        if rnd.random() < 0.02:
            blocks = rnd.choice((1, 8))
            lba = state.get("lba", 0)
            b.scsi(5, struct.pack(">BBIBHB", 0x28, 0, lba, 0, blocks, 0),
                   bytes(rnd.getrandbits(8) for _ in range(512 * blocks)), naks=rnd.randint(0, 3))
            state["lba"] = lba + blocks
        if rnd.random() < 0.003:
            b.sync()
            b._emit(P.make_data(P.PID_DATA1, b"\x01\x02\x03"), P.PKT_ERR_CRC)
        b.wait(10_000)


class DemoWorker(threading.Thread):
    """Synthetic device stream (no hardware needed)."""

    def __init__(self, store: CaptureStore, rate=1.0, fold_sof=True, fold_nak=True, log=None):
        super().__init__(daemon=True)
        self.store = store
        self.rate = rate
        self.fold_sof = fold_sof
        self.fold_nak = fold_nak
        self._stop_evt = threading.Event()
        self.connected = True
        self.reconnects = 0
        self.error = None

    def stop(self):
        self._stop_evt.set()

    def run(self):
        st = self.store
        rnd = random.Random()
        st.host_event(P.HE_SESSION, "demo session")
        st.host_event(P.HE_SEGMENT, "demo start")
        t = 1_000_000
        info = struct.pack("<HHIIBB", 1, 2, 120_000_000, 32768, 10, 11) + b"Demo device"
        b = DemoBus(t, self.fold_sof, self.fold_nak, rnd)
        b.out += P.build_record(P.REC_INFO, info)
        b.out += P.build_record(P.REC_START, struct.pack("<QBBBBB", t, 1, self.fold_sof, self.fold_nak, 1, 1))
        demo_enumeration(b)
        st.feed(bytes(b.out))
        b.out = bytearray()
        wall0 = time.monotonic()
        dev_t0 = b.t
        last_status = 0
        state = {}
        while not self._stop_evt.is_set():
            demo_steady(b, rnd, 20_000, state)
            if b.t - last_status > 500_000:
                last_status = b.t
                b.fold_flush()
                b.out += P.build_record(P.REC_STATUS, struct.pack("<QIIIIIIII", b.t, b.pkts, 0, 10, 300, 32768,
                                                                  0, 0, 0))
            st.feed(bytes(b.out))
            b.out = bytearray()
            delay = wall0 + (b.t - dev_t0) / 1e6 / self.rate - time.monotonic()
            if delay > 0:
                self._stop_evt.wait(delay)
        b.fold_flush()
        st.feed(bytes(b.out) + P.build_record(P.REC_STOP, struct.pack("<QB", b.t, 0)))
