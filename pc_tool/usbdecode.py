"""
Pico USB Sniffer - USB class / descriptor / SCSI decoders (Data Center style).

Detail trees are lists of nodes:  (name, value, [children])
"""
from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------
CLASS_NAMES = {
    0x00: "Defined at Interface", 0x01: "Audio", 0x02: "CDC Communications", 0x03: "HID",
    0x05: "Physical", 0x06: "Image", 0x07: "Printer", 0x08: "Mass Storage", 0x09: "Hub",
    0x0A: "CDC Data", 0x0B: "Smart Card", 0x0D: "Content Security", 0x0E: "Video",
    0x0F: "Personal Healthcare", 0x10: "Audio/Video", 0x11: "Billboard", 0x12: "USB Type-C Bridge",
    0xDC: "Diagnostic", 0xE0: "Wireless Controller", 0xEF: "Miscellaneous", 0xFE: "Application Specific",
    0xFF: "Vendor Specific",
}
DESC_NAMES = {
    1: "Device", 2: "Configuration", 3: "String", 4: "Interface", 5: "Endpoint",
    6: "Device Qualifier", 7: "Other Speed Configuration", 8: "Interface Power", 9: "OTG",
    0x0A: "Debug", 0x0B: "Interface Association", 0x0F: "BOS", 0x10: "Device Capability",
    0x21: "HID", 0x22: "HID Report", 0x23: "HID Physical", 0x24: "Class-Specific Interface",
    0x25: "Class-Specific Endpoint", 0x29: "Hub", 0x30: "SuperSpeed Endpoint Companion",
}
EP_TYPES = ["Control", "Isochronous", "Bulk", "Interrupt"]
RECIPIENTS = {0: "Device", 1: "Interface", 2: "Endpoint", 3: "Other"}
REQ_TYPES = {0: "Standard", 1: "Class", 2: "Vendor", 3: "Reserved"}

STD_REQ = {
    0x00: "Get Status", 0x01: "Clear Feature", 0x03: "Set Feature", 0x05: "Set Address",
    0x06: "Get Descriptor", 0x07: "Set Descriptor", 0x08: "Get Configuration",
    0x09: "Set Configuration", 0x0A: "Get Interface", 0x0B: "Set Interface", 0x0C: "Synch Frame",
    0x30: "Set SEL", 0x31: "Set Isochronous Delay",
}
FEATURES = {(0, 1): "DEVICE_REMOTE_WAKEUP", (0, 2): "TEST_MODE", (2, 0): "ENDPOINT_HALT"}
HID_REQ = {0x01: "Get Report", 0x02: "Get Idle", 0x03: "Get Protocol",
           0x09: "Set Report", 0x0A: "Set Idle", 0x0B: "Set Protocol"}
HID_REPORT_TYPES = {1: "Input", 2: "Output", 3: "Feature"}
CDC_REQ = {0x00: "Send Encapsulated Command", 0x01: "Get Encapsulated Response",
           0x20: "Set Line Coding", 0x21: "Get Line Coding", 0x22: "Set Control Line State",
           0x23: "Send Break"}
MSC_REQ = {0xFE: "Get Max LUN", 0xFF: "Bulk-Only Mass Storage Reset"}
HUB_REQ = {0x00: "Get Status", 0x01: "Clear Feature", 0x03: "Set Feature", 0x06: "Get Hub Descriptor",
           0x08: "Clear TT Buffer", 0x09: "Reset TT", 0x0A: "Get TT State", 0x0B: "Stop TT"}
HUB_PORT_FEATURES = {0: "PORT_CONNECTION", 1: "PORT_ENABLE", 2: "PORT_SUSPEND", 3: "PORT_OVER_CURRENT",
                     4: "PORT_RESET", 8: "PORT_POWER", 9: "PORT_LOW_SPEED", 16: "C_PORT_CONNECTION",
                     17: "C_PORT_ENABLE", 18: "C_PORT_SUSPEND", 19: "C_PORT_OVER_CURRENT",
                     20: "C_PORT_RESET", 21: "PORT_TEST", 22: "PORT_INDICATOR"}

LANG_IDS = {0x0409: "English (US)", 0x0809: "English (UK)", 0x0407: "German", 0x040C: "French",
            0x0411: "Japanese", 0x0804: "Chinese (PRC)", 0x0412: "Korean", 0x042A: "Vietnamese"}


def u16(b, o):
    return b[o] | (b[o + 1] << 8)


def bcd(v):
    return f"{v >> 8:x}.{v & 0xFF:02x}"


def class_name(c):
    return CLASS_NAMES.get(c, f"0x{c:02X}")


def ep_name(addr):
    return f"0x{addr:02X} ({'IN' if addr & 0x80 else 'OUT'} {addr & 0x0F})"


# ---------------------------------------------------------------------------
# control requests
# ---------------------------------------------------------------------------
class Setup:
    __slots__ = ("bm", "req", "val", "idx", "len", "dir_in", "type", "recip")

    def __init__(self, p: bytes):
        self.bm = p[0]
        self.req = p[1]
        self.val = u16(p, 2)
        self.idx = u16(p, 4)
        self.len = u16(p, 6)
        self.dir_in = bool(self.bm & 0x80)
        self.type = (self.bm >> 5) & 3
        self.recip = self.bm & 0x1F


def request_name(s: Setup) -> str:
    """Data Center style transfer name, e.g. 'Get String Descriptor'"""
    if s.type == 0:
        if s.req in (0x06, 0x07):
            dt = s.val >> 8
            dn = DESC_NAMES.get(dt, f"0x{dt:02X}")
            verb = "Get" if s.req == 0x06 else "Set"
            return f"{verb} {dn} Descriptor"
        if s.req in (0x01, 0x03):
            verb = "Clear" if s.req == 0x01 else "Set"
            return f"{verb} {RECIPIENTS.get(s.recip, '')} Feature".replace("  ", " ")
        if s.req == 0x00:
            return f"Get {RECIPIENTS.get(s.recip, '')} Status".replace("  ", " ")
        return STD_REQ.get(s.req, f"Standard Request 0x{s.req:02X}")
    if s.type == 1:
        if s.req in MSC_REQ and s.recip == 1:
            return MSC_REQ[s.req]
        if s.recip == 3 or (s.recip == 0 and s.req in (0x06, 0x08, 0x09, 0x0A, 0x0B)):
            n = HUB_REQ.get(s.req, f"Hub Request 0x{s.req:02X}")
            if s.req in (0x00, 0x01, 0x03):
                n = n.replace("Status", "Port Status" if s.recip == 3 else "Hub Status")
                n = n.replace("Feature", "Port Feature" if s.recip == 3 else "Hub Feature")
            return n
        if s.req in CDC_REQ and s.req >= 0x20:
            return CDC_REQ[s.req]
        if s.req in HID_REQ:
            return HID_REQ[s.req]
        if s.req in CDC_REQ:
            return CDC_REQ[s.req]
        return f"Class Request 0x{s.req:02X}"
    if s.type == 2:
        return f"Vendor Request 0x{s.req:02X}"
    return f"Reserved Request 0x{s.req:02X}"


def request_summary(s: Setup, data: bytes | None) -> str:
    """Summary column of a control transfer (data = data stage bytes)"""
    d = data or b""
    if s.type == 0:
        if s.req == 0x06:
            dt, di = s.val >> 8, s.val & 0xFF
            txt = f"Index={di} Length={s.len}"
            res = descriptor_summary(dt, d, di) if d else ""
            return f"{txt}  {res}" if res else txt
        if s.req == 0x05:
            return f"New address {s.val}"
        if s.req == 0x09:
            return f"Configuration={s.val}"
        if s.req == 0x08:
            return f"Configuration={d[0]}" if d else ""
        if s.req == 0x0B:
            return f"Interface={s.idx} Alternate={s.val}"
        if s.req == 0x0A:
            return f"Interface={s.idx}" + (f" Alternate={d[0]}" if d else "")
        if s.req in (0x01, 0x03):
            f = FEATURES.get((s.recip, s.val), f"Feature {s.val}")
            if s.recip == 2:
                return f"{f} Endpoint {ep_name(s.idx & 0xFF)}"
            return f
        if s.req == 0x00:
            return f"Status=0x{u16(d, 0):04X}" if len(d) >= 2 else ""
        return f"wValue=0x{s.val:04X} wIndex=0x{s.idx:04X} wLength={s.len}"
    if s.type == 1:
        if s.recip == 1 and s.req == 0xFE:
            return f"Max LUN = {d[0]}" if d else ""
        if s.recip == 3 and s.req in (0x01, 0x03):
            return f"{HUB_PORT_FEATURES.get(s.val, s.val)} Port {s.idx & 0xFF}"
        if s.recip == 3 and s.req == 0x00 and len(d) >= 4:
            return f"Port {s.idx} Status=0x{u16(d, 0):04X} Change=0x{u16(d, 2):04X}"
        if s.req == 0x20 and len(d) >= 7:
            return line_coding(d)
        if s.req == 0x21 and len(d) >= 7:
            return line_coding(d)
        if s.req == 0x22 and s.recip == 1:
            return f"DTR={s.val & 1} RTS={(s.val >> 1) & 1}"
        if s.req == 0x0A and s.recip == 1:
            return f"Duration={(s.val >> 8) * 4} ms Report ID={s.val & 0xFF} Interface={s.idx}"
        if s.req == 0x0B and s.recip == 1:
            return f"{'Report' if s.val else 'Boot'} protocol Interface={s.idx}"
        if s.req in (0x01, 0x09) and s.recip == 1:
            rt = HID_REPORT_TYPES.get(s.val >> 8, s.val >> 8)
            return f"{rt} Report ID={s.val & 0xFF} Length={s.len}" + (f"  {d.hex(' ').upper()}" if d else "")
    txt = f"wValue=0x{s.val:04X} wIndex=0x{s.idx:04X} wLength={s.len}"
    if d:
        txt += "  " + hexs(d, 24)
    return txt


def line_coding(d):
    rate = struct.unpack_from("<I", d, 0)[0]
    stop = {0: "1", 1: "1.5", 2: "2"}.get(d[4], "?")
    par = "NOEMS"[d[5]] if d[5] < 5 else "?"
    return f"{rate} baud {d[6]}{par}{stop}"


def setup_tree(s: Setup):
    bm = s.bm
    return [
        ("bmRequestType", f"0x{bm:02X}", [
            ("Direction", "Device-to-Host" if s.dir_in else "Host-to-Device", []),
            ("Type", REQ_TYPES[s.type], []),
            ("Recipient", RECIPIENTS.get(s.recip, "Reserved"), []),
        ]),
        ("bRequest", f"0x{s.req:02X}  {request_name(s)}", []),
        ("wValue", f"0x{s.val:04X}" + (f"  ({DESC_NAMES.get(s.val >> 8, '?')}, index {s.val & 0xFF})"
                                       if s.type == 0 and s.req in (6, 7) else ""), []),
        ("wIndex", f"0x{s.idx:04X}" + (f"  ({LANG_IDS.get(s.idx, 'language')})"
                                       if s.type == 0 and s.req == 6 and (s.val >> 8) == 3 and s.idx else ""), []),
        ("wLength", str(s.len), []),
    ]


# ---------------------------------------------------------------------------
# descriptors
# ---------------------------------------------------------------------------
def string_of(d: bytes) -> str:
    if len(d) < 2:
        return ""
    n = min(d[0], len(d))
    return d[2:n - (n % 2)].decode("utf-16-le", "replace")


def descriptor_summary(dtype: int, d: bytes, index=None) -> str:
    try:
        if dtype == 1 and len(d) >= 8:
            if len(d) >= 12:
                return (f"VID={u16(d, 8):04X} PID={u16(d, 10):04X} USB {bcd(u16(d, 2))} "
                        f"Class={class_name(d[4])} MaxPacket0={d[7]}")
            return f"USB {bcd(u16(d, 2))} MaxPacket0={d[7]}"
        if dtype == 3 and len(d) >= 2:
            if index == 0 and len(d) >= 4:
                ids = [u16(d, i) for i in range(2, min(d[0], len(d)) - 1, 2)]
                return "Languages: " + ", ".join(f"0x{x:04X}" for x in ids)
            return f'"{string_of(d)}"'
        if dtype == 2 and len(d) >= 9:
            itfs = []
            for t, b in walk(d):
                if t == 4 and len(b) >= 9:
                    itfs.append(class_name(b[5]))
            txt = f"Total={u16(d, 2)} Interfaces={d[4]} MaxPower={d[8] * 2}mA"
            if itfs:
                txt += " [" + ", ".join(dict.fromkeys(itfs)) + "]"
            return txt
        if dtype == 6 and len(d) >= 10:
            return f"USB {bcd(u16(d, 2))} MaxPacket0={d[7]}"
        if dtype == 0x0F and len(d) >= 5:
            return f"Total={u16(d, 2)} Capabilities={d[4]}"
        if dtype == 0x22:
            return f"{len(d)} bytes"
    except Exception:
        pass
    return ""


def walk(d: bytes):
    p = 0
    while p + 2 <= len(d):
        n = d[p]
        if n < 2:
            break
        yield d[p + 1], d[p:p + n]
        p += n


def _desc_node(t, b, ctx):
    n = len(b)
    name = DESC_NAMES.get(t, f"Descriptor 0x{t:02X}")
    f = []

    def add(k, v):
        f.append((k, v, []))

    try:
        if t == 1 and n >= 8:
            add("bcdUSB", bcd(u16(b, 2)))
            add("bDeviceClass", f"0x{b[4]:02X} {class_name(b[4])}")
            add("bDeviceSubClass", f"0x{b[5]:02X}")
            add("bDeviceProtocol", f"0x{b[6]:02X}")
            add("bMaxPacketSize0", str(b[7]))
            if n >= 18:
                add("idVendor", f"0x{u16(b, 8):04X}")
                add("idProduct", f"0x{u16(b, 10):04X}")
                add("bcdDevice", bcd(u16(b, 12)))
                add("iManufacturer", str(b[14]))
                add("iProduct", str(b[15]))
                add("iSerialNumber", str(b[16]))
                add("bNumConfigurations", str(b[17]))
            name = "Device Descriptor"
            return (name, "", f)
        if t in (2, 7) and n >= 9:
            add("wTotalLength", str(u16(b, 2)))
            add("bNumInterfaces", str(b[4]))
            add("bConfigurationValue", str(b[5]))
            add("iConfiguration", str(b[6]))
            at = b[7]
            add("bmAttributes", f"0x{at:02X}" + (" Self-powered" if at & 0x40 else " Bus-powered")
                + (" Remote-wakeup" if at & 0x20 else ""))
            add("bMaxPower", f"{b[8] * 2} mA")
            return (f"{name} Descriptor", f"Configuration {b[5]}", f)
        if t == 4 and n >= 9:
            ctx["class"] = b[5]
            add("bInterfaceNumber", str(b[2]))
            add("bAlternateSetting", str(b[3]))
            add("bNumEndpoints", str(b[4]))
            add("bInterfaceClass", f"0x{b[5]:02X} {class_name(b[5])}")
            sub = f"0x{b[6]:02X}"
            prot = f"0x{b[7]:02X}"
            if b[5] == 3:
                sub += " Boot" if b[6] == 1 else ""
                prot += {1: " Keyboard", 2: " Mouse"}.get(b[7], "")
            if b[5] == 8:
                sub += {6: " SCSI transparent", 2: " ATAPI", 4: " UFI"}.get(b[6], "")
                prot += {0x50: " Bulk-Only", 0x62: " UAS"}.get(b[7], "")
            add("bInterfaceSubClass", sub)
            add("bInterfaceProtocol", prot)
            add("iInterface", str(b[8]))
            return ("Interface Descriptor", f"#{b[2]} alt {b[3]} {class_name(b[5])}", f)
        if t == 5 and n >= 7:
            a = b[2]
            ty = EP_TYPES[b[3] & 3]
            mps = u16(b, 4)
            add("bEndpointAddress", ep_name(a))
            add("bmAttributes", f"0x{b[3]:02X} {ty}")
            add("wMaxPacketSize", f"{mps & 0x7FF}" + (f" x{((mps >> 11) & 3) + 1}" if mps >> 11 else ""))
            add("bInterval", str(b[6]))
            return ("Endpoint Descriptor", f"{ep_name(a)} {ty} {mps & 0x7FF} bytes", f)
        if t == 0x21 and n >= 6:
            add("bcdHID", bcd(u16(b, 2)))
            add("bCountryCode", str(b[4]))
            add("bNumDescriptors", str(b[5]))
            for k in range(b[5]):
                o = 6 + 3 * k
                if o + 3 <= n:
                    add(f"Descriptor {k}", f"{DESC_NAMES.get(b[o], hex(b[o]))} length {u16(b, o + 1)}")
            return ("HID Descriptor", f"HID {bcd(u16(b, 2))}", f)
        if t == 0x0B and n >= 8:
            add("bFirstInterface", str(b[2]))
            add("bInterfaceCount", str(b[3]))
            add("bFunctionClass", f"0x{b[4]:02X} {class_name(b[4])}")
            add("bFunctionSubClass", f"0x{b[5]:02X}")
            add("bFunctionProtocol", f"0x{b[6]:02X}")
            add("iFunction", str(b[7]))
            return ("Interface Association Descriptor", f"interfaces {b[2]}..{b[2] + b[3] - 1}", f)
        if t == 0x24 and n >= 3:
            sub = {0: "Header", 1: "Call Management", 2: "Abstract Control Management", 6: "Union"}
            if ctx.get("class") in (2, 0x0A):
                return (f"CDC {sub.get(b[2], f'Functional 0x{b[2]:02X}')} Descriptor", b[3:].hex(" ").upper(), [])
            return ("Class-Specific Interface Descriptor", b[2:].hex(" ").upper(), [])
        if t == 6 and n >= 10:
            add("bcdUSB", bcd(u16(b, 2)))
            add("bDeviceClass", f"0x{b[4]:02X} {class_name(b[4])}")
            add("bMaxPacketSize0", str(b[7]))
            add("bNumConfigurations", str(b[8]))
            return ("Device Qualifier Descriptor", "", f)
        if t == 3:
            return ("String Descriptor", f'"{string_of(b)}"', [])
        if t == 0x0F and n >= 5:
            add("wTotalLength", str(u16(b, 2)))
            add("bNumDeviceCaps", str(b[4]))
            return ("BOS Descriptor", "", f)
        if t == 0x10 and n >= 3:
            caps = {1: "Wireless USB", 2: "USB 2.0 Extension", 3: "SuperSpeed USB", 4: "Container ID",
                    5: "Platform"}
            return ("Device Capability Descriptor", caps.get(b[2], f"type 0x{b[2]:02X}") + "  "
                    + b[3:].hex(" ").upper(), [])
    except Exception:
        pass
    return (f"{name} Descriptor", b.hex(" ").upper(), [])


def descriptor_tree(dtype: int, d: bytes, index=None):
    """detail tree for a descriptor read (data stage of Get Descriptor)"""
    if not d:
        return []
    if dtype == 0x22:
        return [("HID Report Descriptor", f"{len(d)} bytes", hid_report_tree(d))]
    if dtype == 3:
        if index == 0 and len(d) >= 4:
            ids = [u16(d, i) for i in range(2, min(d[0], len(d)) - 1, 2)]
            return [("String Descriptor 0 (languages)", "",
                     [(f"wLANGID[{k}]", f"0x{x:04X} {LANG_IDS.get(x, '')}", []) for k, x in enumerate(ids)])]
        return [("String Descriptor", f'"{string_of(d)}"', [("bLength", str(d[0]), [])])]
    out = []
    ctx = {}
    cur_itf = None
    for t, b in walk(d):
        node = _desc_node(t, b, ctx)
        if t == 4:
            cur_itf = (node[0], node[1], list(node[2]))
            out.append(cur_itf)
        elif cur_itf is not None and t != 0x0B:
            cur_itf[2].append(node)
        else:
            if t == 0x0B:
                cur_itf = None
            out.append(node)
    if dtype in (2, 7) and out:
        # nest interfaces under the configuration
        return [(out[0][0], out[0][1], list(out[0][2]) + out[1:])]
    return out


def parse_config(d: bytes):
    """-> list of interfaces: {num, alt, class, sub, proto, eps: [(addr, type, mps)]}"""
    itfs = []
    cur = None
    for t, b in walk(d):
        if t == 4 and len(b) >= 9:
            cur = {"num": b[2], "alt": b[3], "class": b[5], "sub": b[6], "proto": b[7], "eps": []}
            itfs.append(cur)
        elif t == 5 and len(b) >= 7 and cur is not None:
            cur["eps"].append((b[2], b[3] & 3, u16(b, 4) & 0x7FF))
    return itfs


# ---------------------------------------------------------------------------
# HID report descriptor
# ---------------------------------------------------------------------------
USAGE_PAGES = {0x01: "Generic Desktop", 0x02: "Simulation", 0x05: "Game", 0x06: "Generic Device",
               0x07: "Keyboard/Keypad", 0x08: "LED", 0x09: "Button", 0x0A: "Ordinal", 0x0B: "Telephony",
               0x0C: "Consumer", 0x0D: "Digitizer", 0x0F: "PID", 0x14: "Alphanumeric Display",
               0x20: "Sensor", 0x40: "Medical", 0x84: "Power", 0x85: "Battery"}
GD_USAGES = {0x01: "Pointer", 0x02: "Mouse", 0x04: "Joystick", 0x05: "Game Pad", 0x06: "Keyboard",
             0x07: "Keypad", 0x08: "Multi-axis Controller", 0x30: "X", 0x31: "Y", 0x32: "Z", 0x33: "Rx",
             0x34: "Ry", 0x35: "Rz", 0x36: "Slider", 0x37: "Dial", 0x38: "Wheel", 0x39: "Hat switch",
             0x80: "System Control", 0x81: "System Power Down", 0x82: "System Sleep", 0x83: "System Wake Up"}
CONSUMER_USAGES = {0x01: "Consumer Control", 0xB5: "Scan Next Track", 0xB6: "Scan Previous Track",
                   0xCD: "Play/Pause", 0xE2: "Mute", 0xE9: "Volume Increment", 0xEA: "Volume Decrement",
                   0x238: "AC Pan"}
COLLECTIONS = {0: "Physical", 1: "Application", 2: "Logical", 3: "Report", 4: "Named Array",
               5: "Usage Switch", 6: "Usage Modifier"}
MAIN_ITEMS = {0x8: "Input", 0x9: "Output", 0xB: "Feature", 0xA: "Collection", 0xC: "End Collection"}
GLOBAL_ITEMS = {0x0: "Usage Page", 0x1: "Logical Minimum", 0x2: "Logical Maximum", 0x3: "Physical Minimum",
                0x4: "Physical Maximum", 0x5: "Unit Exponent", 0x6: "Unit", 0x7: "Report Size",
                0x8: "Report ID", 0x9: "Report Count", 0xA: "Push", 0xB: "Pop"}
LOCAL_ITEMS = {0x0: "Usage", 0x1: "Usage Minimum", 0x2: "Usage Maximum", 0x3: "Designator Index",
               0x4: "Designator Minimum", 0x5: "Designator Maximum", 0x7: "String Index",
               0x8: "String Minimum", 0x9: "String Maximum", 0xA: "Delimiter"}


def _main_bits(v):
    a = ["Constant" if v & 1 else "Data", "Variable" if v & 2 else "Array", "Relative" if v & 4 else "Absolute"]
    if v & 8:
        a.append("Wrap")
    if v & 0x10:
        a.append("Non-linear")
    if v & 0x20:
        a.append("No preferred")
    if v & 0x40:
        a.append("Null state")
    return ", ".join(a)


def hid_report_tree(d: bytes):
    root = []
    stack = [root]
    page = 0
    p = 0
    while p < len(d):
        b = d[p]
        if b == 0xFE:  # long item
            n = d[p + 1] if p + 1 < len(d) else 0
            stack[-1].append(("Long item", d[p:p + 3 + n].hex(" ").upper(), []))
            p += 3 + n
            continue
        size = (0, 1, 2, 4)[b & 3]
        typ = (b >> 2) & 3
        tag = b >> 4
        raw = d[p + 1:p + 1 + size]
        v = int.from_bytes(raw, "little") if raw else 0
        sv = int.from_bytes(raw, "little", signed=True) if raw else 0
        hx = d[p:p + 1 + size].hex(" ").upper()
        p += 1 + size
        if typ == 0:
            name = MAIN_ITEMS.get(tag, f"Main 0x{tag:X}")
            if tag == 0xA:
                node = (f"Collection ({COLLECTIONS.get(v, hex(v))})", hx, [])
                stack[-1].append(node)
                stack.append(node[2])
                continue
            if tag == 0xC:
                if len(stack) > 1:
                    stack.pop()
                stack[-1].append(("End Collection", hx, []))
                continue
            stack[-1].append((f"{name} ({_main_bits(v)})", hx, []))
        elif typ == 1:
            name = GLOBAL_ITEMS.get(tag, f"Global 0x{tag:X}")
            if tag == 0:
                page = v
                val = USAGE_PAGES.get(v, "Vendor Defined" if v >= 0xFF00 else f"0x{v:04X}")
            elif tag in (1, 3):
                val = str(sv)
            else:
                val = str(v)
            stack[-1].append((f"{name} ({val})", hx, []))
        elif typ == 2:
            name = LOCAL_ITEMS.get(tag, f"Local 0x{tag:X}")
            if tag in (0, 1, 2):
                if page == 1:
                    val = GD_USAGES.get(v, f"0x{v:02X}")
                elif page == 0x0C:
                    val = CONSUMER_USAGES.get(v, f"0x{v:02X}")
                else:
                    val = f"0x{v:02X}"
            else:
                val = str(v)
            stack[-1].append((f"{name} ({val})", hx, []))
        else:
            stack[-1].append((f"Reserved item 0x{b:02X}", hx, []))
    return root


# ---------------------------------------------------------------------------
# Mass storage Bulk-Only Transport / SCSI
# ---------------------------------------------------------------------------
SCSI_OPS = {
    0x00: "Test Unit Ready", 0x03: "Request Sense", 0x04: "Format Unit", 0x12: "Inquiry",
    0x15: "Mode Select(6)", 0x1A: "Mode Sense(6)", 0x1B: "Start Stop Unit",
    0x1E: "Prevent Allow Medium Removal", 0x23: "Read Format Capacities", 0x25: "Read Capacity(10)",
    0x28: "Read(10)", 0x2A: "Write(10)", 0x2F: "Verify(10)", 0x35: "Synchronize Cache(10)",
    0x55: "Mode Select(10)", 0x5A: "Mode Sense(10)", 0x88: "Read(16)", 0x8A: "Write(16)",
    0x9E: "Read Capacity(16)", 0xA0: "Report LUNs", 0xA8: "Read(12)", 0xAA: "Write(12)",
}
SENSE_KEYS = {0: "No Sense", 1: "Recovered Error", 2: "Not Ready", 3: "Medium Error", 4: "Hardware Error",
              5: "Illegal Request", 6: "Unit Attention", 7: "Data Protect", 8: "Blank Check",
              9: "Vendor Specific", 0xA: "Copy Aborted", 0xB: "Aborted Command", 0xD: "Volume Overflow",
              0xE: "Miscompare"}
ASC_NAMES = {(0x04, 0x01): "Becoming ready", (0x20, 0x00): "Invalid command operation code",
             (0x24, 0x00): "Invalid field in CDB", (0x28, 0x00): "Medium may have changed",
             (0x29, 0x00): "Power on, reset", (0x3A, 0x00): "Medium not present",
             (0x21, 0x00): "LBA out of range", (0x27, 0x00): "Write protected"}
CSW_STATUS = {0: "Passed", 1: "Failed", 2: "Phase Error"}
PERIPH_TYPES = {0: "Direct-access block device", 5: "CD/DVD", 7: "Optical memory", 0x0E: "RBC",
                0x1F: "Unknown"}


def is_cbw(p: bytes | None) -> bool:
    return p is not None and len(p) == 31 and p[:4] == b"USBC"


def is_csw(p: bytes | None) -> bool:
    return p is not None and len(p) == 13 and p[:4] == b"USBS"


class CBW:
    def __init__(self, p: bytes):
        self.tag, self.dlen, self.flags, self.lun, self.cblen = struct.unpack_from("<IIBBB", p, 4)
        self.lun &= 0x0F
        self.cblen &= 0x1F
        self.cdb = p[15:15 + max(1, min(self.cblen, 16))]
        self.op = self.cdb[0]
        self.dir_in = bool(self.flags & 0x80)

    @property
    def name(self):
        return SCSI_OPS.get(self.op, f"SCSI 0x{self.op:02X}")


def cdb_summary(c: CBW) -> str:
    b = c.cdb
    try:
        if c.op in (0x28, 0x2A, 0x2F) and len(b) >= 10:
            return f"LBA={struct.unpack_from('>I', b, 2)[0]} Blocks={struct.unpack_from('>H', b, 7)[0]}"
        if c.op in (0x88, 0x8A) and len(b) >= 16:
            return f"LBA={struct.unpack_from('>Q', b, 2)[0]} Blocks={struct.unpack_from('>I', b, 10)[0]}"
        if c.op in (0xA8, 0xAA) and len(b) >= 12:
            return f"LBA={struct.unpack_from('>I', b, 2)[0]} Blocks={struct.unpack_from('>I', b, 6)[0]}"
        if c.op == 0x1A and len(b) >= 6:
            return f"Page=0x{b[2] & 0x3F:02X}"
        if c.op == 0x1B and len(b) >= 5:
            return {0: "Stop", 1: "Start", 2: "Eject", 3: "Load"}.get(b[4] & 3, "")
        if c.op == 0x1E and len(b) >= 5:
            return "Prevent" if b[4] & 1 else "Allow"
    except Exception:
        pass
    return ""


def scsi_data_summary(c: CBW, d: bytes) -> str:
    try:
        if c.op == 0x12 and len(d) >= 36:
            return (f"{d[8:16].decode('ascii', 'replace').strip()} {d[16:32].decode('ascii', 'replace').strip()} "
                    f"{d[32:36].decode('ascii', 'replace').strip()}")
        if c.op == 0x25 and len(d) >= 8:
            last, bl = struct.unpack_from(">II", d, 0)
            return f"Last LBA={last} Block={bl} ({(last + 1) * bl / 1e9:.2f} GB)"
        if c.op == 0x03 and len(d) >= 14:
            sk = d[2] & 0x0F
            asc = ASC_NAMES.get((d[12], d[13]), f"ASC=0x{d[12]:02X} ASCQ=0x{d[13]:02X}")
            return f"Sense Key = {SENSE_KEYS.get(sk, sk)}, {asc}"
        if c.op == 0x23 and len(d) >= 12:
            n, bl = struct.unpack_from(">I", d, 4)[0], struct.unpack_from(">I", d, 8)[0] & 0xFFFFFF
            return f"Blocks={n} Block={bl}"
    except Exception:
        pass
    return ""


def cbw_tree(c: CBW, raw: bytes):
    k = [
        ("dCBWSignature", raw[:4].decode("ascii", "replace"), []),
        ("dCBWTag", f"0x{c.tag:08X}", []),
        ("dCBWDataTransferLength", str(c.dlen), []),
        ("bmCBWFlags", f"0x{c.flags:02X} ({'Data-In' if c.dir_in else 'Data-Out'})", []),
        ("bCBWLUN", str(c.lun), []),
        ("bCBWCBLength", str(c.cblen), []),
        ("CBWCB", f"{c.name}  {cdb_summary(c)}".strip(), [("Bytes", c.cdb.hex(" ").upper(), [])]),
    ]
    return [("Command Block Wrapper", c.name, k)]


def csw_tree(p: bytes):
    tag, res, st = struct.unpack_from("<IIB", p, 4)
    return [("Command Status Wrapper", CSW_STATUS.get(st, str(st)), [
        ("dCSWSignature", p[:4].decode("ascii", "replace"), []),
        ("dCSWTag", f"0x{tag:08X}", []),
        ("dCSWDataResidue", str(res), []),
        ("bCSWStatus", f"{st} ({CSW_STATUS.get(st, '?')})", []),
    ])]


def scsi_data_tree(c: CBW, d: bytes):
    out = []
    try:
        if c.op == 0x12 and len(d) >= 36:
            out = [("Peripheral type", PERIPH_TYPES.get(d[0] & 0x1F, hex(d[0] & 0x1F)), []),
                   ("Removable", "Yes" if d[1] & 0x80 else "No", []),
                   ("Version", f"0x{d[2]:02X}", []),
                   ("Vendor", d[8:16].decode("ascii", "replace").strip(), []),
                   ("Product", d[16:32].decode("ascii", "replace").strip(), []),
                   ("Revision", d[32:36].decode("ascii", "replace").strip(), [])]
        elif c.op == 0x03 and len(d) >= 14:
            out = [("Response code", f"0x{d[0] & 0x7F:02X}", []),
                   ("Sense key", f"{d[2] & 0xF} {SENSE_KEYS.get(d[2] & 0xF, '')}", []),
                   ("ASC / ASCQ", f"0x{d[12]:02X} / 0x{d[13]:02X} {ASC_NAMES.get((d[12], d[13]), '')}", [])]
        elif c.op == 0x25 and len(d) >= 8:
            last, bl = struct.unpack_from(">II", d, 0)
            out = [("Last LBA", str(last), []), ("Block length", str(bl), []),
                   ("Capacity", f"{(last + 1) * bl:,} bytes", [])]
    except Exception:
        out = []
    return [("SCSI data", f"{len(d)} bytes", out)] if out else []


def hexs(b: bytes, limit: int = 64) -> str:
    if len(b) > limit:
        return b[:limit].hex(" ").upper() + " ..."
    return b.hex(" ").upper()
