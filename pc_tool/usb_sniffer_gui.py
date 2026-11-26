"""
Pico USB Sniffer - live capture GUI

  python usb_sniffer_gui.py [--demo | capture.pusb]

Start/stop live streaming capture from the Pico, view the traffic in real
time as a Data Center style hierarchy (transfer -> transaction -> packet),
save the capture (.pusb) or export CSV / text.
"""
from __future__ import annotations

import os
import queue
import struct
import sys
import time
from array import array
from bisect import bisect_left, bisect_right

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPointF, QRect, Qt, QTimer
from PySide6.QtGui import (QAction, QBrush, QColor, QFont, QGuiApplication, QIcon, QKeySequence, QPainter, QPalette,
                           QPolygonF)
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPlainTextEdit, QProgressDialog, QPushButton, QRadioButton, QSpinBox, QSplitter, QStyle,
    QStyledItemDelegate, QStyleOptionViewItem, QTableView, QTabWidget, QToolBar, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

# packaged .exe: the folder of the exe, not the bundle folder
HERE = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
sys.path.insert(0, HERE)

import capture as C  # noqa: E402
import export_csv  # noqa: E402
import export_pcap  # noqa: E402
import export_usbpcap  # noqa: E402
import protocol as P  # noqa: E402
import sources  # noqa: E402

APP_NAME = "Pico USB Sniffer"


def _data_dir():
    """folder for captures / error.log: next to the tool, or the user profile if that is read-only"""
    for base in (HERE, os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "PicoUsbSniffer")):
        try:
            d = os.path.join(base, "captures")
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, f".write_test_{os.getpid()}")
            with open(probe, "w"):
                pass
            os.remove(probe)
            return base
        except OSError:
            continue
    return HERE


ICON_FILE = os.path.join(getattr(sys, "_MEIPASS", HERE), "app.ico")
DATA_DIR = _data_dir()
CAPTURE_DIR = os.path.join(DATA_DIR, "captures")
DEMO_PORT = "DEMO (no hardware)"

ROLE_DEPTH = Qt.UserRole + 1
ROLE_EXP = Qt.UserRole + 2   # 0 leaf, 1 collapsed, 2 expanded
ROLE_CAT = Qt.UserRole + 3

# colours (light theme)
ICON = {
    "ctrl": "#E8A317", "setup": "#F0B400", "in": "#2F7FD8", "out": "#2E9E44", "msc": "#8E44AD",
    "idle": "#A0A0A0", "nak": "#B5B5B5", "event": "#7E57C2", "reset": "#E65100", "err": "#D32F2F",
    "data": "#5C6BC0", "hs": "#26A69A", "pkt": "#78909C",
}
ROW_BG = {
    "ctrl": "#FFF7E0", "setup": "#FFF3D1", "in": "#EDF5FF", "out": "#EDF9EF", "msc": "#F5ECFB",
    "event": "#EFEAF8", "reset": "#FFEBD2", "err": "#FFE5E5",
}
ICON_C = {k: QColor(v) for k, v in ICON.items()}
BG_C = {k: QColor(v) for k, v in ROW_BG.items()}
BG_CHILD = {k: QColor(v).lighter(104) for k, v in ROW_BG.items()}
FG_IDLE = QColor("#8A8A8A")
FG_ERR = QColor("#C00000")
FG_WARN = QColor("#B45F06")
FG_DEFAULT = QColor("#000000")
COL_WIDTHS = (30, 70, 115, 75, 55, 50, 35, 30, 330)


class Entry:
    __slots__ = ("depth", "node", "expanded")

    def __init__(self, depth, node):
        self.depth = depth
        self.node = node
        self.expanded = False


# ---------------------------------------------------------------------------
# Virtual "flat tree" model: the top level is the (possibly filtered) row
# index of the capture store; expanded rows insert their children inline.
# A QTreeView would need per-row bookkeeping for millions of top level rows,
# a table with inline expansion stays O(expanded rows).
# ---------------------------------------------------------------------------
class TreeModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self.store: C.CaptureStore | None = None
        self.flt = C.RowFilter()
        self.view: array | None = None
        self._n = 0
        self._scanned = 0
        self.exp: dict[int, list[Entry]] = {}
        self._keys: list[int] = []
        self._disp: list[int] = []
        self._cum: list[int] = []
        self._extra = 0
        self.mono = QFont("Consolas", 9)
        self.mono.setStyleHint(QFont.Monospace)

    # -------------------------------------------------------------- setup
    def set_store(self, store):
        self.beginResetModel()
        self.store = store
        self._n = 0
        self._scanned = 0
        self.exp = {}
        self._rebuild()
        self.view = None if self.flt.is_pass_all() else array("I")
        self.endResetModel()
        self.refresh()

    def set_filter(self, flt: C.RowFilter):
        self.flt = flt
        self.set_store(self.store)

    def refresh(self) -> bool:
        if not self.store:
            return False
        total = self.store.row_count()
        if self.view is None:
            new = total
        else:
            st, f, v = self.store, self.flt, self.view
            for i in range(self._scanned, total):
                if st.match(i, f):
                    v.append(i)
            self._scanned = total
            new = len(v)
        if new > self._n:
            first = self._n + self._extra
            self.beginInsertRows(QModelIndex(), first, first + new - self._n - 1)
            self._n = new
            self.endInsertRows()
            return True
        return False

    # ----------------------------------------------------------- mapping
    def _rebuild(self):
        self._keys = sorted(self.exp)
        c = 0
        self._disp = []
        self._cum = []
        for k in self._keys:
            self._cum.append(c)
            self._disp.append(k + c)
            c += len(self.exp[k])
        self._extra = c

    def top_count(self):
        return self._n

    def row_id(self, k):
        return k if self.view is None else self.view[k]

    def locate(self, d):
        """display row -> (top position, child index or -1)"""
        i = bisect_right(self._disp, d) - 1
        if i < 0:
            return d, -1
        k = self._keys[i]
        dp = self._disp[i]
        ex = len(self.exp[k])
        if d - dp <= ex:
            return k, d - dp - 1
        return d - (self._cum[i] + ex), -1

    def expanded(self, k):
        """expansion of a top row for the CSV export: None (collapsed) or
        {child position: same for that child}, expanded children only"""
        lst = self.exp.get(k)
        if lst is None:
            return None
        root = {}
        cur, cnt = [root], [-1]
        for e in lst:
            d = e.depth
            del cur[d:], cnt[d:]
            cnt[d - 1] += 1
            if e.expanded:
                sub = cur[d - 1][cnt[d - 1]] = {}
                cur.append(sub)
                cnt.append(-1)
        return root

    def top_display_row(self, k):
        i = bisect_left(self._keys, k)
        return k + (self._cum[i] if i < len(self._keys) else self._extra)

    def node_at(self, d):
        k, j = self.locate(d)
        if k >= self._n or k < 0:
            return None, 0, 0
        if j < 0:
            n = self.store.top_node(self.row_id(k))
            return n, 0, (2 if k in self.exp else (1 if n.kids else 0))
        e = self.exp[k][j]
        return e.node, e.depth, (2 if e.expanded else (1 if e.node.kids else 0))

    # --------------------------------------------------------- expansion
    def is_expanded(self, d):
        return self.node_at(d)[2] == 2

    def toggle(self, d, want=None):
        k, j = self.locate(d)
        if k >= self._n or k < 0:
            return
        if j < 0:
            if k in self.exp:
                if want is True:
                    return
                n = len(self.exp[k])
                self.beginRemoveRows(QModelIndex(), d + 1, d + n)
                del self.exp[k]
                self._rebuild()
                self.endRemoveRows()
            else:
                if want is False:
                    return
                node = self.store.top_node(self.row_id(k))
                kids = self._kids(node, 1)
                if not kids:
                    return
                self.beginInsertRows(QModelIndex(), d + 1, d + len(kids))
                self.exp[k] = kids
                self._rebuild()
                self.endInsertRows()
        else:
            lst = self.exp[k]
            e = lst[j]
            if e.expanded:
                if want is True:
                    return
                m = j + 1
                while m < len(lst) and lst[m].depth > e.depth:
                    m += 1
                e.expanded = False
                if m > j + 1:
                    self.beginRemoveRows(QModelIndex(), d + 1, d + m - j - 1)
                    del lst[j + 1:m]
                    self._rebuild()
                    self.endRemoveRows()
            else:
                if want is False:
                    return
                kids = self._kids(e.node, e.depth + 1)
                if not kids:
                    return
                self.beginInsertRows(QModelIndex(), d + 1, d + len(kids))
                lst[j + 1:j + 1] = kids
                e.expanded = True
                self._rebuild()
                self.endInsertRows()
        ix = self.index(d, C.COL_RECORD)
        self.dataChanged.emit(ix, ix)

    @staticmethod
    def _kids(node, depth):
        if not node.kids:
            return []
        try:
            return [Entry(depth, n) for n in node.kids()]
        except Exception as e:
            return [Entry(depth, C.Node(("", "", "", "", "", "ERR", "", "", "?", f"decode error: {e}"), "err",
                                        C.RF_ERROR))]

    def expand_all_children(self, d):
        """expand a row and all its descendants"""
        self.toggle(d, True)
        _node, depth, _st = self.node_at(d)
        r = d + 1
        while r < self.rowCount():
            _n, dep, s = self.node_at(r)
            if dep <= depth:
                break
            if s == 1:
                self.toggle(r, True)
            r += 1

    def parent_row(self, d):
        k, j = self.locate(d)
        if j < 0:
            return -1
        lst = self.exp[k]
        dep = lst[j].depth
        top = self.top_display_row(k)
        for m in range(j - 1, -1, -1):
            if lst[m].depth < dep:
                return top + 1 + m
        return top

    # ------------------------------------------------------------- Qt api
    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else self._n + self._extra

    def columnCount(self, parent=QModelIndex()):
        return len(C.COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return C.COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not self.store:
            return None
        col = index.column()
        if role == Qt.DisplayRole:
            n, _, _ = self.node_at(index.row())
            return n.cols[col] if n else None
        if role == Qt.ForegroundRole:
            n, _, _ = self.node_at(index.row())
            if n is None:
                return None
            fl = n.flags
            if fl & C.RF_ERROR:
                return QBrush(FG_ERR)
            if fl & (C.RF_IDLE | C.RF_NAK):
                return QBrush(FG_IDLE)
            if fl & (C.RF_STALL | C.RF_INCOMPLETE) and n.cat in ("ctrl", "msc"):
                return QBrush(FG_WARN)
            return QBrush(FG_DEFAULT)
        if role == Qt.BackgroundRole:
            n, depth, _ = self.node_at(index.row())
            if n is None:
                return None
            cat = "err" if (n.flags & C.RF_ERROR and depth == 0) else n.cat
            c = (BG_C if depth == 0 else BG_CHILD).get(cat)
            return QBrush(c) if c is not None else None
        if role == ROLE_DEPTH:
            return self.node_at(index.row())[1]
        if role == ROLE_EXP:
            return self.node_at(index.row())[2]
        if role == ROLE_CAT:
            n = self.node_at(index.row())[0]
            return n.cat if n else ""
        if role == Qt.FontRole and col == 9:
            return self.mono
        if role == Qt.TextAlignmentRole and col in (1, 3, 4, 6, 7):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return None


class RecordDelegate(QStyledItemDelegate):
    """Record column: indentation, expand arrow and a coloured type icon"""
    INDENT = 16

    def paint(self, painter: QPainter, option, index):
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        text = opt.text
        opt.text = ""
        w = opt.widget
        style = w.style() if w else QApplication.style()
        style.drawControl(QStyle.CE_ItemViewItem, opt, painter, w)
        depth = index.data(ROLE_DEPTH) or 0
        exp = index.data(ROLE_EXP) or 0
        cat = index.data(ROLE_CAT) or ""
        r = option.rect
        x = r.left() + 4 + depth * self.INDENT
        cy = r.center().y() + 0.5
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        selected = bool(option.state & QStyle.State_Selected)
        if exp:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor("#FFFFFF") if selected else QColor("#505050"))
            if exp == 1:
                pts = [QPointF(x + 2, cy - 4.5), QPointF(x + 7.5, cy), QPointF(x + 2, cy + 4.5)]
            else:
                pts = [QPointF(x, cy - 2.5), QPointF(x + 9, cy - 2.5), QPointF(x + 4.5, cy + 3)]
            painter.drawPolygon(QPolygonF(pts))
        x += 13
        col = ICON_C.get(cat)
        if col is not None:
            painter.setPen(col.darker(130))
            painter.setBrush(col)
            painter.drawRoundedRect(QRect(int(x), int(cy - 5), 10, 10), 2, 2)
        x += 15
        fg = index.data(Qt.ForegroundRole)
        painter.setPen(opt.palette.highlightedText().color() if selected else
                       (fg.color() if fg is not None else FG_DEFAULT))
        tr = QRect(int(x), r.top(), max(0, r.right() - int(x) - 2), r.height())
        painter.setFont(opt.font)
        painter.drawText(tr, Qt.AlignVCenter | Qt.AlignLeft,
                         opt.fontMetrics.elidedText(text, Qt.ElideRight, tr.width()))
        painter.restore()

    @classmethod
    def arrow_hit(cls, rect: QRect, depth: int, x: int) -> bool:
        ax = rect.left() + 4 + depth * cls.INDENT
        return ax - 3 <= x <= ax + 12


class TrafficView(QTableView):
    def __init__(self, model: TreeModel):
        super().__init__()
        self.tm = model
        self.setModel(model)

    def mousePressEvent(self, ev):
        pos = ev.position().toPoint()
        idx = self.indexAt(pos)
        if idx.isValid() and idx.column() == C.COL_RECORD and ev.button() == Qt.LeftButton:
            depth = idx.data(ROLE_DEPTH) or 0
            if idx.data(ROLE_EXP) and RecordDelegate.arrow_hit(self.visualRect(idx), depth, pos.x()):
                self.setCurrentIndex(idx)
                self.tm.toggle(idx.row())
                return
        super().mousePressEvent(ev)

    def mouseDoubleClickEvent(self, ev):
        idx = self.indexAt(ev.position().toPoint())
        if idx.isValid():
            self.tm.toggle(idx.row())
            return
        super().mouseDoubleClickEvent(ev)

    def keyPressEvent(self, ev):
        idx = self.currentIndex()
        if idx.isValid():
            r = idx.row()
            k = ev.key()
            if k == Qt.Key_Asterisk:
                self.tm.expand_all_children(r)
                return
            if k in (Qt.Key_Right, Qt.Key_Plus):
                self.tm.toggle(r, True)
                return
            if k in (Qt.Key_Left, Qt.Key_Minus):
                if self.tm.is_expanded(r):
                    self.tm.toggle(r, False)
                else:
                    p = self.tm.parent_row(r)
                    if p >= 0:
                        self.selectRow(p)
                        self.scrollTo(self.tm.index(p, 0))
                return
            if k in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space):
                self.tm.toggle(r)
                return
        super().keyPressEvent(ev)


def fill_tree(widget: QTreeWidget, nodes, parent=None, depth=0):
    for name, value, kids in nodes:
        it = QTreeWidgetItem([name, value])
        it.setToolTip(1, value)
        if parent is None:
            widget.addTopLevelItem(it)
        else:
            parent.addChild(it)
        if kids:
            fill_tree(widget, kids, it, depth + 1)
        it.setExpanded(depth < 3)


def sync_stats(widget: QTreeWidget, nodes, parent=None, depth=0, err=False):
    """Update a (name, count, kids) tree in place, keeping what the user expanded / collapsed."""
    have = widget.topLevelItemCount() if parent is None else parent.childCount()
    for i, (name, val, kids) in enumerate(nodes):
        if i < have:
            it = widget.topLevelItem(i) if parent is None else parent.child(i)
        else:
            it = QTreeWidgetItem()
            it.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
            if parent is None:
                widget.addTopLevelItem(it)
            else:
                parent.addChild(it)
            it.setExpanded(depth < 2)
        is_err = err or name == "Errors"
        it.setText(0, name)
        it.setText(1, f"{val:,}")
        it.setForeground(1, QBrush(FG_ERR if is_err and val else FG_DEFAULT))
        if depth == 0:
            f = it.font(0)
            f.setBold(True)
            it.setFont(0, f)
        sync_stats(widget, kids, it, depth + 1, is_err)
    for i in range(have - 1, len(nodes) - 1, -1):
        if parent is None:
            widget.takeTopLevelItem(i)
        else:
            parent.takeChild(i)


def _titled(label: QLabel, w):
    """A pane with a small header line, like the Data Center side panels."""
    box = QWidget()
    lay = QVBoxLayout(box)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(0)
    label.setStyleSheet("background:#DCE6F2;border:1px solid #B8C7DA;padding:2px 6px;font-weight:bold")
    lay.addWidget(label)
    lay.addWidget(w)
    return box


class WiresharkDialog(QDialog):
    """format of the Wireshark export and, if the enumeration was not captured, the descriptors to add"""
    REF_FILE = os.path.join(DATA_DIR, "descriptor_reference.txt")  # last reference file used

    def __init__(self, parent, missing):
        super().__init__(parent)
        self.setWindowTitle("Export to Wireshark")
        lay = QVBoxLayout(self)
        self.usbpcap = QRadioButton("USBPcap transfers - same layout as a Wireshark capture on Windows (usbhid.data ...)")
        self.packets = QRadioButton("USB packets - every token / data / handshake, errors included (usbll)")
        self.usbpcap.setChecked(True)
        lay.addWidget(self.usbpcap)
        lay.addWidget(self.packets)
        self.box = QWidget()
        b = QVBoxLayout(self.box)
        b.setContentsMargins(20, 8, 0, 8)
        b.addWidget(QLabel(f"The enumeration of device {', '.join(map(str, missing))} is not in this capture.\n"
                           "Wireshark needs descriptors to show HID data:"))
        self.generic = QRadioButton("add generic HID descriptors (VID/PID 0000)")
        self.ref = QRadioButton("take them from a reference file if its endpoints match, else generic HID")
        self.none = QRadioButton("add nothing (data is shown as usb.capdata)")
        self.path = QLineEdit()
        self.path.setPlaceholderText("USBPcap .pcapng or .pusb with the enumeration")
        browse = QPushButton("Browse...")
        browse.clicked.connect(self._browse)
        row = QHBoxLayout()
        row.setContentsMargins(20, 0, 0, 0)
        row.addWidget(self.path)
        row.addWidget(browse)
        b.addWidget(self.generic)
        b.addWidget(self.ref)
        b.addLayout(row)
        b.addWidget(self.none)
        lay.addWidget(self.box)
        self.box.setVisible(bool(missing))
        self.usbpcap.toggled.connect(self.box.setEnabled)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        try:
            with open(self.REF_FILE, encoding="utf-8") as f:
                self.path.setText(f.read().strip())
        except OSError:
            pass
        (self.ref if os.path.isfile(self.path.text()) else self.generic).setChecked(True)
        self.path.textEdited.connect(lambda _t: self.ref.setChecked(True))
        self.reference = None

    def _browse(self):
        p, _ = QFileDialog.getOpenFileName(self, "Reference with descriptors", self.path.text(),
                                           "Captures (*.pcapng *.pusb)")
        if p:
            self.path.setText(p)
            self.ref.setChecked(True)

    def accept(self):
        self.reference = None
        if self.usbpcap.isChecked() and self.ref.isChecked() and self.box.isVisibleTo(self):
            path = self.path.text().strip().strip('"')
            try:
                self.reference = export_usbpcap.load_reference(path)
            except Exception as e:
                QMessageBox.warning(self, APP_NAME, f"Cannot use the reference file:\n{e}")
                return
            try:
                with open(self.REF_FILE, "w", encoding="utf-8") as f:
                    f.write(path)
            except OSError:
                pass
        super().accept()


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1450, 900)
        os.makedirs(CAPTURE_DIR, exist_ok=True)

        self.store: C.CaptureStore | None = None
        self.worker = None
        self.running = False
        self.t_start = 0.0
        self.t_stop = 0.0
        self.saved = True
        self.logq: queue.SimpleQueue = queue.SimpleQueue()
        self._rate_last = (time.monotonic(), 0)
        self._rate = 0.0
        self._dev_version = -1

        self.model = TreeModel()
        self._build_ui()
        self.refresh_ports()
        self._set_running(False)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(100)
        self.stat_timer = QTimer(self)
        self.stat_timer.timeout.connect(self._update_stats)
        self.stat_timer.start(500)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        st = self.style()
        tb = QToolBar("Capture")
        tb.setMovable(False)
        self.addToolBar(tb)

        tb.addWidget(QLabel(" Port: "))
        self.port_cb = QComboBox()
        self.port_cb.setMinimumWidth(200)
        tb.addWidget(self.port_cb)
        a = QAction(st.standardIcon(QStyle.SP_BrowserReload), "Refresh ports", self)
        a.triggered.connect(self.refresh_ports)
        tb.addAction(a)
        tb.addSeparator()

        tb.addWidget(QLabel(" Speed: "))
        self.speed_cb = QComboBox()
        self.speed_cb.addItem("Auto detect", "A")
        self.speed_cb.addItem("Full Speed (12 Mb/s)", "F")
        self.speed_cb.addItem("Low Speed (1.5 Mb/s)", "L")
        tb.addWidget(self.speed_cb)
        self.fold_sof_cb = QCheckBox("Fold SOF")
        self.fold_sof_cb.setChecked(True)
        self.fold_sof_cb.setToolTip("Collapse SOF / LS keep-alive into summary rows (saves bandwidth)")
        self.fold_nak_cb = QCheckBox("Fold IN-NAK")
        self.fold_nak_cb.setChecked(True)
        self.fold_nak_cb.setToolTip("Collapse IN+NAK polling of interrupt/bulk endpoints into summary rows.\n"
                                    "Endpoint 0 is never folded (shown as [N POLL] inside control transfers).")
        self.reconnect_cb = QCheckBox("Auto-reconnect")
        self.reconnect_cb.setChecked(True)
        self.reconnect_cb.setToolTip("If the Pico disappears during a long capture, reopen and restart automatically")
        for w in (self.fold_sof_cb, self.fold_nak_cb, self.reconnect_cb):
            tb.addWidget(w)
        tb.addSeparator()

        self.start_btn = QPushButton(st.standardIcon(QStyle.SP_MediaPlay), " Start")
        self.start_btn.setStyleSheet("QPushButton{background:#2E9E44;color:white;font-weight:bold;padding:4px 14px}"
                                     "QPushButton:disabled{background:#9BC9A5}")
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn = QPushButton(st.standardIcon(QStyle.SP_MediaStop), " Stop")
        self.stop_btn.setStyleSheet("QPushButton{background:#C62828;color:white;font-weight:bold;padding:4px 14px}"
                                    "QPushButton:disabled{background:#E3A3A3}")
        self.stop_btn.clicked.connect(self.stop_capture)
        tb.addWidget(self.start_btn)
        tb.addWidget(self.stop_btn)
        tb.addSeparator()

        self.save_act = QAction(st.standardIcon(QStyle.SP_DialogSaveButton), "Save", self)
        self.save_act.setShortcut(QKeySequence.Save)
        self.save_act.triggered.connect(self.save_capture)
        self.open_act = QAction(st.standardIcon(QStyle.SP_DialogOpenButton), "Open", self)
        self.open_act.setShortcut(QKeySequence.Open)
        self.open_act.triggered.connect(lambda: self.open_capture())
        tb.addAction(self.save_act)
        tb.addAction(self.open_act)
        tb.addSeparator()
        self.autoscroll_cb = QCheckBox("Autoscroll")
        self.autoscroll_cb.setChecked(True)
        tb.addWidget(self.autoscroll_cb)

        # filter / find bar
        self.addToolBarBreak()
        fb = QToolBar("Filter")
        fb.setMovable(False)
        self.addToolBar(fb)
        fb.addWidget(QLabel(" Filter  Dev: "))
        self.dev_sp = QSpinBox()
        self.dev_sp.setRange(-1, 127)
        self.dev_sp.setSpecialValueText("any")
        self.dev_sp.setValue(-1)
        fb.addWidget(self.dev_sp)
        fb.addWidget(QLabel("  Ep: "))
        self.ep_sp = QSpinBox()
        self.ep_sp.setRange(-1, 15)
        self.ep_sp.setSpecialValueText("any")
        self.ep_sp.setValue(-1)
        fb.addWidget(self.ep_sp)
        self.hide_idle_cb = QCheckBox("Hide SOF/idle")
        self.hide_nak_cb = QCheckBox("Hide NAK")
        self.err_only_cb = QCheckBox("Errors only")
        for w in (self.hide_idle_cb, self.hide_nak_cb, self.err_only_cb):
            fb.addWidget(w)
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self.apply_filter)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_filter)
        fb.addWidget(apply_btn)
        fb.addWidget(clear_btn)
        fb.addSeparator()
        fb.addWidget(QLabel(" Find: "))
        self.find_edit = QLineEdit()
        self.find_edit.setPlaceholderText("text in Record / Summary (Enter = next)")
        self.find_edit.setMinimumWidth(240)
        self.find_edit.returnPressed.connect(lambda: self.find(True))
        fb.addWidget(self.find_edit)
        prev_btn = QPushButton("◀")
        prev_btn.setToolTip("Find previous (Shift+F3)")
        prev_btn.clicked.connect(lambda: self.find(False))
        next_btn = QPushButton("▶")
        next_btn.setToolTip("Find next (F3)")
        next_btn.clicked.connect(lambda: self.find(True))
        fb.addWidget(prev_btn)
        fb.addWidget(next_btn)
        fb.addSeparator()
        end_btn = QPushButton("Go to end")
        end_btn.clicked.connect(lambda: self.table.scrollToBottom())
        fb.addWidget(end_btn)
        f3 = QAction(self)
        f3.setShortcut(QKeySequence("F3"))
        f3.triggered.connect(lambda: self.find(True))
        sf3 = QAction(self)
        sf3.setShortcut(QKeySequence("Shift+F3"))
        sf3.triggered.connect(lambda: self.find(False))
        cf = QAction(self)
        cf.setShortcut(QKeySequence.Find)
        cf.triggered.connect(lambda: (self.find_edit.setFocus(), self.find_edit.selectAll()))
        self.addActions([f3, sf3, cf])

        # menu
        m = self.menuBar().addMenu("&File")
        m.addAction(self.open_act)
        m.addAction(self.save_act)
        exp = QAction("Export CSV / text...", self)
        exp.triggered.connect(self.export_rows)
        m.addAction(exp)
        ws = QAction("Export Wireshark (.pcapng)...", self)
        ws.triggered.connect(self.export_wireshark)
        m.addAction(ws)
        oc = QAction("Open captures folder", self)
        oc.triggered.connect(lambda: os.startfile(CAPTURE_DIR) if hasattr(os, "startfile") else None)
        m.addAction(oc)
        m.addSeparator()
        q = QAction("Exit", self)
        q.triggered.connect(self.close)
        m.addAction(q)
        vm = self.menuBar().addMenu("&View")
        ea = QAction("Expand selected row (all levels)    *", self)
        ea.triggered.connect(self._expand_selected)
        vm.addAction(ea)
        ca = QAction("Collapse all", self)
        ca.triggered.connect(lambda: self.model.set_store(self.store))
        vm.addAction(ca)
        dm = self.menuBar().addMenu("&Device")
        info = QAction("Query device info", self)
        info.triggered.connect(self.query_info)
        dm.addAction(info)
        boot = QAction("Reboot Pico to BOOTSEL (firmware update)", self)
        boot.triggered.connect(self.reboot_bootsel)
        dm.addAction(boot)
        hm = self.menuBar().addMenu("&Help")
        keys = QAction("Keyboard shortcuts", self)
        keys.triggered.connect(lambda: QMessageBox.information(
            self, APP_NAME,
            "Click the arrow / double-click / Enter: expand or collapse\n"
            "Right / +: expand     Left / -: collapse or go to parent\n"
            "*: expand all levels of the selected row\n"
            "Ctrl+F: find     F3 / Shift+F3: next / previous\n"
            "Ctrl+C: copy selected rows"))
        hm.addAction(keys)

        # traffic table
        self.table = TrafficView(self.model)
        self.table.setItemDelegateForColumn(C.COL_RECORD, RecordDelegate(self.table))
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setWordWrap(False)
        self.table.setShowGrid(False)
        self.table.setFont(QFont("Segoe UI", 9))
        vh = self.table.verticalHeader()
        vh.setVisible(False)
        vh.setSectionResizeMode(QHeaderView.Fixed)
        vh.setDefaultSectionSize(20)
        hh = self.table.horizontalHeader()
        for c, w in enumerate(COL_WIDTHS):
            self.table.setColumnWidth(c, w)
        hh.setStretchLastSection(True)
        self.table.selectionModel().currentRowChanged.connect(self._row_selected)
        self.table.verticalScrollBar().valueChanged.connect(self._scrolled)
        copy = QAction("Copy", self.table)
        copy.setShortcut(QKeySequence.Copy)
        copy.triggered.connect(self.copy_rows)
        self.table.addAction(copy)

        # bottom left: decoded fields / log
        self.tabs = QTabWidget()
        self.detail = QTreeWidget()
        self.detail.setHeaderLabels(["Field", "Value"])
        self.detail.setColumnWidth(0, 300)
        self.detail.setFont(QFont("Consolas", 9))
        self.logw = QPlainTextEdit()
        self.logw.setReadOnly(True)
        self.logw.setMaximumBlockCount(5000)
        self.logw.setFont(QFont("Consolas", 9))
        self.tabs.addTab(self.detail, "Details")
        self.tabs.addTab(self.logw, "Log")

        # bottom right: Data Center style hex dump of the selected row
        self.hex = QPlainTextEdit()
        self.hex.setReadOnly(True)
        self.hex.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.hex.setFont(QFont("Consolas", 10))
        self.hex_title = QLabel("Data")
        hexbox = _titled(self.hex_title, self.hex)

        bottom = QSplitter(Qt.Horizontal)
        bottom.addWidget(self.tabs)
        bottom.addWidget(hexbox)
        bottom.setSizes([620, 420])

        left = QSplitter(Qt.Vertical)
        left.addWidget(self.table)
        left.addWidget(bottom)
        left.setStretchFactor(0, 4)
        left.setStretchFactor(1, 1)
        left.setSizes([600, 260])

        # right: navigator (devices / descriptors) + statistics
        self.devices = QTreeWidget()
        self.devices.setHeaderLabels(["Device / descriptor", "Value"])
        self.devices.setColumnWidth(0, 260)
        self.devices.setFont(QFont("Consolas", 9))
        self.stats = QTreeWidget()
        self.stats.setHeaderLabels(["Statistic", "Count"])
        self.stats.setColumnWidth(0, 250)
        self.stats.headerItem().setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
        right = QSplitter(Qt.Vertical)
        right.addWidget(_titled(QLabel("Navigator"), self.devices))
        right.addWidget(_titled(QLabel("Statistics"), self.stats))
        right.setSizes([330, 530])

        main = QSplitter(Qt.Horizontal)
        main.addWidget(left)
        main.addWidget(right)
        main.setStretchFactor(0, 3)
        main.setStretchFactor(1, 1)
        main.setSizes([1080, 370])
        self.setCentralWidget(main)

        # status bar
        sb = self.statusBar()
        self.lbl_state = QLabel("Idle")
        self.lbl_time = QLabel("00:00:00")
        self.lbl_rows = QLabel("Rows: 0")
        self.lbl_rx = QLabel("Rx: 0 B")
        self.lbl_dev = QLabel("Device: -")
        self.lbl_file = QLabel("")
        for w in (self.lbl_state, self.lbl_time, self.lbl_rows, self.lbl_rx, self.lbl_dev):
            w.setStyleSheet("padding: 0 10px")
            sb.addWidget(w)
        sb.addPermanentWidget(self.lbl_file)

    def log(self, text):
        self.logq.put(time.strftime("%H:%M:%S ") + text)

    def _sel_row(self):
        ix = self.table.currentIndex()
        return ix.row() if ix.isValid() else -1

    def _expand_selected(self):
        r = self._sel_row()
        if r >= 0:
            self.model.expand_all_children(r)

    # -------------------------------------------------------------- ports
    def refresh_ports(self):
        cur = self.port_cb.currentData()
        self.port_cb.clear()
        try:
            from serial.tools import list_ports
            ports = sorted(list_ports.comports(), key=lambda p: (p.vid != 0x2E8A, p.device))
        except Exception:
            ports = []
        for p in ports:
            tag = "  [Pico]" if p.vid == 0x2E8A else ""
            self.port_cb.addItem(f"{p.device} - {p.description}{tag}", p.device)
        self.port_cb.addItem(DEMO_PORT, DEMO_PORT)
        if cur:
            i = self.port_cb.findData(cur)
            if i >= 0:
                self.port_cb.setCurrentIndex(i)

    # ------------------------------------------------------------ capture
    def _set_running(self, on):
        self.running = on
        self.start_btn.setEnabled(not on)
        self.stop_btn.setEnabled(on)
        for w in (self.port_cb, self.speed_cb, self.fold_sof_cb, self.fold_nak_cb, self.reconnect_cb):
            w.setEnabled(not on)
        self.open_act.setEnabled(not on)
        self.save_act.setEnabled(not on and self.store is not None)

    def _new_store(self, store):
        if self.store:
            self.store.close()
        self.store = store
        self.model.set_store(store)
        self.detail.clear()
        self.hex.clear()
        self.hex_title.setText("Data")
        self.devices.clear()
        self.stats.clear()
        self._dev_version = -1

    def start_capture(self):
        port = self.port_cb.currentData()
        if not port:
            QMessageBox.warning(self, APP_NAME, "No serial port selected.")
            return
        if self.store is not None and not self.saved:
            r = QMessageBox.question(
                self, APP_NAME,
                f"The previous capture has not been saved elsewhere.\nIt is kept at:\n{self.store.path}\n\n"
                "Start a new capture?")
            if r != QMessageBox.Yes:
                return
        path = os.path.join(CAPTURE_DIR, time.strftime("capture_%Y%m%d_%H%M%S.pusb"))
        self._new_store(C.CaptureStore(path))
        if port == DEMO_PORT:
            self.worker = sources.DemoWorker(self.store, fold_sof=self.fold_sof_cb.isChecked(),
                                             fold_nak=self.fold_nak_cb.isChecked())
        else:
            self.worker = sources.SerialWorker(port, self.store, speed=self.speed_cb.currentData(),
                                               fold_sof=self.fold_sof_cb.isChecked(),
                                               fold_nak=self.fold_nak_cb.isChecked(),
                                               auto_reconnect=self.reconnect_cb.isChecked(), log=self.log)
        self.worker.start()
        self.t_start = time.monotonic()
        self.saved = False
        self._rate_last = (time.monotonic(), 0)
        self._set_running(True)
        self.lbl_file.setText(path)
        self.log(f"Capture started on {port} -> {path}")

    def stop_capture(self, ask_save=True):
        if not self.running:
            return
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.worker.stop()
            self.worker.join(timeout=4)
            self.store.close_writer()
            self.model.refresh()
        finally:
            QApplication.restoreOverrideCursor()
        self.t_stop = time.monotonic()
        self._set_running(False)
        self._update_stats()
        self.log(f"Capture stopped: {self.store.row_count()} rows, {self.store.bytes_in / 1e6:.1f} MB")
        if ask_save:
            r = QMessageBox.question(self, APP_NAME, "Capture stopped. Save the capture now?",
                                     QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
                                     QMessageBox.Save)
            if r == QMessageBox.Save:
                self.save_capture()
            elif r == QMessageBox.Discard:
                self._discard_capture()

    def _discard_capture(self):
        if not self.store:
            return
        path = self.store.path
        self.model.set_store(None)
        self.store.close()
        self.store = None
        self.saved = True
        try:
            os.remove(path)
        except OSError:
            pass
        self.lbl_file.setText("")
        self.devices.clear()
        self.stats.clear()
        self._set_running(False)
        self.log(f"Capture discarded ({path})")

    def save_capture(self):
        if not self.store or self.running:
            return
        path, _flt = QFileDialog.getSaveFileName(
            self, "Save capture", os.path.join(os.path.expanduser("~"), os.path.basename(self.store.path)),
            "Pico USB capture (*.pusb);;Wireshark (*.pcapng);;CSV (*.csv);;Text (*.txt)")
        if not path:
            return
        ext = os.path.splitext(path)[1].lower()
        if not ext and "pcapng" in _flt:
            path += ".pcapng"
            ext = ".pcapng"
        if ext in (".pcapng", ".pcap"):
            self._export_wireshark(path)
            return
        if ext == ".csv":
            self._export_csv(path)
            return
        if ext == ".txt":
            self._export_txt(path, self._ask_children())
            return
        if not ext:
            path += ".pusb"
        if os.path.abspath(path) == os.path.abspath(self.store.path):
            self.saved = True
            return
        size = os.path.getsize(self.store.path)
        dlg = QProgressDialog("Saving capture...", "Cancel", 0, 1000, self)
        dlg.setWindowModality(Qt.WindowModal)
        dlg.setMinimumDuration(300)
        done = 0
        ok = True
        with open(self.store.path, "rb") as src, open(path, "wb") as dst:
            while True:
                b = src.read(8 << 20)
                if not b:
                    break
                dst.write(b)
                done += len(b)
                dlg.setValue(int(done * 1000 / max(size, 1)))
                QApplication.processEvents()
                if dlg.wasCanceled():
                    ok = False
                    break
        dlg.close()
        if not ok:
            os.remove(path)
            return
        self.saved = True
        self.log(f"Saved {size / 1e6:.1f} MB to {path}")
        self.statusBar().showMessage(f"Saved to {path}", 8000)

    def _ask_children(self):
        r = QMessageBox.question(self, APP_NAME, "Include transactions and packets (all levels) in the export?\n"
                                 "(No = top level rows only, faster and smaller)",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        return r == QMessageBox.Yes

    def export_rows(self):
        if not self.store:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export rows (current filter)",
                                              os.path.splitext(self.store.path)[0] + ".csv",
                                              "CSV (*.csv);;Text (*.txt)")
        if not path:
            return
        ext = os.path.splitext(path)[1].lower()
        if ext == ".csv":
            self._export_csv(path)
        else:
            self._export_txt(path, self._ask_children())

    def _export_csv(self, path):
        """Data Center style CSV of the rows passing the filter"""
        box = QMessageBox(QMessageBox.Question, APP_NAME,
                          "Export CSV (Data Center layout, current filter applied).\n\n"
                          "Visible records: rows as shown, children only where expanded.\n"
                          "All levels: every transaction and packet (slower, larger file).", parent=self)
        vis = box.addButton("Visible records", QMessageBox.AcceptRole)
        lev = box.addButton("All levels", QMessageBox.AcceptRole)
        box.addButton(QMessageBox.Cancel)
        box.setDefaultButton(vis)
        full = QCheckBox(f"Full data in Summary (Data Center cuts it after {export_csv.DATA_LIMIT} bytes)")
        box.setCheckBox(full)
        box.exec()
        if box.clickedButton() is vis:
            self._write_csv(path, self.model.expanded, full.isChecked())
        elif box.clickedButton() is lev:
            self._write_csv(path, lambda _k: True, full.isChecked())

    def _write_csv(self, path, expanded, full_data):
        n = self.model.top_count()
        dlg = QProgressDialog(f"Exporting {n} rows...", "Cancel", 0, 1000, self)
        dlg.setWindowModality(Qt.WindowModal)
        dlg.setMinimumDuration(300)

        def progress(i, total):
            dlg.setValue(min(999, i * 1000 // max(total, 1)))
            QApplication.processEvents()
            return not dlg.wasCanceled()

        try:
            rows = export_csv.export_csv(self.store, path, [self.model.row_id(k) for k in range(n)], expanded,
                                         full_data, progress)
        except export_csv.Cancelled:
            os.remove(path)
            self.statusBar().showMessage("Export cancelled", 5000)
            return
        except Exception as e:
            QMessageBox.critical(self, APP_NAME, f"Export failed:\n{e}")
            return
        finally:
            dlg.close()
        self.log(f"Exported {rows} rows to {path}")
        self.statusBar().showMessage(f"Exported to {path}", 8000)

    def _export_txt(self, path, children=False):
        n = self.model.top_count()
        dlg = QProgressDialog(f"Exporting {n} rows...", "Cancel", 0, max(n, 1), self)
        dlg.setWindowModality(Qt.WindowModal)
        dlg.setMinimumDuration(300)
        st = self.store
        widths = (2, 9, 17, 11, 5, 8, 4, 3, 40)

        def walk(node, depth):
            yield depth, node
            if children and node.kids:
                try:
                    kids = node.kids()
                except Exception:
                    kids = []
                for k in kids:
                    yield from walk(k, depth + 1)

        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write("  ".join(c.ljust(widths[i]) if i < len(widths) else c
                              for i, c in enumerate(C.COLUMNS)) + "\n")
            for r in range(n):
                for depth, node in walk(st.top_node(self.model.row_id(r)), 0):
                    cols = list(node.cols)
                    cols[C.COL_RECORD] = "  " * depth + cols[C.COL_RECORD]
                    f.write("  ".join(v.ljust(widths[i]) if i < len(widths) else v
                                      for i, v in enumerate(cols)) + "\n")
                if r % 2000 == 0:
                    dlg.setValue(r)
                    QApplication.processEvents()
                    if dlg.wasCanceled():
                        break
        dlg.close()
        self.log(f"Exported {n} rows to {path}")
        self.statusBar().showMessage(f"Exported to {path}", 8000)

    def export_wireshark(self):
        if not self.store or self.running:
            if self.running:
                QMessageBox.information(self, APP_NAME, "Stop the capture first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export to Wireshark",
                                              os.path.splitext(self.store.path)[0] + ".pcapng",
                                              "Wireshark pcapng (*.pcapng)")
        if path:
            if not os.path.splitext(path)[1]:
                path += ".pcapng"
            self._export_wireshark(path)

    def _export_wireshark(self, path):
        ask = WiresharkDialog(self, export_usbpcap.missing_descriptors(self.store))
        if ask.exec() != QDialog.Accepted:
            return
        self._write_wireshark(path, ask.usbpcap.isChecked(), "none" if ask.none.isChecked() else "generic",
                              ask.reference)

    def _write_wireshark(self, path, usbpcap, descriptors="generic", reference=None):
        dlg = QProgressDialog("Exporting to Wireshark...", "Cancel", 0, 1000, self)
        dlg.setWindowModality(Qt.WindowModal)
        dlg.setMinimumDuration(300)

        def prog(done, total):
            dlg.setValue(int(done * 1000 / max(total, 1)))
            QApplication.processEvents()
            return not dlg.wasCanceled()

        try:
            if usbpcap:
                s = export_usbpcap.export_usbpcap(self.store, path, prog, descriptors, reference)
            else:
                s = export_pcap.export_pcapng(self.store, path, prog)
        except Exception as e:
            dlg.close()
            QMessageBox.critical(self, APP_NAME, f"Export failed:\n{e}")
            return
        dlg.close()
        if s["cancelled"]:
            try:
                os.remove(path)
            except OSError:
                pass
            return
        if usbpcap:
            msg = f"{s['transfers']:,} transfers ({s['frames']:,} frames) written to\n{path}"
            if s["descriptors"]:
                msg += "\n\nDescriptors added (not captured, marked with a comment):\n" + "\n".join(s["descriptors"])
            if s["skipped"] or s["errors"]:
                msg += (f"\n\n{s['skipped']:,} transactions and {s['errors']:,} packets with errors are not in the "
                        "file.\nUse the USB packets format to see them.")
            self.log(f"Wireshark export: {s['transfers']} transfers -> {path}")
            QMessageBox.information(self, APP_NAME, msg)
            return
        msg = f"{s['packets']:,} USB packets written to\n{path}"
        if s["errors"]:
            msg += f"\n{s['errors']:,} packets with decode errors (marked with a comment)."
        if s["folded_sof"] or s["folded_nak"]:
            msg += (f"\n\nNote: {s['folded_sof']:,} SOF and {s['folded_nak']:,} IN-NAK were folded by the "
                    "sniffer and are not in the file.\nUncheck Fold SOF / Fold IN-NAK before capturing to get "
                    "every packet.")
        msg += "\n\nOpen with Wireshark 3.6 or newer (USB 2.0 link layer, display filter: usbll / usb)."
        self.log(f"Wireshark export: {s['packets']} packets -> {path}")
        QMessageBox.information(self, APP_NAME, msg)

    def open_capture(self, path=None):
        if self.running:
            return
        if self.store is not None and not self.saved:
            r = QMessageBox.question(self, APP_NAME,
                                     f"Current capture not saved elsewhere (kept at {self.store.path}). Continue?")
            if r != QMessageBox.Yes:
                return
        if not path:
            path, _ = QFileDialog.getOpenFileName(self, "Open capture", CAPTURE_DIR, "Pico USB capture (*.pusb)")
        if not path:
            return
        try:
            store = C.CaptureStore(path, create=False)
        except Exception as e:
            QMessageBox.critical(self, APP_NAME, f"Cannot open file:\n{e}")
            return
        dlg = QProgressDialog("Indexing capture...", "Cancel", 0, 1000, self)
        dlg.setWindowModality(Qt.WindowModal)
        dlg.setMinimumDuration(300)

        def prog(done, total):
            dlg.setValue(int(done * 1000 / max(total, 1)))
            QApplication.processEvents()
            return not dlg.wasCanceled()

        store.load(prog)
        dlg.close()
        self._new_store(store)
        self.saved = True
        self._set_running(False)
        self.lbl_file.setText(path)
        self._update_stats()
        self.log(f"Opened {path}: {store.row_count()} rows")

    def _with_port(self, payload: bytes):
        port = self.port_cb.currentData()
        if self.running or not port or port == DEMO_PORT:
            QMessageBox.information(self, APP_NAME, "Select the Pico port (and stop any capture) first.")
            return None
        import serial
        try:
            with serial.Serial(port, timeout=0.3) as s:
                s.write(payload)
                time.sleep(0.3)
                return s.read(4096)
        except Exception as e:
            QMessageBox.critical(self, APP_NAME, f"{port}: {e}")
            return None

    def query_info(self):
        data = self._with_port(b"PI")
        if data is None:
            return
        for _p, t, pl in C.CaptureStore.iter_records(data):
            if t == P.REC_INFO:
                proto, fw, clk, ring, dp, dm = struct.unpack_from("<HHIIBB", pl, 0)
                txt = bytes(pl[14:]).decode("ascii", "replace")
                QMessageBox.information(self, APP_NAME,
                                        f"{txt}\nProtocol v{proto}, firmware v{fw}\nclk_sys {clk / 1e6:.0f} MHz\n"
                                        f"Capture ring {ring * 4 // 1024} KB\nD+ = GP{dp}, D- = GP{dm}")
                return
        QMessageBox.warning(self, APP_NAME, "No answer from device (is the sniffer firmware flashed?)")

    def reboot_bootsel(self):
        if QMessageBox.question(self, APP_NAME, "Reboot the Pico into BOOTSEL mode (RPI-RP2 drive)?") != \
                QMessageBox.Yes:
            return
        port = self.port_cb.currentData()
        if self.running or not port or port == DEMO_PORT:
            QMessageBox.information(self, APP_NAME, "Select the Pico port (and stop any capture) first.")
            return
        import serial
        try:
            # 1200 baud "touch" (SDK reset convention), fall back to the 'R' command
            with serial.Serial(port, 1200) as s:
                s.dtr = False
            time.sleep(0.5)
            from serial.tools import list_ports
            if any(p.device == port for p in list_ports.comports()):
                with serial.Serial(port, timeout=0.3) as s:
                    s.write(b"R")
        except Exception:
            pass
        self.statusBar().showMessage("Reboot to BOOTSEL requested", 5000)
        QTimer.singleShot(2000, self.refresh_ports)

    # ------------------------------------------------------------- filter
    def apply_filter(self):
        flt = C.RowFilter(self.dev_sp.value(), self.ep_sp.value(), self.hide_idle_cb.isChecked(),
                          self.hide_nak_cb.isChecked(), self.err_only_cb.isChecked())
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.model.set_filter(flt)
        finally:
            QApplication.restoreOverrideCursor()
        self._update_stats()

    def clear_filter(self):
        self.dev_sp.setValue(-1)
        self.ep_sp.setValue(-1)
        for w in (self.hide_idle_cb, self.hide_nak_cb, self.err_only_cb):
            w.setChecked(False)
        self.apply_filter()

    # --------------------------------------------------------------- find
    def find(self, forward=True):
        text = self.find_edit.text().strip().lower()
        if not text or not self.store:
            return
        m = self.model
        n = m.top_count()
        if n == 0:
            return
        cur = self._sel_row()
        start = m.locate(cur)[0] if cur >= 0 else (-1 if forward else n)
        step = 1 if forward else -1
        k = start + step
        st = self.store
        dlg = None
        t0 = time.monotonic()
        scanned = 0
        while 0 <= k < n:
            node = st.top_node(m.row_id(k))
            if text in node.cols[8].lower() or text in node.cols[9].lower():
                if dlg:
                    dlg.close()
                self.autoscroll_cb.setChecked(False)
                d = m.top_display_row(k)
                self.table.selectRow(d)
                self.table.scrollTo(m.index(d, 0), QAbstractItemView.PositionAtCenter)
                return
            k += step
            scanned += 1
            if scanned % 2000 == 0:
                if dlg is None and time.monotonic() - t0 > 0.4:
                    dlg = QProgressDialog(f"Searching '{text}'...", "Cancel", 0, n, self)
                    dlg.setWindowModality(Qt.WindowModal)
                    dlg.show()
                if dlg:
                    dlg.setValue(k if forward else n - k)
                    QApplication.processEvents()
                    if dlg.wasCanceled():
                        break
        if dlg:
            dlg.close()
        self.statusBar().showMessage(f"'{text}' not found", 4000)

    # ------------------------------------------------------------ details
    def _row_selected(self, cur, prev):
        if not cur.isValid() or not self.store:
            return
        node, _, _ = self.model.node_at(cur.row())
        self.detail.clear()
        if node is None:
            return
        try:
            tree, data, title = self.store.describe(node)
        except Exception as e:
            tree, data, title = [("Decode error", str(e), [])], b"", ""
        c = node.cols
        head = [(c[8], c[9], [
            ("Time", c[2], []), ("Duration", c[3], []), ("Index", c[1], []),
            ("Device / Endpoint", f"{c[6]} / {c[7]}", []),
        ] + ([("Errors", c[5], [])] if c[5] else []))]
        fill_tree(self.detail, head + tree)
        self.hex_title.setText(title or "Data")
        self.hex.setPlainText(P.hexdump8(data) if data else "")

    def _refresh_devices(self):
        st = self.store
        if not st or st.dev_version == self._dev_version:
            return
        self._dev_version = st.dev_version
        self.devices.clear()
        fill_tree(self.devices, st.device_tree())

    def copy_rows(self):
        rows = sorted({i.row() for i in self.table.selectionModel().selectedRows()})
        if not rows:
            return
        lines = ["\t".join(C.COLUMNS)]
        for r in rows[:100000]:
            node, depth, _ = self.model.node_at(r)
            if node is None:
                continue
            cols = list(node.cols)
            cols[C.COL_RECORD] = "  " * depth + cols[C.COL_RECORD]
            lines.append("\t".join(cols))
        QGuiApplication.clipboard().setText("\n".join(lines))

    def _scrolled(self, v):
        sb = self.table.verticalScrollBar()
        # user dragged the scrollbar up -> pause autoscroll
        if self.running and v < sb.maximum() - 2 and sb.isSliderDown():
            self.autoscroll_cb.setChecked(False)

    # --------------------------------------------------------------- timer
    def _tick(self):
        while True:
            try:
                self.logw.appendPlainText(self.logq.get_nowait())
            except queue.Empty:
                break
        if not self.store:
            return
        grew = self.model.refresh()
        if grew and self.autoscroll_cb.isChecked():
            self.table.scrollToBottom()
        if self.running and self.worker and not self.worker.is_alive():
            err = getattr(self.worker, "error", None)
            self.stop_capture(ask_save=False)
            QMessageBox.warning(self, APP_NAME, f"Capture ended: {err or 'worker stopped'}")

    def _update_stats(self):
        st = self.store
        if self.running:
            el = time.monotonic() - self.t_start
            w = self.worker
            conn = getattr(w, "connected", True)
            self.lbl_state.setText("● CAPTURING" if conn else "● RECONNECTING...")
            self.lbl_state.setStyleSheet("padding:0 10px;font-weight:bold;color:%s" %
                                         ("#2E9E44" if conn else "#E65100"))
        else:
            el = (self.t_stop - self.t_start) if self.t_start else 0
            self.lbl_state.setText("Stopped" if st else "Idle")
            self.lbl_state.setStyleSheet("padding:0 10px;color:#555")
        el = int(el)
        self.lbl_time.setText(f"{el // 3600:02d}:{el % 3600 // 60:02d}:{el % 60:02d}")
        if not st:
            return
        self._refresh_devices()
        sync_stats(self.stats, st.stats_tree())
        now = time.monotonic()
        t0, b0 = self._rate_last
        if now - t0 >= 1.0:
            self._rate = (st.bytes_in - b0) / (now - t0)
            self._rate_last = (now, st.bytes_in)
        shown = self.model.top_count()
        total = st.row_count()
        self.lbl_rows.setText(f"Rows: {shown:,}" + (f" / {total:,}" if shown != total else ""))
        self.lbl_rx.setText(f"Rx: {st.bytes_in / 1e6:,.1f} MB  {self._rate / 1024:,.1f} KB/s  "
                            f"pkts {st.packets:,}")
        s = st.status
        if s:
            _, pk, drop, fill, maxfill, ring, stall, recs, syncerr = s
            txt = (f"Device: pkts {pk:,}  dropped {drop:,}  buf {fill * 100 // max(ring, 1)}% "
                   f"(max {maxfill * 100 // max(ring, 1)}%)")
            if stall:
                txt += f"  PIO stall {stall}"
            if syncerr:
                txt += f"  sync err {syncerr}"
            rc = getattr(self.worker, "reconnects", 0) if self.worker else 0
            if rc:
                txt += f"  reconnects {rc}"
            self.lbl_dev.setText(txt)
            self.lbl_dev.setStyleSheet("padding:0 10px;color:%s" % ("#C00000" if drop or stall else "#000"))
        try:
            fsz = os.path.getsize(st.path)
            self.lbl_file.setText(f"{st.path}  ({fsz / 1e6:,.1f} MB)")
        except OSError:
            pass

    def closeEvent(self, ev):
        if self.running:
            if QMessageBox.question(self, APP_NAME, "A capture is running. Stop and exit?") != QMessageBox.Yes:
                ev.ignore()
                return
            self.stop_capture(ask_save=False)
        if self.store and not self.saved:
            r = QMessageBox.question(self, APP_NAME,
                                     f"The capture is kept at:\n{self.store.path}\n\nSave a copy elsewhere before exit?",
                                     QMessageBox.Save | QMessageBox.No | QMessageBox.Cancel)
            if r == QMessageBox.Cancel:
                ev.ignore()
                return
            if r == QMessageBox.Save:
                self.save_capture()
        if self.store:
            self.store.close()
        ev.accept()


def light_palette(app):
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor("#F3F3F3"))
    pal.setColor(QPalette.WindowText, Qt.black)
    pal.setColor(QPalette.Base, Qt.white)
    pal.setColor(QPalette.AlternateBase, QColor("#F7F7F7"))
    pal.setColor(QPalette.Text, Qt.black)
    pal.setColor(QPalette.Button, QColor("#ECECEC"))
    pal.setColor(QPalette.ButtonText, Qt.black)
    pal.setColor(QPalette.Highlight, QColor("#3874D8"))
    pal.setColor(QPalette.HighlightedText, Qt.white)
    pal.setColor(QPalette.ToolTipBase, QColor("#FFFFE0"))
    pal.setColor(QPalette.ToolTipText, Qt.black)
    app.setPalette(pal)


def _install_error_handler():
    """started with pythonw there is no console: show / log unexpected errors"""
    import traceback

    def hook(etype, value, tb):
        text = "".join(traceback.format_exception(etype, value, tb))
        try:
            with open(os.path.join(DATA_DIR, "error.log"), "a", encoding="utf-8") as f:
                f.write(time.strftime("\n=== %Y-%m-%d %H:%M:%S ===\n") + text)
        except OSError:
            pass
        if sys.stderr:
            sys.stderr.write(text)
        if QApplication.instance():
            QMessageBox.critical(None, APP_NAME, f"Unexpected error (details in error.log):\n\n{value}")

    sys.excepthook = hook


def _own_taskbar_button():
    """without an own id Windows groups the window under pythonw.exe and shows the Python icon"""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PicoUsbSniffer.Gui")
        except (AttributeError, OSError):
            pass


def main():
    _install_error_handler()
    _own_taskbar_button()
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(QIcon(ICON_FILE))
    light_palette(app)
    w = MainWindow()
    w.show()
    args = sys.argv[1:]
    if args and args[0] == "--demo":
        w.port_cb.setCurrentIndex(w.port_cb.findData(DEMO_PORT))
        w.start_capture()
    elif args and args[0].lower().endswith(".pusb") and os.path.exists(args[0]):
        w.open_capture(args[0])
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
