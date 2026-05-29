"""Network Monitor panel - live connections and bandwidth."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QLineEdit, QComboBox, QAbstractItemView, QFrame
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from core import monitor


class MonitorPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._paused = False
        self._build_ui()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(2000)
        self._refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("Network Monitor")
        title.setObjectName("heading")
        hdr.addWidget(title)
        hdr.addStretch()

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by IP, process, port...")
        self.filter_edit.setMaximumWidth(200)
        self.proto_combo = QComboBox()
        self.proto_combo.addItems(["All", "TCP", "UDP"])
        self.proto_combo.currentTextChanged.connect(self._refresh)
        self.filter_edit.textChanged.connect(self._refresh)

        self.pause_btn = QPushButton("Pause")
        self.pause_btn.setObjectName("secondary")
        self.pause_btn.clicked.connect(self._toggle_pause)

        for w in (self.filter_edit, self.proto_combo, self.pause_btn):
            hdr.addWidget(w)
        layout.addLayout(hdr)

        # Stats cards row
        stats_row = QHBoxLayout()
        self.stat_labels = {}
        for name in ("Connections", "TCP", "UDP", "Listening", "Upload", "Download"):
            card = QFrame()
            card.setObjectName("card")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(12, 8, 12, 8)
            val = QLabel("0")
            val.setStyleSheet("font-size: 18px; font-weight: bold; color: #3498db;")
            lbl = QLabel(name)
            lbl.setObjectName("stat_label")
            cl.addWidget(val)
            cl.addWidget(lbl)
            self.stat_labels[name] = val
            stats_row.addWidget(card)
        layout.addLayout(stats_row)

        # Connection table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Protocol", "Local Address", "Local Port",
            "Remote Address", "Remote Port", "Status", "Process"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        layout.addWidget(self.table)

        # Per-interface bandwidth
        iface_frame = QFrame()
        iface_frame.setObjectName("card")
        iface_layout = QVBoxLayout(iface_frame)
        iface_layout.setContentsMargins(12, 10, 12, 10)
        iface_layout.addWidget(QLabel("Interface Bandwidth"))
        self.iface_table = QTableWidget(0, 3)
        self.iface_table.setHorizontalHeaderLabels(["Interface", "Bytes Sent", "Bytes Received"])
        self.iface_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.iface_table.setAlternatingRowColors(True)
        self.iface_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.iface_table.verticalHeader().setVisible(False)
        self.iface_table.setMaximumHeight(150)
        iface_layout.addWidget(self.iface_table)
        layout.addWidget(iface_frame)

        self._prev_net = monitor.get_network_stats()

    def _refresh(self):
        if self._paused:
            return

        conns = monitor.get_connections()
        filt = self.filter_edit.text().lower()
        proto_f = self.proto_combo.currentText()

        filtered = []
        tcp_count = udp_count = listen_count = 0
        for c in conns:
            if c["proto"] == "TCP":
                tcp_count += 1
            elif c["proto"] == "UDP":
                udp_count += 1
            if c["status"] == "Listening":
                listen_count += 1
            if proto_f != "All" and c["proto"] != proto_f:
                continue
            if filt and not any(filt in str(v).lower() for v in c.values()):
                continue
            filtered.append(c)

        net = monitor.get_network_stats()
        prev = self._prev_net
        sent_rate = max(0, net["bytes_sent"] - prev["bytes_sent"])
        recv_rate = max(0, net["bytes_recv"] - prev["bytes_recv"])
        self._prev_net = net

        self.stat_labels["Connections"].setText(str(len(conns)))
        self.stat_labels["TCP"].setText(str(tcp_count))
        self.stat_labels["UDP"].setText(str(udp_count))
        self.stat_labels["Listening"].setText(str(listen_count))
        self.stat_labels["Upload"].setText(monitor.format_bytes(sent_rate // 2) + "/s")
        self.stat_labels["Download"].setText(monitor.format_bytes(recv_rate // 2) + "/s")

        self.table.setRowCount(len(filtered))
        status_colors = {
            "Established": "#27ae60", "Listening": "#3498db",
            "Time Wait": "#e67e22", "Close Wait": "#e67e22",
        }
        for row, c in enumerate(filtered):
            vals = [
                c["proto"],
                c["local_ip"], str(c["local_port"]),
                c["remote_ip"] or "-", str(c["remote_port"]) if c["remote_port"] else "-",
                c["status"], c["process"]
            ]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 5:
                    item.setForeground(QColor(status_colors.get(v, "#e0e6ed")))
                self.table.setItem(row, col, item)

        ifaces = monitor.get_per_interface_stats()
        self.iface_table.setRowCount(len(ifaces))
        for row, (name, s) in enumerate(ifaces.items()):
            for col, v in enumerate([name,
                                     monitor.format_bytes(s["bytes_sent"]),
                                     monitor.format_bytes(s["bytes_recv"])]):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.iface_table.setItem(row, col, item)

    def _toggle_pause(self):
        self._paused = not self._paused
        self.pause_btn.setText("Resume" if self._paused else "Pause")
        self.pause_btn.setObjectName("danger" if self._paused else "secondary")
        self.pause_btn.style().unpolish(self.pause_btn)
        self.pause_btn.style().polish(self.pause_btn)
