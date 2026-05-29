"""AegisGuard Dashboard panel."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QGridLayout,
    QTableWidget, QTableWidgetItem, QHeaderView, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont
import psutil
from db import database
from core import monitor, ips


class StatCard(QFrame):
    def __init__(self, title, value, color="#c0392b", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setMinimumHeight(100)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)

        self.value_label = QLabel(str(value))
        self.value_label.setObjectName("stat_value")
        self.value_label.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")

        title_label = QLabel(title.upper())
        title_label.setObjectName("stat_label")

        layout.addWidget(self.value_label)
        layout.addWidget(title_label)

    def update_value(self, value):
        self.value_label.setText(str(value))


class ThreatRow(QTableWidgetItem):
    pass


class DashboardPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._prev_net = psutil.net_io_counters()
        self._build_ui()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(3000)
        self._refresh()

    def _build_ui(self):
        main = QVBoxLayout(self)
        main.setSpacing(16)
        main.setContentsMargins(20, 20, 20, 20)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("Dashboard")
        title.setObjectName("heading")
        subtitle = QLabel("System overview and security status")
        subtitle.setObjectName("subheading")
        hdr.addWidget(title)
        hdr.addStretch()
        hdr.addWidget(subtitle)
        main.addLayout(hdr)

        # Stat cards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)
        self.card_conns = StatCard("Active Connections", "0", "#3498db")
        self.card_blocked = StatCard("Blocked Today", "0", "#c0392b")
        self.card_threats = StatCard("Threats Detected", "0", "#e67e22")
        self.card_upload = StatCard("Upload Speed", "0 B/s", "#27ae60")
        self.card_download = StatCard("Download Speed", "0 B/s", "#2980b9")
        for card in (self.card_conns, self.card_blocked, self.card_threats,
                     self.card_upload, self.card_download):
            card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            cards_layout.addWidget(card)
        main.addLayout(cards_layout)

        # Middle row: connections + threats
        mid = QHBoxLayout()
        mid.setSpacing(12)

        # Active connections table
        conn_frame = QFrame()
        conn_frame.setObjectName("card")
        conn_layout = QVBoxLayout(conn_frame)
        conn_layout.setContentsMargins(16, 12, 16, 12)
        conn_title = QLabel("Active Connections")
        conn_title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        conn_layout.addWidget(conn_title)

        self.conn_table = QTableWidget(0, 5)
        self.conn_table.setHorizontalHeaderLabels(["Protocol", "Local IP:Port", "Remote IP:Port", "Status", "Process"])
        self.conn_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.conn_table.setAlternatingRowColors(True)
        self.conn_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.conn_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.conn_table.verticalHeader().setVisible(False)
        self.conn_table.setMaximumHeight(280)
        conn_layout.addWidget(self.conn_table)
        mid.addWidget(conn_frame, 3)

        # Threat alerts panel
        threat_frame = QFrame()
        threat_frame.setObjectName("card")
        threat_layout = QVBoxLayout(threat_frame)
        threat_layout.setContentsMargins(16, 12, 16, 12)
        threat_title = QLabel("Recent Threats")
        threat_title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        threat_layout.addWidget(threat_title)

        self.threat_table = QTableWidget(0, 3)
        self.threat_table.setHorizontalHeaderLabels(["Severity", "Threat", "Source IP"])
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.threat_table.setAlternatingRowColors(True)
        self.threat_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.threat_table.verticalHeader().setVisible(False)
        self.threat_table.setMaximumHeight(280)
        threat_layout.addWidget(self.threat_table)
        mid.addWidget(threat_frame, 2)

        main.addLayout(mid)

        # Bottom row: network stats + log summary
        bot = QHBoxLayout()
        bot.setSpacing(12)

        net_frame = QFrame()
        net_frame.setObjectName("card")
        net_layout = QVBoxLayout(net_frame)
        net_layout.setContentsMargins(16, 12, 16, 12)
        net_title = QLabel("Network I/O")
        net_title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        net_layout.addWidget(net_title)
        self.net_label = QLabel("Collecting data...")
        self.net_label.setWordWrap(True)
        net_layout.addWidget(self.net_label)
        bot.addWidget(net_frame, 1)

        log_frame = QFrame()
        log_frame.setObjectName("card")
        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(16, 12, 16, 12)
        log_title = QLabel("Event Summary")
        log_title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        log_layout.addWidget(log_title)
        self.log_summary = QLabel("Loading...")
        self.log_summary.setWordWrap(True)
        log_layout.addWidget(self.log_summary)
        bot.addWidget(log_frame, 1)

        main.addLayout(bot)

    def _refresh(self):
        try:
            conns = monitor.get_connections()
            self.card_conns.update_value(len(conns))
            self._refresh_conn_table(conns[:50])

            stats = database.get_log_stats()
            self.card_blocked.update_value(stats["blocked"])

            alerts = ips.get_alerts(20)
            self.card_threats.update_value(len(alerts))
            self._refresh_threat_table(alerts[:20])

            net_now = psutil.net_io_counters()
            sent = net_now.bytes_sent - self._prev_net.bytes_sent
            recv = net_now.bytes_recv - self._prev_net.bytes_recv
            self._prev_net = net_now
            interval = 3
            self.card_upload.update_value(monitor.format_bytes(sent // interval) + "/s")
            self.card_download.update_value(monitor.format_bytes(recv // interval) + "/s")

            self.net_label.setText(
                f"Total Sent:     {monitor.format_bytes(net_now.bytes_sent)}\n"
                f"Total Received: {monitor.format_bytes(net_now.bytes_recv)}\n"
                f"Packets Sent:   {net_now.packets_sent:,}\n"
                f"Packets Recv:   {net_now.packets_recv:,}"
            )

            self.log_summary.setText(
                f"Total Events:   {stats['total']:,}\n"
                f"Blocked:        {stats['blocked']:,}\n"
                f"Allowed:        {stats['allowed']:,}\n"
                f"Today:          {stats['today']:,}"
            )
        except Exception:
            pass

    def _refresh_conn_table(self, conns):
        self.conn_table.setRowCount(len(conns))
        for row, c in enumerate(conns):
            local = f"{c['local_ip']}:{c['local_port']}"
            remote = f"{c['remote_ip']}:{c['remote_port']}" if c['remote_ip'] else "-"
            items = [c["proto"], local, remote, c["status"], c["process"]]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.conn_table.setItem(row, col, item)

    def _refresh_threat_table(self, alerts):
        self.threat_table.setRowCount(len(alerts))
        sev_colors = {"CRITICAL": "#c0392b", "HIGH": "#e67e22",
                      "MEDIUM": "#f1c40f", "LOW": "#3498db"}
        for row, a in enumerate(alerts):
            sev = a["severity"]
            color = sev_colors.get(sev, "#ffffff")
            items = [sev, a["name"], a["remote_ip"]]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setForeground(QColor(color))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.threat_table.setItem(row, col, item)
