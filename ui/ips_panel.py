"""Intrusion Prevention System panel."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QSplitter, QFrame, QAbstractItemView
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont
from core import ips


class IPSPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        ips.register_callback(self._on_alert)
        self._build_ui()
        self._refresh_sigs()
        ips.start()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_alerts)
        self._timer.start(3000)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("Intrusion Prevention System")
        title.setObjectName("heading")
        hdr.addWidget(title)
        hdr.addStretch()
        self.alert_count_label = QLabel("Alerts: 0")
        self.alert_count_label.setObjectName("subheading")
        hdr.addWidget(self.alert_count_label)
        btn_clear = QPushButton("Clear Alerts")
        btn_clear.setObjectName("secondary")
        btn_clear.clicked.connect(self._clear_alerts)
        hdr.addWidget(btn_clear)
        layout.addLayout(hdr)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Signatures
        sig_frame = QFrame()
        sig_frame.setObjectName("card")
        sig_layout = QVBoxLayout(sig_frame)
        sig_layout.setContentsMargins(12, 12, 12, 12)
        sig_layout.addWidget(QLabel("Detection Signatures"))

        self.sig_table = QTableWidget(0, 5)
        self.sig_table.setHorizontalHeaderLabels(["Enabled", "ID", "Name", "Severity", "Description"])
        self.sig_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.sig_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.sig_table.setAlternatingRowColors(True)
        self.sig_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sig_table.verticalHeader().setVisible(False)
        self.sig_table.setMaximumHeight(200)
        sig_layout.addWidget(self.sig_table)
        splitter.addWidget(sig_frame)

        # Alerts
        alert_frame = QFrame()
        alert_frame.setObjectName("card")
        alert_layout = QVBoxLayout(alert_frame)
        alert_layout.setContentsMargins(12, 12, 12, 12)
        alert_layout.addWidget(QLabel("Live Threat Alerts"))

        self.alert_table = QTableWidget(0, 5)
        self.alert_table.setHorizontalHeaderLabels(["Time", "Severity", "Threat", "Source IP", "Detail"])
        self.alert_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.alert_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.alert_table.verticalHeader().setVisible(False)
        alert_layout.addWidget(self.alert_table)
        splitter.addWidget(alert_frame)

        layout.addWidget(splitter)

    def _refresh_sigs(self):
        sigs = ips.get_signatures()
        self.sig_table.setRowCount(len(sigs))
        sev_colors = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#3498db"}
        for row, sig in enumerate(sigs):
            cb = QCheckBox()
            cb.setChecked(sig["enabled"])
            cb.stateChanged.connect(lambda state, sid=sig["id"]:
                                    ips.set_signature_enabled(sid, state == Qt.CheckState.Checked.value))
            self.sig_table.setCellWidget(row, 0, cb)

            for col, v in enumerate([sig["id"], sig["name"], sig["severity"], sig["description"]]):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 2:
                    item.setForeground(QColor(sev_colors.get(v, "#ffffff")))
                self.sig_table.setItem(row, col + 1, item)

    def _refresh_alerts(self):
        alerts = ips.get_alerts(100)
        self.alert_count_label.setText(f"Alerts: {len(alerts)}")
        self.alert_table.setRowCount(len(alerts))
        sev_colors = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#3498db"}
        for row, a in enumerate(alerts):
            ts = a["timestamp"][:19].replace("T", " ")
            sev = a["severity"]
            color = sev_colors.get(sev, "#ffffff")
            for col, v in enumerate([ts, sev, a["name"], a["remote_ip"], a["detail"]]):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col in (1, 2):
                    item.setForeground(QColor(color))
                self.alert_table.setItem(row, col, item)

    def _on_alert(self, alert):
        self._refresh_alerts()

    def _clear_alerts(self):
        ips.clear_alerts()
        self._refresh_alerts()
