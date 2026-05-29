"""Logs & Reports panel."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QLineEdit, QComboBox, QAbstractItemView,
    QMessageBox, QFileDialog
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from db import database
import csv


class LogsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self.refresh()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(5000)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("Logs & Reports")
        title.setObjectName("heading")
        hdr.addWidget(title)
        hdr.addStretch()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search IP, process, rule...")
        self.search_edit.setMaximumWidth(220)
        self.search_edit.textChanged.connect(self.refresh)

        self.action_combo = QComboBox()
        self.action_combo.addItems(["All Actions", "BLOCK", "ALLOW", "INFO", "THREAT"])
        self.action_combo.currentTextChanged.connect(self.refresh)

        self.limit_combo = QComboBox()
        self.limit_combo.addItems(["100", "250", "500", "1000"])
        self.limit_combo.setCurrentIndex(1)
        self.limit_combo.currentTextChanged.connect(self.refresh)

        btn_refresh = QPushButton("Refresh")
        btn_refresh.setObjectName("secondary")
        btn_refresh.clicked.connect(self.refresh)
        btn_export = QPushButton("Export CSV")
        btn_export.setObjectName("secondary")
        btn_export.clicked.connect(self._export_csv)
        btn_clear = QPushButton("Clear Logs")
        btn_clear.setObjectName("danger")
        btn_clear.clicked.connect(self._clear_logs)

        for w in (self.search_edit, self.action_combo, self.limit_combo,
                  btn_refresh, btn_export, btn_clear):
            hdr.addWidget(w)
        layout.addLayout(hdr)

        # Stats bar
        stats_row = QHBoxLayout()
        self.stat_total = QLabel("Total: 0")
        self.stat_blocked = QLabel("Blocked: 0")
        self.stat_blocked.setStyleSheet("color: #c0392b;")
        self.stat_allowed = QLabel("Allowed: 0")
        self.stat_allowed.setStyleSheet("color: #27ae60;")
        self.stat_threats = QLabel("Threats: 0")
        self.stat_threats.setStyleSheet("color: #e67e22;")
        for lbl in (self.stat_total, self.stat_blocked, self.stat_allowed, self.stat_threats):
            stats_row.addWidget(lbl)
        stats_row.addStretch()
        layout.addLayout(stats_row)

        # Table
        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels([
            "Time", "Action", "Direction", "Protocol",
            "Source IP", "Source Port", "Dest IP", "Dest Port", "Process", "Rule / Detail"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        layout.addWidget(self.table)

        self.count_label = QLabel("")
        self.count_label.setObjectName("subheading")
        layout.addWidget(self.count_label)

    def refresh(self):
        search = self.search_edit.text().strip() or None
        action = self.action_combo.currentText()
        if action == "All Actions":
            action = None
        limit = int(self.limit_combo.currentText())
        logs = database.get_logs(limit=limit, action_filter=action, search=search)

        self.table.setRowCount(len(logs))
        action_colors = {
            "BLOCK": "#c0392b", "ALLOW": "#27ae60",
            "THREAT": "#e67e22", "INFO": "#3498db"
        }
        for row, log in enumerate(logs):
            ts = log["timestamp"][:19].replace("T", " ") if log["timestamp"] else ""
            detail = log.get("rule_name") or log.get("details") or ""
            vals = [
                ts, log["action"], log.get("direction", ""),
                log.get("protocol", ""), log.get("src_ip", ""),
                str(log["src_port"]) if log.get("src_port") else "",
                log.get("dst_ip", ""),
                str(log["dst_port"]) if log.get("dst_port") else "",
                log.get("process", ""), detail
            ]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v or "")
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 1:
                    item.setForeground(QColor(action_colors.get(v, "#e0e6ed")))
                self.table.setItem(row, col, item)

        self.count_label.setText(f"Showing {len(logs)} entries")

        stats = database.get_log_stats()
        self.stat_total.setText(f"Total: {stats['total']:,}")
        self.stat_blocked.setText(f"Blocked: {stats['blocked']:,}")
        self.stat_allowed.setText(f"Allowed: {stats['allowed']:,}")

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Logs", "aegisguard_logs.csv",
                                              "CSV Files (*.csv)")
        if not path:
            return
        logs = database.get_logs(limit=10000)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=logs[0].keys() if logs else [])
            writer.writeheader()
            writer.writerows(logs)
        QMessageBox.information(self, "Export", f"Exported {len(logs)} entries to {path}")

    def _clear_logs(self):
        ret = QMessageBox.question(self, "Confirm", "Clear all logs? This cannot be undone.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ret == QMessageBox.StandardButton.Yes:
            database.clear_logs()
            self.refresh()
