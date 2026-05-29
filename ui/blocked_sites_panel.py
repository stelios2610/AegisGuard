"""Blocked Sites panel - quick IP and domain blocklist."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QLineEdit, QTabWidget, QMessageBox,
    QAbstractItemView, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from db import database
from core import rules_engine
import subprocess


class BlockedSitesPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._ip_blocks = []
        self._build_ui()
        self._load()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("Blocked Sites")
        title.setObjectName("heading")
        layout.addWidget(title)

        tabs = QTabWidget()

        # ── IP Blocklist tab ──────────────────────────────────────────────────
        ip_tab = QWidget()
        il = QVBoxLayout(ip_tab)
        il.setContentsMargins(12, 12, 12, 12)

        add_row = QHBoxLayout()
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("Enter IP or CIDR (e.g. 1.2.3.4 or 10.0.0.0/8)")
        self.ip_edit.returnPressed.connect(self._add_ip)
        btn_add_ip = QPushButton("Block IP")
        btn_add_ip.clicked.connect(self._add_ip)
        btn_del_ip = QPushButton("Unblock Selected")
        btn_del_ip.setObjectName("secondary")
        btn_del_ip.clicked.connect(self._del_ip)
        add_row.addWidget(self.ip_edit)
        add_row.addWidget(btn_add_ip)
        add_row.addWidget(btn_del_ip)
        il.addLayout(add_row)

        self.ip_table = QTableWidget(0, 3)
        self.ip_table.setHorizontalHeaderLabels(["IP / CIDR", "Rule Name", "Direction"])
        self.ip_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ip_table.setAlternatingRowColors(True)
        self.ip_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ip_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.ip_table.verticalHeader().setVisible(False)
        il.addWidget(self.ip_table)

        # Known malicious ranges
        known = QHBoxLayout()
        known.addWidget(QLabel("Block Known Bad:"))
        threat_ranges = [
            ("Bogon 0.0.0.0/8", "0.0.0.0/8"),
            ("Loopback Abuse", "127.0.0.0/8"),
            ("RFC1918 from WAN", ""),
        ]
        for label, ip in threat_ranges:
            if ip:
                btn = QPushButton(label)
                btn.setObjectName("secondary")
                btn.setFixedHeight(26)
                btn.clicked.connect(lambda checked, i=ip: self._quick_block_ip(i))
                known.addWidget(btn)
        known.addStretch()
        il.addLayout(known)

        tabs.addTab(ip_tab, "IP Blocklist")

        # ── Domain/Host tab ───────────────────────────────────────────────────
        domain_tab = QWidget()
        dl = QVBoxLayout(domain_tab)
        dl.setContentsMargins(12, 12, 12, 12)

        d_add_row = QHBoxLayout()
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText("Domain to block (e.g. badsite.com)")
        self.domain_edit.returnPressed.connect(self._add_domain)
        btn_add_domain = QPushButton("Block Domain")
        btn_add_domain.clicked.connect(self._add_domain)
        btn_del_domain = QPushButton("Unblock Selected")
        btn_del_domain.setObjectName("secondary")
        btn_del_domain.clicked.connect(self._del_domain)
        d_add_row.addWidget(self.domain_edit)
        d_add_row.addWidget(btn_add_domain)
        d_add_row.addWidget(btn_del_domain)
        dl.addLayout(d_add_row)

        self.domain_table = QTableWidget(0, 2)
        self.domain_table.setHorizontalHeaderLabels(["Domain", "Category"])
        self.domain_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.domain_table.setAlternatingRowColors(True)
        self.domain_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.domain_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.domain_table.verticalHeader().setVisible(False)
        dl.addWidget(self.domain_table)

        # Bulk import
        bulk_frame = QFrame()
        bulk_frame.setObjectName("card")
        bulk_layout = QVBoxLayout(bulk_frame)
        bulk_layout.setContentsMargins(12, 8, 12, 8)
        bulk_layout.addWidget(QLabel("Bulk Import (one domain per line):"))
        self.bulk_edit = QTextEdit()
        self.bulk_edit.setMaximumHeight(80)
        self.bulk_edit.setPlaceholderText("facebook.com\ninstagram.com\ntiktok.com")
        bulk_btn = QPushButton("Import All")
        bulk_btn.clicked.connect(self._bulk_import)
        bulk_layout.addWidget(self.bulk_edit)
        bulk_layout.addWidget(bulk_btn)
        dl.addWidget(bulk_frame)

        tabs.addTab(domain_tab, "Domain Blocklist")

        layout.addWidget(tabs)

    def _load(self):
        self._load_ip_rules()
        self._load_domain_rules()

    def _load_ip_rules(self):
        rules = [r for r in database.get_rules() if r["name"].startswith("Block-IP:")]
        self._ip_blocks = rules
        self.ip_table.setRowCount(len(rules))
        for row, r in enumerate(rules):
            ip = r.get("remote_ip", "") or r.get("local_ip", "")
            for col, v in enumerate([ip, r["name"], r["direction"]]):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                item.setForeground(QColor("#c0392b"))
                self.ip_table.setItem(row, col, item)

    def _load_domain_rules(self):
        filters = [f for f in database.get_web_filters() if f["action"] == "BLOCK"]
        self.domain_table.setRowCount(len(filters))
        self._domain_ids = [f["id"] for f in filters]
        for row, f in enumerate(filters):
            for col, v in enumerate([f["pattern"], f["category"]]):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.domain_table.setItem(row, col, item)

    def _add_ip(self):
        ip = self.ip_edit.text().strip()
        if not ip:
            return
        name = f"Block-IP:{ip}"
        database.add_rule(name, "BLOCK", "BOTH", "ANY", "", ip, "", "", 1, 10)
        self.ip_edit.clear()
        self._load_ip_rules()

    def _del_ip(self):
        row = self.ip_table.currentRow()
        if row < 0 or row >= len(self._ip_blocks):
            return
        rule = self._ip_blocks[row]
        ret = QMessageBox.question(self, "Confirm", f"Unblock {rule['name'].replace('Block-IP:', '')}?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ret == QMessageBox.StandardButton.Yes:
            rules_engine.remove_rule_from_windows(rule)
            database.delete_rule(rule["id"])
            self._load_ip_rules()

    def _quick_block_ip(self, ip):
        self.ip_edit.setText(ip)
        self._add_ip()

    def _add_domain(self):
        domain = self.domain_edit.text().strip()
        if not domain:
            return
        database.add_web_filter(domain, "Custom", "BLOCK")
        self.domain_edit.clear()
        self._load_domain_rules()

    def _del_domain(self):
        row = self.domain_table.currentRow()
        if row < 0 or row >= len(self._domain_ids):
            return
        ret = QMessageBox.question(self, "Confirm", "Unblock this domain?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ret == QMessageBox.StandardButton.Yes:
            database.delete_web_filter(self._domain_ids[row])
            self._load_domain_rules()

    def _bulk_import(self):
        text = self.bulk_edit.toPlainText()
        domains = [line.strip() for line in text.splitlines() if line.strip()]
        for d in domains:
            database.add_web_filter(d, "Custom", "BLOCK")
        self.bulk_edit.clear()
        self._load_domain_rules()
        QMessageBox.information(self, "Import", f"Imported {len(domains)} domains.")
