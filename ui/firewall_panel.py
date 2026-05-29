"""Firewall Policies panel."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QDialog, QFormLayout, QLineEdit,
    QComboBox, QSpinBox, QCheckBox, QTextEdit, QMessageBox, QDialogButtonBox,
    QFrame, QAbstractItemView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from db import database
from core import rules_engine


class RuleDialog(QDialog):
    def __init__(self, rule=None, parent=None):
        super().__init__(parent)
        self.rule = rule
        self.setWindowTitle("Add Firewall Rule" if not rule else "Edit Firewall Rule")
        self.setMinimumWidth(480)
        self._build()

    def _build(self):
        layout = QFormLayout(self)
        layout.setSpacing(10)

        self.name_edit = QLineEdit(self.rule["name"] if self.rule else "")
        self.name_edit.setPlaceholderText("e.g. Block HTTP")

        self.action_combo = QComboBox()
        self.action_combo.addItems(["ALLOW", "BLOCK"])
        if self.rule:
            self.action_combo.setCurrentText(self.rule["action"])

        self.direction_combo = QComboBox()
        self.direction_combo.addItems(["IN", "OUT", "BOTH"])
        if self.rule:
            self.direction_combo.setCurrentText(self.rule["direction"])

        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["ANY", "TCP", "UDP", "ICMP"])
        if self.rule:
            self.protocol_combo.setCurrentText(self.rule.get("protocol", "ANY"))

        self.local_ip = QLineEdit(self.rule.get("local_ip", "") if self.rule else "")
        self.local_ip.setPlaceholderText("e.g. 192.168.1.0/24 (blank = any)")

        self.remote_ip = QLineEdit(self.rule.get("remote_ip", "") if self.rule else "")
        self.remote_ip.setPlaceholderText("e.g. 10.0.0.1 (blank = any)")

        self.local_port = QLineEdit(self.rule.get("local_port", "") if self.rule else "")
        self.local_port.setPlaceholderText("e.g. 80, 443, 8000-8080 (blank = any)")

        self.remote_port = QLineEdit(self.rule.get("remote_port", "") if self.rule else "")
        self.remote_port.setPlaceholderText("e.g. 443 (blank = any)")

        self.priority_spin = QSpinBox()
        self.priority_spin.setRange(1, 9999)
        self.priority_spin.setValue(self.rule["priority"] if self.rule else 100)

        self.enabled_check = QCheckBox("Enabled")
        self.enabled_check.setChecked(bool(self.rule["enabled"]) if self.rule else True)

        self.desc_edit = QTextEdit(self.rule.get("description", "") if self.rule else "")
        self.desc_edit.setMaximumHeight(60)
        self.desc_edit.setPlaceholderText("Optional description")

        layout.addRow("Name *", self.name_edit)
        layout.addRow("Action", self.action_combo)
        layout.addRow("Direction", self.direction_combo)
        layout.addRow("Protocol", self.protocol_combo)
        layout.addRow("Local IP / Subnet", self.local_ip)
        layout.addRow("Remote IP / Subnet", self.remote_ip)
        layout.addRow("Local Port", self.local_port)
        layout.addRow("Remote Port", self.remote_port)
        layout.addRow("Priority", self.priority_spin)
        layout.addRow("", self.enabled_check)
        layout.addRow("Description", self.desc_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _accept(self):
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Name is required.")
            return
        self.accept()

    def get_data(self):
        return {
            "name": self.name_edit.text().strip(),
            "action": self.action_combo.currentText(),
            "direction": self.direction_combo.currentText(),
            "protocol": self.protocol_combo.currentText(),
            "local_ip": self.local_ip.text().strip(),
            "remote_ip": self.remote_ip.text().strip(),
            "local_port": self.local_port.text().strip(),
            "remote_port": self.remote_port.text().strip(),
            "priority": self.priority_spin.value(),
            "enabled": 1 if self.enabled_check.isChecked() else 0,
            "description": self.desc_edit.toPlainText().strip(),
        }


class FirewallPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("Firewall Policies")
        title.setObjectName("heading")
        hdr.addWidget(title)
        hdr.addStretch()

        btn_add = QPushButton("+ Add Rule")
        btn_add.clicked.connect(self._add_rule)
        btn_edit = QPushButton("Edit")
        btn_edit.setObjectName("secondary")
        btn_edit.clicked.connect(self._edit_rule)
        btn_del = QPushButton("Delete")
        btn_del.setObjectName("danger")
        btn_del.clicked.connect(self._delete_rule)
        btn_sync = QPushButton("Sync to Windows FW")
        btn_sync.setObjectName("secondary")
        btn_sync.clicked.connect(self._sync_rules)
        btn_toggle = QPushButton("Toggle Enable")
        btn_toggle.setObjectName("secondary")
        btn_toggle.clicked.connect(self._toggle_rule)

        for btn in (btn_add, btn_edit, btn_del, btn_toggle, btn_sync):
            hdr.addWidget(btn)
        layout.addLayout(hdr)

        # Info bar
        self.info_label = QLabel("")
        self.info_label.setObjectName("subheading")
        layout.addWidget(self.info_label)

        # Table
        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels([
            "ID", "Name", "Action", "Direction", "Protocol",
            "Local IP", "Remote IP", "Ports", "Priority", "Status"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.doubleClicked.connect(self._edit_rule)
        layout.addWidget(self.table)

        # Predefined rules quick-add
        quick = QHBoxLayout()
        quick.addWidget(QLabel("Quick Add:"))
        quick_rules = [
            ("Block Telnet", "BLOCK", "IN", "TCP", "", "", "", "23"),
            ("Block FTP", "BLOCK", "IN", "TCP", "", "", "", "21"),
            ("Allow HTTPS", "ALLOW", "OUT", "TCP", "", "", "", "443"),
            ("Allow DNS", "ALLOW", "OUT", "UDP", "", "", "", "53"),
            ("Block SMB", "BLOCK", "BOTH", "TCP", "", "", "", "445"),
        ]
        for label, *args in quick_rules:
            btn = QPushButton(label)
            btn.setObjectName("secondary")
            btn.setFixedHeight(28)
            btn.clicked.connect(lambda checked, a=args, l=label: self._quick_add(l, *a))
            quick.addWidget(btn)
        quick.addStretch()
        layout.addLayout(quick)

    def refresh(self):
        rules = database.get_rules()
        self.table.setRowCount(len(rules))
        action_colors = {"ALLOW": "#27ae60", "BLOCK": "#c0392b"}
        for row, r in enumerate(rules):
            ports = ""
            lp = r.get("local_port", "")
            rp = r.get("remote_port", "")
            if lp and rp:
                ports = f"L:{lp} R:{rp}"
            elif lp:
                ports = f"L:{lp}"
            elif rp:
                ports = f"R:{rp}"

            vals = [
                str(r["id"]), r["name"], r["action"], r["direction"],
                r.get("protocol", "ANY"),
                r.get("local_ip", "") or "ANY",
                r.get("remote_ip", "") or "ANY",
                ports or "ANY",
                str(r["priority"]),
                "Enabled" if r["enabled"] else "Disabled",
            ]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 2:
                    item.setForeground(QColor(action_colors.get(v, "#ffffff")))
                if not r["enabled"]:
                    item.setForeground(QColor("#555555"))
                self.table.setItem(row, col, item)
        self.info_label.setText(f"{len(rules)} rule(s) defined")

    def _selected_rule_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        return int(item.text()) if item else None

    def _add_rule(self):
        dlg = RuleDialog(parent=self)
        if dlg.exec():
            data = dlg.get_data()
            database.add_rule(**data)
            self.refresh()

    def _edit_rule(self):
        rule_id = self._selected_rule_id()
        if not rule_id:
            return
        rules = {r["id"]: r for r in database.get_rules()}
        rule = rules.get(rule_id)
        if not rule:
            return
        dlg = RuleDialog(rule=rule, parent=self)
        if dlg.exec():
            data = dlg.get_data()
            database.update_rule(rule_id, **data)
            self.refresh()

    def _delete_rule(self):
        rule_id = self._selected_rule_id()
        if not rule_id:
            return
        ret = QMessageBox.question(self, "Confirm", "Delete selected rule?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ret == QMessageBox.StandardButton.Yes:
            rule = next((r for r in database.get_rules() if r["id"] == rule_id), None)
            if rule:
                rules_engine.remove_rule_from_windows(rule)
            database.delete_rule(rule_id)
            self.refresh()

    def _toggle_rule(self):
        rule_id = self._selected_rule_id()
        if not rule_id:
            return
        rules = {r["id"]: r for r in database.get_rules()}
        rule = rules.get(rule_id)
        if rule:
            new_state = 0 if rule["enabled"] else 1
            database.update_rule(rule_id, enabled=new_state)
            self.refresh()

    def _sync_rules(self):
        results = rules_engine.sync_all_rules()
        ok_count = sum(1 for _, ok, _ in results if ok)
        QMessageBox.information(self, "Sync Complete",
                                f"Synced {ok_count}/{len(results)} rules to Windows Firewall.")

    def _quick_add(self, label, action, direction, proto, local_ip, remote_ip, local_port, remote_port):
        database.add_rule(label, action, direction, proto, local_ip, remote_ip,
                          local_port, remote_port)
        self.refresh()
