"""Application Control panel."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QDialog,
    QFormLayout, QLineEdit, QComboBox, QCheckBox, QFileDialog,
    QMessageBox, QDialogButtonBox, QAbstractItemView, QSplitter, QFrame
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from db import database
from core import app_control


class AppRuleDialog(QDialog):
    def __init__(self, rule=None, parent=None):
        super().__init__(parent)
        self.rule = rule
        self.setWindowTitle("Add Application Rule" if not rule else "Edit Application Rule")
        self.setMinimumWidth(480)
        self._build()

    def _build(self):
        layout = QFormLayout(self)
        layout.setSpacing(10)

        self.name_edit = QLineEdit(self.rule["name"] if self.rule else "")
        self.name_edit.setPlaceholderText("e.g. Block BitTorrent")

        exe_row = QHBoxLayout()
        self.exe_edit = QLineEdit(self.rule["exe_path"] if self.rule else "")
        self.exe_edit.setPlaceholderText("Full path to .exe")
        browse_btn = QPushButton("Browse...")
        browse_btn.setObjectName("secondary")
        browse_btn.clicked.connect(self._browse)
        exe_row.addWidget(self.exe_edit)
        exe_row.addWidget(browse_btn)

        self.action_combo = QComboBox()
        self.action_combo.addItems(["ALLOW", "BLOCK"])
        if self.rule:
            self.action_combo.setCurrentText(self.rule["action"])

        self.direction_combo = QComboBox()
        self.direction_combo.addItems(["BOTH", "IN", "OUT"])
        if self.rule:
            self.direction_combo.setCurrentText(self.rule.get("direction", "BOTH"))

        self.enabled_check = QCheckBox("Enabled")
        self.enabled_check.setChecked(bool(self.rule["enabled"]) if self.rule else True)

        self.desc_edit = QLineEdit(self.rule.get("description", "") if self.rule else "")
        self.desc_edit.setPlaceholderText("Optional")

        layout.addRow("Name *", self.name_edit)
        layout.addRow("Executable *", exe_row)
        layout.addRow("Action", self.action_combo)
        layout.addRow("Direction", self.direction_combo)
        layout.addRow("", self.enabled_check)
        layout.addRow("Description", self.desc_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Executable", "",
                                              "Executables (*.exe);;All Files (*)")
        if path:
            self.exe_edit.setText(path)

    def _accept(self):
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Name is required.")
            return
        if not self.exe_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Executable path is required.")
            return
        self.accept()

    def get_data(self):
        return {
            "name": self.name_edit.text().strip(),
            "exe_path": self.exe_edit.text().strip(),
            "action": self.action_combo.currentText(),
            "direction": self.direction_combo.currentText(),
            "enabled": 1 if self.enabled_check.isChecked() else 0,
            "description": self.desc_edit.text().strip(),
        }


class AppControlPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self.refresh()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_running)
        self._timer.start(5000)
        self._refresh_running()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("Application Control")
        title.setObjectName("heading")
        layout.addWidget(title)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: rules
        left = QFrame()
        left.setObjectName("card")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 12, 12, 12)

        rules_hdr = QHBoxLayout()
        rules_hdr.addWidget(QLabel("Application Rules"))
        btn_add = QPushButton("+ Add")
        btn_add.clicked.connect(self._add_rule)
        btn_edit = QPushButton("Edit")
        btn_edit.setObjectName("secondary")
        btn_edit.clicked.connect(self._edit_rule)
        btn_del = QPushButton("Delete")
        btn_del.setObjectName("danger")
        btn_del.clicked.connect(self._delete_rule)
        btn_sync = QPushButton("Sync to WF")
        btn_sync.setObjectName("secondary")
        btn_sync.clicked.connect(self._sync)
        for b in (btn_add, btn_edit, btn_del, btn_sync):
            rules_hdr.addWidget(b)
        ll.addLayout(rules_hdr)

        self.rules_table = QTableWidget(0, 5)
        self.rules_table.setHorizontalHeaderLabels(["Name", "Executable", "Action", "Direction", "Status"])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.rules_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rules_table.verticalHeader().setVisible(False)
        self.rules_table.doubleClicked.connect(self._edit_rule)
        ll.addWidget(self.rules_table)
        splitter.addWidget(left)

        # Right: running apps
        right = QFrame()
        right.setObjectName("card")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(12, 12, 12, 12)

        run_hdr = QHBoxLayout()
        run_hdr.addWidget(QLabel("Active Network Apps"))
        btn_block_now = QPushButton("Block Selected Now")
        btn_block_now.setObjectName("danger")
        btn_block_now.clicked.connect(self._block_selected_app)
        btn_add_from = QPushButton("Add as Rule")
        btn_add_from.setObjectName("secondary")
        btn_add_from.clicked.connect(self._add_from_running)
        run_hdr.addWidget(btn_add_from)
        run_hdr.addWidget(btn_block_now)
        rl.addLayout(run_hdr)

        self.running_table = QTableWidget(0, 4)
        self.running_table.setHorizontalHeaderLabels(["Name", "Executable", "Connections", "PID"])
        self.running_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.running_table.setAlternatingRowColors(True)
        self.running_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.running_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.running_table.verticalHeader().setVisible(False)
        rl.addWidget(self.running_table)
        splitter.addWidget(right)

        splitter.setSizes([500, 400])
        layout.addWidget(splitter)

    def refresh(self):
        rules = database.get_app_rules()
        self.rules_table.setRowCount(len(rules))
        for row, r in enumerate(rules):
            action_color = "#27ae60" if r["action"] == "ALLOW" else "#c0392b"
            vals = [r["name"], r["exe_path"], r["action"], r.get("direction", "BOTH"),
                    "Enabled" if r["enabled"] else "Disabled"]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 2:
                    item.setForeground(QColor(action_color))
                self.rules_table.setItem(row, col, item)

    def _refresh_running(self):
        apps = app_control.get_running_apps()
        self.running_table.setRowCount(len(apps))
        for row, a in enumerate(apps):
            for col, v in enumerate([a["name"], a["exe"], str(a["connections"]), str(a["pid"])]):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.running_table.setItem(row, col, item)

    def _selected_rule_id(self):
        row = self.rules_table.currentRow()
        if row < 0:
            return None
        rules = database.get_app_rules()
        return rules[row]["id"] if row < len(rules) else None

    def _add_rule(self):
        dlg = AppRuleDialog(parent=self)
        if dlg.exec():
            data = dlg.get_data()
            database.add_app_rule(**data)
            self.refresh()

    def _edit_rule(self):
        rule_id = self._selected_rule_id()
        if not rule_id:
            return
        rule = next((r for r in database.get_app_rules() if r["id"] == rule_id), None)
        if not rule:
            return
        dlg = AppRuleDialog(rule=rule, parent=self)
        if dlg.exec():
            database.update_app_rule(rule_id, **dlg.get_data())
            self.refresh()

    def _delete_rule(self):
        rule_id = self._selected_rule_id()
        if not rule_id:
            return
        ret = QMessageBox.question(self, "Confirm", "Delete selected app rule?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ret == QMessageBox.StandardButton.Yes:
            rule = next((r for r in database.get_app_rules() if r["id"] == rule_id), None)
            if rule:
                app_control.remove_app_rule(rule)
            database.delete_app_rule(rule_id)
            self.refresh()

    def _sync(self):
        results = app_control.sync_all_app_rules()
        ok_count = sum(1 for _, ok, _ in results if ok)
        QMessageBox.information(self, "Sync", f"Synced {ok_count}/{len(results)} app rules.")

    def _block_selected_app(self):
        row = self.running_table.currentRow()
        if row < 0:
            return
        pid_item = self.running_table.item(row, 3)
        if not pid_item:
            return
        ok, msg = app_control.block_process_now(int(pid_item.text()))
        QMessageBox.information(self, "Block App", msg)

    def _add_from_running(self):
        row = self.running_table.currentRow()
        if row < 0:
            return
        name = self.running_table.item(row, 0).text() if self.running_table.item(row, 0) else ""
        exe = self.running_table.item(row, 1).text() if self.running_table.item(row, 1) else ""
        rule = {"name": name, "exe_path": exe, "action": "BLOCK", "direction": "BOTH",
                "enabled": 1, "description": ""}
        dlg = AppRuleDialog(rule=rule, parent=self)
        if dlg.exec():
            database.add_app_rule(**dlg.get_data())
            self.refresh()
