"""Web Filter panel."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QDialog, QFormLayout, QLineEdit,
    QComboBox, QCheckBox, QMessageBox, QDialogButtonBox, QAbstractItemView,
    QFrame, QSplitter, QGroupBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from db import database
from core import web_filter


class FilterDialog(QDialog):
    def __init__(self, entry=None, parent=None):
        super().__init__(parent)
        self.entry = entry
        self.setWindowTitle("Add Web Filter Rule" if not entry else "Edit Web Filter Rule")
        self.setMinimumWidth(440)
        self._build()

    def _build(self):
        layout = QFormLayout(self)
        layout.setSpacing(10)

        self.pattern_edit = QLineEdit(self.entry["pattern"] if self.entry else "")
        self.pattern_edit.setPlaceholderText("e.g. facebook.com or *.ads.example.com")

        self.category_combo = QComboBox()
        cats = [c["name"] for c in database.get_web_categories()]
        self.category_combo.addItems(cats)
        if self.entry:
            self.category_combo.setCurrentText(self.entry.get("category", "Custom"))

        self.action_combo = QComboBox()
        self.action_combo.addItems(["BLOCK", "ALLOW"])
        if self.entry:
            self.action_combo.setCurrentText(self.entry.get("action", "BLOCK"))

        self.enabled_check = QCheckBox("Enabled")
        self.enabled_check.setChecked(bool(self.entry["enabled"]) if self.entry else True)

        self.desc_edit = QLineEdit(self.entry.get("description", "") if self.entry else "")
        self.desc_edit.setPlaceholderText("Optional")

        layout.addRow("Domain / Pattern *", self.pattern_edit)
        layout.addRow("Category", self.category_combo)
        layout.addRow("Action", self.action_combo)
        layout.addRow("", self.enabled_check)
        layout.addRow("Description", self.desc_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _accept(self):
        if not self.pattern_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Pattern is required.")
            return
        self.accept()

    def get_data(self):
        return {
            "pattern": self.pattern_edit.text().strip(),
            "category": self.category_combo.currentText(),
            "action": self.action_combo.currentText(),
            "enabled": 1 if self.enabled_check.isChecked() else 0,
            "description": self.desc_edit.text().strip(),
        }


class WebFilterPanel(QWidget):
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
        title = QLabel("Web Filter")
        title.setObjectName("heading")
        hdr.addWidget(title)
        hdr.addStretch()

        self.status_label = QLabel("Status: Unknown")
        self.status_label.setObjectName("subheading")
        hdr.addWidget(self.status_label)

        btn_apply = QPushButton("Apply to Hosts File")
        btn_apply.clicked.connect(self._apply)
        btn_remove = QPushButton("Remove from Hosts")
        btn_remove.setObjectName("secondary")
        btn_remove.clicked.connect(self._remove)
        btn_flush = QPushButton("Flush DNS Cache")
        btn_flush.setObjectName("secondary")
        btn_flush.clicked.connect(self._flush_dns)
        for b in (btn_apply, btn_remove, btn_flush):
            hdr.addWidget(b)
        layout.addLayout(hdr)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: custom rules
        left = QFrame()
        left.setObjectName("card")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 12, 12, 12)

        rules_hdr = QHBoxLayout()
        rules_hdr.addWidget(QLabel("Custom Rules"))
        btn_add = QPushButton("+ Add")
        btn_add.clicked.connect(self._add_filter)
        btn_edit = QPushButton("Edit")
        btn_edit.setObjectName("secondary")
        btn_edit.clicked.connect(self._edit_filter)
        btn_del = QPushButton("Delete")
        btn_del.setObjectName("danger")
        btn_del.clicked.connect(self._delete_filter)
        for b in (btn_add, btn_edit, btn_del):
            rules_hdr.addWidget(b)
        ll.addLayout(rules_hdr)

        self.filter_table = QTableWidget(0, 4)
        self.filter_table.setHorizontalHeaderLabels(["Domain/Pattern", "Category", "Action", "Status"])
        self.filter_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.filter_table.setAlternatingRowColors(True)
        self.filter_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.filter_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.filter_table.verticalHeader().setVisible(False)
        self.filter_table.doubleClicked.connect(self._edit_filter)
        ll.addWidget(self.filter_table)

        # Quick add common domains
        quick = QHBoxLayout()
        quick.addWidget(QLabel("Block:"))
        quick_blocks = [
            ("Facebook", "facebook.com"), ("TikTok", "tiktok.com"),
            ("Instagram", "instagram.com"), ("YouTube", "youtube.com"),
            ("Twitter/X", "x.com"),
        ]
        for label, domain in quick_blocks:
            btn = QPushButton(label)
            btn.setObjectName("secondary")
            btn.setFixedHeight(26)
            btn.clicked.connect(lambda checked, d=domain: self._quick_block(d))
            quick.addWidget(btn)
        quick.addStretch()
        ll.addLayout(quick)

        splitter.addWidget(left)

        # Right: built-in categories
        right = QFrame()
        right.setObjectName("card")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(12, 12, 12, 12)
        rl.addWidget(QLabel("Category Filters"))

        self.category_checks = {}
        categories = database.get_web_categories()
        for cat in categories:
            cb = QCheckBox(cat["name"])
            cb.setChecked(bool(cat["enabled"]))
            cb.stateChanged.connect(lambda state, c=cat: self._toggle_category(c["name"], state))
            self.category_checks[cat["name"]] = cb
            rl.addWidget(cb)

        rl.addStretch()

        builtin_counts = {cat: len(domains) for cat, domains in web_filter.BUILTIN_CATEGORIES.items()}
        info_label = QLabel("\n".join(
            f"  {cat}: {count} domains"
            for cat, count in builtin_counts.items()
        ))
        info_label.setObjectName("subheading")
        rl.addWidget(info_label)

        splitter.addWidget(right)
        splitter.setSizes([600, 300])
        layout.addWidget(splitter)

        self._update_status()

    def _update_status(self):
        state, count = web_filter.get_hosts_status()
        if state == "active":
            self.status_label.setText(f"Status: Active ({count} entries in hosts file)")
            self.status_label.setStyleSheet("color: #27ae60;")
        elif state == "inactive":
            self.status_label.setText("Status: Not Applied")
            self.status_label.setStyleSheet("color: #e67e22;")
        else:
            self.status_label.setText("Status: Error (run as Administrator)")
            self.status_label.setStyleSheet("color: #c0392b;")

    def refresh(self):
        filters = database.get_web_filters()
        self.filter_table.setRowCount(len(filters))
        for row, f in enumerate(filters):
            action_color = "#c0392b" if f["action"] == "BLOCK" else "#27ae60"
            vals = [f["pattern"], f["category"], f["action"],
                    "Enabled" if f["enabled"] else "Disabled"]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 2:
                    item.setForeground(QColor(action_color))
                self.filter_table.setItem(row, col, item)
        self._update_status()

    def _apply(self):
        ok, msg = web_filter.apply_filters()
        if ok:
            web_filter.flush_dns()
            QMessageBox.information(self, "Success", "Web filter applied to hosts file.\nDNS cache flushed.")
        else:
            QMessageBox.warning(self, "Error", msg)
        self._update_status()

    def _remove(self):
        ok, msg = web_filter.remove_filters()
        if ok:
            web_filter.flush_dns()
            QMessageBox.information(self, "Success", "Web filter removed from hosts file.")
        else:
            QMessageBox.warning(self, "Error", msg)
        self._update_status()

    def _flush_dns(self):
        web_filter.flush_dns()
        QMessageBox.information(self, "DNS", "DNS cache flushed.")

    def _selected_filter_id(self):
        row = self.filter_table.currentRow()
        if row < 0:
            return None
        filters = database.get_web_filters()
        return filters[row]["id"] if row < len(filters) else None

    def _add_filter(self):
        dlg = FilterDialog(parent=self)
        if dlg.exec():
            database.add_web_filter(**dlg.get_data())
            self.refresh()

    def _edit_filter(self):
        fid = self._selected_filter_id()
        if not fid:
            return
        entry = next((f for f in database.get_web_filters() if f["id"] == fid), None)
        if not entry:
            return
        dlg = FilterDialog(entry=entry, parent=self)
        if dlg.exec():
            database.update_web_filter(fid, **dlg.get_data())
            self.refresh()

    def _delete_filter(self):
        fid = self._selected_filter_id()
        if not fid:
            return
        ret = QMessageBox.question(self, "Confirm", "Delete selected filter?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ret == QMessageBox.StandardButton.Yes:
            database.delete_web_filter(fid)
            self.refresh()

    def _quick_block(self, domain):
        database.add_web_filter(domain, "Custom", "BLOCK")
        self.refresh()

    def _toggle_category(self, name, state):
        enabled = 1 if state == Qt.CheckState.Checked.value else 0
        conn = database.get_connection()
        conn.execute("UPDATE web_categories SET enabled = ? WHERE name = ?", (enabled, name))
        conn.commit()
        conn.close()
