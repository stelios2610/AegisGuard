"""VPN panel - OpenVPN, WireGuard, and Site-to-Site IPSec."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QDialog, QFormLayout, QLineEdit,
    QComboBox, QCheckBox, QMessageBox, QDialogButtonBox, QAbstractItemView,
    QFrame, QTabWidget, QTextEdit, QFileDialog, QGroupBox, QSplitter,
    QSpinBox
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont
from db import database
from core import vpn_manager, ipsec_manager


class VPNProfileDialog(QDialog):
    def __init__(self, profile=None, parent=None):
        super().__init__(parent)
        self.profile = profile
        self.setWindowTitle("Add VPN Profile" if not profile else "Edit VPN Profile")
        self.setMinimumWidth(480)
        self._build()

    def _build(self):
        layout = QFormLayout(self)
        layout.setSpacing(10)

        self.name_edit = QLineEdit(self.profile["name"] if self.profile else "")
        self.name_edit.setPlaceholderText("e.g. Office VPN")

        self.type_combo = QComboBox()
        self.type_combo.addItems(["OpenVPN", "WireGuard"])
        if self.profile:
            self.type_combo.setCurrentText(self.profile["type"])

        config_row = QHBoxLayout()
        self.config_edit = QLineEdit(self.profile["config_path"] if self.profile else "")
        self.config_edit.setPlaceholderText("Path to .ovpn or .conf file")
        browse_btn = QPushButton("Browse...")
        browse_btn.setObjectName("secondary")
        browse_btn.clicked.connect(self._browse)
        config_row.addWidget(self.config_edit)
        config_row.addWidget(browse_btn)

        self.server_edit = QLineEdit(self.profile.get("server", "") if self.profile else "")
        self.server_edit.setPlaceholderText("e.g. vpn.company.com:1194 (optional)")

        self.auto_check = QCheckBox("Auto-connect on startup")
        self.auto_check.setChecked(bool(self.profile.get("auto_connect", 0)) if self.profile else False)

        layout.addRow("Name *", self.name_edit)
        layout.addRow("Type", self.type_combo)
        layout.addRow("Config File *", config_row)
        layout.addRow("Server (info)", self.server_edit)
        layout.addRow("", self.auto_check)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _browse(self):
        vtype = self.type_combo.currentText()
        if vtype == "OpenVPN":
            filt = "OpenVPN Config (*.ovpn *.conf);;All Files (*)"
        else:
            filt = "WireGuard Config (*.conf);;All Files (*)"
        path, _ = QFileDialog.getOpenFileName(self, "Select VPN Config", "", filt)
        if path:
            self.config_edit.setText(path)

    def _accept(self):
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Name is required.")
            return
        if not self.config_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Config file path is required.")
            return
        self.accept()

    def get_data(self):
        return {
            "name": self.name_edit.text().strip(),
            "vpn_type": self.type_combo.currentText(),
            "config_path": self.config_edit.text().strip(),
            "server": self.server_edit.text().strip(),
            "auto_connect": 1 if self.auto_check.isChecked() else 0,
        }


class IPSecDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Site-to-Site IPSec Tunnel")
        self.setMinimumWidth(520)
        self._build()

    def _build(self):
        layout = QFormLayout(self)
        layout.setSpacing(10)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g. Branch-Office-1")

        self.local_ip_edit = QLineEdit()
        self.local_ip_edit.setPlaceholderText("e.g. 192.168.1.0/24")

        self.remote_ip_edit = QLineEdit()
        self.remote_ip_edit.setPlaceholderText("e.g. 10.0.0.1 (remote gateway IP)")

        self.local_subnet_edit = QLineEdit()
        self.local_subnet_edit.setPlaceholderText("e.g. 192.168.1.0/24")

        self.remote_subnet_edit = QLineEdit()
        self.remote_subnet_edit.setPlaceholderText("e.g. 10.0.1.0/24")

        self.psk_edit = QLineEdit()
        self.psk_edit.setPlaceholderText("Pre-Shared Key")
        gen_btn = QPushButton("Generate")
        gen_btn.setObjectName("secondary")
        gen_btn.clicked.connect(lambda: self.psk_edit.setText(ipsec_manager.generate_psk()))
        psk_row = QHBoxLayout()
        psk_row.addWidget(self.psk_edit)
        psk_row.addWidget(gen_btn)

        self.ike_combo = QComboBox()
        self.ike_combo.addItems(["AES256", "AES128", "3DES"])

        self.hash_combo = QComboBox()
        self.hash_combo.addItems(["SHA256", "SHA384", "SHA512", "SHA1"])

        self.dh_combo = QComboBox()
        self.dh_combo.addItems(["DH14", "DH15", "DH16", "DH19", "DH20"])

        layout.addRow("Tunnel Name *", self.name_edit)
        layout.addRow("Local Subnet *", self.local_subnet_edit)
        layout.addRow("Remote Gateway IP *", self.remote_ip_edit)
        layout.addRow("Remote Subnet *", self.remote_subnet_edit)
        layout.addRow("Pre-Shared Key *", psk_row)
        layout.addRow("IKE Encryption", self.ike_combo)
        layout.addRow("IKE Hash", self.hash_combo)
        layout.addRow("DH Group", self.dh_combo)

        note = QLabel("Note: Requires Administrator privileges and matching config on remote peer.")
        note.setObjectName("subheading")
        note.setWordWrap(True)
        layout.addRow(note)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _accept(self):
        for field, label in [
            (self.name_edit, "Name"),
            (self.local_subnet_edit, "Local Subnet"),
            (self.remote_ip_edit, "Remote Gateway IP"),
            (self.remote_subnet_edit, "Remote Subnet"),
            (self.psk_edit, "Pre-Shared Key"),
        ]:
            if not field.text().strip():
                QMessageBox.warning(self, "Validation", f"{label} is required.")
                return
        self.accept()

    def get_data(self):
        return {
            "name": self.name_edit.text().strip(),
            "local_ip": "",
            "remote_ip": self.remote_ip_edit.text().strip(),
            "psk": self.psk_edit.text().strip(),
            "local_subnet": self.local_subnet_edit.text().strip(),
            "remote_subnet": self.remote_subnet_edit.text().strip(),
            "ike_cipher": self.ike_combo.currentText(),
            "ike_hash": self.hash_combo.currentText(),
            "dh_group": self.dh_combo.currentText(),
        }


class WGConfigDialog(QDialog):
    """WireGuard config generator."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WireGuard Config Generator")
        self.setMinimumSize(550, 420)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.endpoint_edit = QLineEdit()
        self.endpoint_edit.setPlaceholderText("e.g. vpn.server.com:51820")

        self.server_pub_edit = QLineEdit()
        self.server_pub_edit.setPlaceholderText("Server's public key (base64)")

        self.client_priv_edit = QLineEdit()
        self.client_priv_edit.setPlaceholderText("Your private key (base64)")

        self.client_addr_edit = QLineEdit()
        self.client_addr_edit.setPlaceholderText("e.g. 10.8.0.2/32")

        self.dns_edit = QLineEdit("1.1.1.1")
        self.allowed_edit = QLineEdit("0.0.0.0/0")

        form.addRow("Server Endpoint *", self.endpoint_edit)
        form.addRow("Server Public Key *", self.server_pub_edit)
        form.addRow("Client Private Key *", self.client_priv_edit)
        form.addRow("Client Address *", self.client_addr_edit)
        form.addRow("DNS", self.dns_edit)
        form.addRow("Allowed IPs", self.allowed_edit)
        layout.addLayout(form)

        gen_btn = QPushButton("Generate Config")
        gen_btn.clicked.connect(self._generate)
        layout.addWidget(gen_btn)

        self.result_edit = QTextEdit()
        self.result_edit.setReadOnly(True)
        self.result_edit.setPlaceholderText("Generated config will appear here...")
        layout.addWidget(self.result_edit)

        save_btn = QPushButton("Save Config File...")
        save_btn.setObjectName("secondary")
        save_btn.clicked.connect(self._save)
        layout.addWidget(save_btn)

        close_btn = QPushButton("Close")
        close_btn.setObjectName("secondary")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

    def _generate(self):
        config = vpn_manager.generate_wireguard_config(
            self.endpoint_edit.text().strip(),
            self.server_pub_edit.text().strip(),
            self.client_priv_edit.text().strip(),
            self.client_addr_edit.text().strip(),
            self.dns_edit.text().strip(),
            self.allowed_edit.text().strip(),
        )
        self.result_edit.setPlainText(config)

    def _save(self):
        config = self.result_edit.toPlainText()
        if not config:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save WireGuard Config", "wg0.conf",
                                              "WireGuard Config (*.conf)")
        if path:
            with open(path, "w") as f:
                f.write(config)
            QMessageBox.information(self, "Saved", f"Config saved to {path}")


class VPNPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self.refresh()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_status_column)
        self._timer.start(4000)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("VPN")
        title.setObjectName("heading")
        layout.addWidget(title)

        tabs = QTabWidget()

        # ── Mobile/Remote VPN tab ─────────────────────────────────────────────
        mobile_tab = QWidget()
        ml = QVBoxLayout(mobile_tab)
        ml.setSpacing(10)
        ml.setContentsMargins(12, 12, 12, 12)

        mobile_hdr = QHBoxLayout()
        mobile_hdr.addWidget(QLabel("Remote Access VPN (OpenVPN / WireGuard)"))
        mobile_hdr.addStretch()
        btn_add = QPushButton("+ Add Profile")
        btn_add.clicked.connect(self._add_profile)
        btn_edit = QPushButton("Edit")
        btn_edit.setObjectName("secondary")
        btn_edit.clicked.connect(self._edit_profile)
        btn_del = QPushButton("Delete")
        btn_del.setObjectName("danger")
        btn_del.clicked.connect(self._delete_profile)
        btn_connect = QPushButton("Connect")
        btn_connect.setObjectName("success")
        btn_connect.clicked.connect(self._connect)
        btn_disconnect = QPushButton("Disconnect")
        btn_disconnect.setObjectName("danger")
        btn_disconnect.clicked.connect(self._disconnect)
        btn_wg_gen = QPushButton("WG Config Generator")
        btn_wg_gen.setObjectName("secondary")
        btn_wg_gen.clicked.connect(self._wg_generator)
        for b in (btn_add, btn_edit, btn_del, btn_connect, btn_disconnect, btn_wg_gen):
            mobile_hdr.addWidget(b)
        ml.addLayout(mobile_hdr)

        self.vpn_table = QTableWidget(0, 6)
        self.vpn_table.setHorizontalHeaderLabels(["Name", "Type", "Config", "Server", "Auto", "Status"])
        self.vpn_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.vpn_table.setAlternatingRowColors(True)
        self.vpn_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.vpn_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.vpn_table.verticalHeader().setVisible(False)
        self.vpn_table.doubleClicked.connect(self._connect)
        ml.addWidget(self.vpn_table)

        # VPN status info
        self.vpn_info = QLabel("Select a profile and click Connect.")
        self.vpn_info.setObjectName("subheading")
        ml.addWidget(self.vpn_info)

        tabs.addTab(mobile_tab, "Remote Access VPN")

        # ── Site-to-Site IPSec tab ────────────────────────────────────────────
        s2s_tab = QWidget()
        sl = QVBoxLayout(s2s_tab)
        sl.setSpacing(10)
        sl.setContentsMargins(12, 12, 12, 12)

        s2s_hdr = QHBoxLayout()
        s2s_hdr.addWidget(QLabel("Site-to-Site IPSec Tunnels"))
        s2s_hdr.addStretch()
        btn_new_ipsec = QPushButton("+ New Tunnel")
        btn_new_ipsec.clicked.connect(self._new_ipsec)
        btn_del_ipsec = QPushButton("Delete Tunnel")
        btn_del_ipsec.setObjectName("danger")
        btn_del_ipsec.clicked.connect(self._delete_ipsec)
        btn_refresh_sa = QPushButton("Refresh SA")
        btn_refresh_sa.setObjectName("secondary")
        btn_refresh_sa.clicked.connect(self._refresh_sa)
        for b in (btn_new_ipsec, btn_del_ipsec, btn_refresh_sa):
            s2s_hdr.addWidget(b)
        sl.addLayout(s2s_hdr)

        self.ipsec_table = QTableWidget(0, 3)
        self.ipsec_table.setHorizontalHeaderLabels(["Tunnel Name", "Status", "Enabled"])
        self.ipsec_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ipsec_table.setAlternatingRowColors(True)
        self.ipsec_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ipsec_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.ipsec_table.verticalHeader().setVisible(False)
        sl.addWidget(self.ipsec_table)

        sa_group = QGroupBox("Active Security Associations")
        sa_layout = QVBoxLayout(sa_group)
        self.sa_table = QTableWidget(0, 3)
        self.sa_table.setHorizontalHeaderLabels(["Local Address", "Remote Address", "State"])
        self.sa_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.sa_table.setAlternatingRowColors(True)
        self.sa_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sa_table.verticalHeader().setVisible(False)
        sa_layout.addWidget(self.sa_table)
        sl.addWidget(sa_group)

        ipsec_note = QLabel(
            "Site-to-Site IPSec uses Windows IKEv2/IPSec. "
            "Requires Administrator privileges and matching configuration on the remote peer."
        )
        ipsec_note.setObjectName("subheading")
        ipsec_note.setWordWrap(True)
        sl.addWidget(ipsec_note)

        tabs.addTab(s2s_tab, "Site-to-Site IPSec")

        layout.addWidget(tabs)

    def refresh(self):
        profiles = database.get_vpn_profiles()
        self.vpn_table.setRowCount(len(profiles))
        status_colors = {
            "Connected": "#27ae60", "Connecting": "#e67e22",
            "Disconnected": "#8b949e", "Error": "#c0392b"
        }
        for row, p in enumerate(profiles):
            status = vpn_manager.get_status(p["id"]).get("status", p.get("status", "Disconnected"))
            vals = [
                p["name"], p["type"], p["config_path"],
                p.get("server", ""), "Yes" if p.get("auto_connect") else "No",
                status
            ]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 5:
                    item.setForeground(QColor(status_colors.get(v, "#ffffff")))
                self.vpn_table.setItem(row, col, item)

        self._refresh_ipsec()

    def _refresh_ipsec(self):
        tunnels = ipsec_manager.get_ipsec_tunnels()
        self.ipsec_table.setRowCount(len(tunnels))
        for row, t in enumerate(tunnels):
            name = str(t.get("DisplayName", t.get("Name", ""))).replace("FGUARD IPSec ", "")
            enabled = "Yes" if t.get("Enabled", True) else "No"
            status = str(t.get("PrimaryStatus", "Unknown"))
            for col, v in enumerate([name, status, enabled]):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.ipsec_table.setItem(row, col, item)

    def _refresh_sa(self):
        sas = ipsec_manager.get_ipsec_sa()
        self.sa_table.setRowCount(len(sas))
        for row, sa in enumerate(sas):
            for col, v in enumerate([
                str(sa.get("LocalAddress", "")),
                str(sa.get("RemoteAddress", "")),
                str(sa.get("State", "")),
            ]):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.sa_table.setItem(row, col, item)

    def _update_status_column(self):
        profiles = database.get_vpn_profiles()
        status_colors = {
            "Connected": "#27ae60", "Connecting": "#e67e22",
            "Disconnected": "#8b949e", "Error": "#c0392b"
        }
        for row, p in enumerate(profiles):
            status = vpn_manager.get_status(p["id"]).get("status", "Disconnected")
            item = QTableWidgetItem(status)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            item.setForeground(QColor(status_colors.get(status, "#ffffff")))
            self.vpn_table.setItem(row, 5, item)

    def _selected_profile(self):
        row = self.vpn_table.currentRow()
        if row < 0:
            return None
        profiles = database.get_vpn_profiles()
        return profiles[row] if row < len(profiles) else None

    def _add_profile(self):
        dlg = VPNProfileDialog(parent=self)
        if dlg.exec():
            data = dlg.get_data()
            database.add_vpn_profile(**data)
            self.refresh()

    def _edit_profile(self):
        p = self._selected_profile()
        if not p:
            return
        dlg = VPNProfileDialog(profile=p, parent=self)
        if dlg.exec():
            data = dlg.get_data()
            database.update_vpn_profile(p["id"], **{
                "name": data["name"], "type": data["vpn_type"],
                "config_path": data["config_path"], "server": data["server"],
                "auto_connect": data["auto_connect"]
            })
            self.refresh()

    def _delete_profile(self):
        p = self._selected_profile()
        if not p:
            return
        ret = QMessageBox.question(self, "Confirm", f"Delete profile '{p['name']}'?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ret == QMessageBox.StandardButton.Yes:
            database.delete_vpn_profile(p["id"])
            self.refresh()

    def _connect(self):
        p = self._selected_profile()
        if not p:
            QMessageBox.information(self, "VPN", "Select a VPN profile first.")
            return
        ok, msg = vpn_manager.connect(p)
        self.vpn_info.setText(msg)
        if not ok:
            QMessageBox.warning(self, "VPN Error", msg)

    def _disconnect(self):
        p = self._selected_profile()
        if not p:
            return
        ok, msg = vpn_manager.disconnect(p)
        self.vpn_info.setText(msg)

    def _wg_generator(self):
        dlg = WGConfigDialog(parent=self)
        dlg.exec()

    def _new_ipsec(self):
        dlg = IPSecDialog(parent=self)
        if dlg.exec():
            data = dlg.get_data()
            ok, msg = ipsec_manager.create_ipsec_tunnel(**data)
            if ok:
                QMessageBox.information(self, "IPSec", msg)
            else:
                QMessageBox.warning(self, "IPSec Error", msg)
            self._refresh_ipsec()

    def _delete_ipsec(self):
        row = self.ipsec_table.currentRow()
        if row < 0:
            return
        tunnels = ipsec_manager.get_ipsec_tunnels()
        if row >= len(tunnels):
            return
        name_raw = str(tunnels[row].get("Name", ""))
        name = name_raw.replace("FGUARD-IPSec-", "")
        ret = QMessageBox.question(self, "Confirm", f"Delete IPSec tunnel '{name}'?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ret == QMessageBox.StandardButton.Yes:
            ipsec_manager.remove_ipsec_tunnel(name)
            self._refresh_ipsec()
