"""Settings & System panel."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFormLayout, QLineEdit, QComboBox, QCheckBox, QGroupBox,
    QTabWidget, QMessageBox, QFrame, QTextEdit
)
from PyQt6.QtCore import Qt
from db import database
from core import rules_engine, web_filter


class SettingsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self._load()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("System Settings")
        title.setObjectName("heading")
        layout.addWidget(title)

        tabs = QTabWidget()

        # ── General tab ───────────────────────────────────────────────────────
        general_tab = QWidget()
        gl = QVBoxLayout(general_tab)
        gl.setContentsMargins(16, 16, 16, 16)
        gl.setSpacing(16)

        fw_group = QGroupBox("Firewall")
        fw_form = QFormLayout(fw_group)

        self.fw_enabled = QCheckBox("Enable AegisGuard firewall engine")
        self.default_policy = QComboBox()
        self.default_policy.addItems(["ALLOW", "BLOCK"])
        self.log_blocked = QCheckBox("Log blocked connections")
        self.log_allowed = QCheckBox("Log allowed connections")
        self.max_logs = QLineEdit()
        self.max_logs.setPlaceholderText("e.g. 10000")

        fw_form.addRow("", self.fw_enabled)
        fw_form.addRow("Default Policy", self.default_policy)
        fw_form.addRow("", self.log_blocked)
        fw_form.addRow("", self.log_allowed)
        fw_form.addRow("Max Log Entries", self.max_logs)
        gl.addWidget(fw_group)

        wf_group = QGroupBox("Web Filter")
        wf_form = QFormLayout(wf_group)
        self.wf_enabled = QCheckBox("Enable Web Filter")
        self.wf_hosts = QCheckBox("Use hosts file for blocking")
        wf_form.addRow("", self.wf_enabled)
        wf_form.addRow("", self.wf_hosts)
        gl.addWidget(wf_group)

        ac_group = QGroupBox("Application Control")
        ac_form = QFormLayout(ac_group)
        self.ac_enabled = QCheckBox("Enable Application Control")
        ac_form.addRow("", self.ac_enabled)
        gl.addWidget(ac_group)

        gl.addStretch()

        save_btn = QPushButton("Save General Settings")
        save_btn.clicked.connect(self._save_general)
        gl.addWidget(save_btn)

        tabs.addTab(general_tab, "General")

        # ── VPN Paths tab ─────────────────────────────────────────────────────
        vpn_tab = QWidget()
        vl = QVBoxLayout(vpn_tab)
        vl.setContentsMargins(16, 16, 16, 16)
        vl.setSpacing(12)

        vpn_group = QGroupBox("VPN Executable Paths")
        vpn_form = QFormLayout(vpn_group)

        self.ovpn_path = QLineEdit()
        self.ovpn_path.setPlaceholderText("C:\\Program Files\\OpenVPN\\bin\\openvpn.exe")
        self.wg_path = QLineEdit()
        self.wg_path.setPlaceholderText("C:\\Program Files\\WireGuard\\wireguard.exe")

        vpn_form.addRow("OpenVPN Executable", self.ovpn_path)
        vpn_form.addRow("WireGuard Executable", self.wg_path)
        vl.addWidget(vpn_group)

        vpn_info = QLabel(
            "OpenVPN: Download from https://openvpn.net/community-downloads/\n"
            "WireGuard: Download from https://www.wireguard.com/install/"
        )
        vpn_info.setObjectName("subheading")
        vl.addWidget(vpn_info)
        vl.addStretch()

        save_vpn_btn = QPushButton("Save VPN Settings")
        save_vpn_btn.clicked.connect(self._save_vpn)
        vl.addWidget(save_vpn_btn)

        tabs.addTab(vpn_tab, "VPN Paths")

        # ── Windows Firewall tab ──────────────────────────────────────────────
        wf_status_tab = QWidget()
        ws = QVBoxLayout(wf_status_tab)
        ws.setContentsMargins(16, 16, 16, 16)

        ws.addWidget(QLabel("Windows Firewall Status"))

        self.wf_status_text = QTextEdit()
        self.wf_status_text.setReadOnly(True)
        ws.addWidget(self.wf_status_text)

        wf_btns = QHBoxLayout()
        btn_check = QPushButton("Check Status")
        btn_check.setObjectName("secondary")
        btn_check.clicked.connect(self._check_wf)
        btn_sync_all = QPushButton("Sync All Rules to WF")
        btn_sync_all.clicked.connect(self._sync_all)
        btn_enable_wf = QPushButton("Enable Windows FW")
        btn_enable_wf.setObjectName("success")
        btn_enable_wf.clicked.connect(self._enable_wf)
        for b in (btn_check, btn_sync_all, btn_enable_wf):
            wf_btns.addWidget(b)
        wf_btns.addStretch()
        ws.addLayout(wf_btns)

        tabs.addTab(wf_status_tab, "Windows Firewall")

        # ── About tab ─────────────────────────────────────────────────────────
        about_tab = QWidget()
        al = QVBoxLayout(about_tab)
        al.setAlignment(Qt.AlignmentFlag.AlignCenter)

        logo = QLabel("🛡 AegisGuard")
        logo.setStyleSheet("font-size: 36px; font-weight: bold; color: #c0392b;")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)

        ver = QLabel("Version 1.0.0")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver.setObjectName("subheading")

        desc = QLabel(
            "AegisGuard is a comprehensive network security solution\n"
            "featuring Firewall, Application Control, Web Filter,\n"
            "IPS, VPN (OpenVPN, WireGuard, Site-to-Site IPSec),\n"
            "and real-time network monitoring."
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setObjectName("subheading")

        features = QLabel(
            "Features:\n"
            "  Stateful Firewall with rule priorities\n"
            "  Application-level access control\n"
            "  Web content filtering (hosts file)\n"
            "  Signature-based Intrusion Prevention\n"
            "  OpenVPN & WireGuard client management\n"
            "  Site-to-Site IKEv2/IPSec tunnels\n"
            "  Real-time network traffic monitor\n"
            "  Event logging & CSV export"
        )
        features.setAlignment(Qt.AlignmentFlag.AlignCenter)

        for w in (logo, ver, desc, features):
            al.addWidget(w)
        al.addStretch()

        tabs.addTab(about_tab, "About")

        layout.addWidget(tabs)

    def _load(self):
        s = database.get_all_settings()
        self.fw_enabled.setChecked(s.get("firewall_enabled", "1") == "1")
        self.default_policy.setCurrentText(s.get("default_policy", "ALLOW"))
        self.log_blocked.setChecked(s.get("log_blocked", "1") == "1")
        self.log_allowed.setChecked(s.get("log_allowed", "0") == "1")
        self.max_logs.setText(s.get("max_log_entries", "10000"))
        self.wf_enabled.setChecked(s.get("web_filter_enabled", "1") == "1")
        self.wf_hosts.setChecked(s.get("web_filter_use_hosts", "1") == "1")
        self.ac_enabled.setChecked(s.get("app_control_enabled", "1") == "1")
        self.ovpn_path.setText(s.get("vpn_openvpn_path", ""))
        self.wg_path.setText(s.get("vpn_wireguard_path", ""))

    def _save_general(self):
        database.set_setting("firewall_enabled", "1" if self.fw_enabled.isChecked() else "0")
        database.set_setting("default_policy", self.default_policy.currentText())
        database.set_setting("log_blocked", "1" if self.log_blocked.isChecked() else "0")
        database.set_setting("log_allowed", "1" if self.log_allowed.isChecked() else "0")
        database.set_setting("max_log_entries", self.max_logs.text() or "10000")
        database.set_setting("web_filter_enabled", "1" if self.wf_enabled.isChecked() else "0")
        database.set_setting("web_filter_use_hosts", "1" if self.wf_hosts.isChecked() else "0")
        database.set_setting("app_control_enabled", "1" if self.ac_enabled.isChecked() else "0")
        QMessageBox.information(self, "Saved", "General settings saved.")

    def _save_vpn(self):
        database.set_setting("vpn_openvpn_path", self.ovpn_path.text())
        database.set_setting("vpn_wireguard_path", self.wg_path.text())
        QMessageBox.information(self, "Saved", "VPN path settings saved.")

    def _check_wf(self):
        status = rules_engine.get_windows_firewall_state()
        self.wf_status_text.setPlainText(status)

    def _sync_all(self):
        results = rules_engine.sync_all_rules()
        ok = sum(1 for _, ok, _ in results if ok)
        self.wf_status_text.setPlainText(
            f"Synced {ok}/{len(results)} rules to Windows Firewall.\n\n" +
            "\n".join(f"{'OK' if ok else 'FAIL'} | {name}: {msg}"
                      for name, ok, msg in results)
        )

    def _enable_wf(self):
        import subprocess
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                       capture_output=True)
        self._check_wf()
