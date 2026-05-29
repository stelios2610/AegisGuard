"""AegisGuard main window."""
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QListWidget,
    QListWidgetItem, QStackedWidget, QLabel, QStatusBar, QFrame,
    QSizePolicy, QSplitter
)
from PyQt6.QtCore import Qt, QTimer, QSize
from PyQt6.QtGui import QFont, QIcon, QColor

from ui.dashboard import DashboardPanel
from ui.firewall_panel import FirewallPanel
from ui.app_control_panel import AppControlPanel
from ui.web_filter_panel import WebFilterPanel
from ui.ips_panel import IPSPanel
from ui.vpn_panel import VPNPanel
from ui.monitor_panel import MonitorPanel
from ui.logs_panel import LogsPanel
from ui.blocked_sites_panel import BlockedSitesPanel
from ui.settings_panel import SettingsPanel
from db import database
from core import ips


NAV_ITEMS = [
    ("  Dashboard",         "dashboard"),
    ("  Firewall Policies", "firewall"),
    ("  Application Control","appcontrol"),
    ("  Web Filter",        "webfilter"),
    ("  Intrusion Prevention","ips"),
    ("  Blocked Sites",     "blocked"),
    ("  VPN",               "vpn"),
    ("  Network Monitor",   "monitor"),
    ("  Logs & Reports",    "logs"),
    ("  Settings",          "settings"),
]

SECTION_SEPARATORS = {
    0: "OVERVIEW",
    1: "SECURITY SERVICES",
    6: "CONNECTIVITY",
    7: "MONITORING",
    9: "SYSTEM",
}


class SidebarLabel(QListWidgetItem):
    pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AegisGuard - Network Security")
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)
        self._build_ui()
        self._build_status_bar()
        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._update_status)
        self._status_timer.start(5000)
        self._update_status()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ───────────────────────────────────────────────────────────
        sidebar_container = QFrame()
        sidebar_container.setFixedWidth(220)
        sidebar_container.setStyleSheet("background-color: #161b22; border-right: 1px solid #30363d;")
        sidebar_layout = QVBoxLayout(sidebar_container)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        # Logo area
        logo_frame = QFrame()
        logo_frame.setFixedHeight(64)
        logo_frame.setStyleSheet("background-color: #0d1117; border-bottom: 1px solid #30363d;")
        logo_layout = QHBoxLayout(logo_frame)
        logo_layout.setContentsMargins(16, 8, 16, 8)

        shield = QLabel("🛡")
        shield.setStyleSheet("font-size: 24px;")
        logo_text = QLabel("AegisGuard")
        logo_text.setStyleSheet("font-size: 16px; font-weight: bold; color: #c0392b; letter-spacing: 1px;")
        logo_layout.addWidget(shield)
        logo_layout.addWidget(logo_text)
        logo_layout.addStretch()
        sidebar_layout.addWidget(logo_frame)

        # Navigation list
        self.nav = QListWidget()
        self.nav.setObjectName("sidebar")
        self.nav.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        for i, (label, key) in enumerate(NAV_ITEMS):
            if i in SECTION_SEPARATORS:
                sep = QListWidgetItem(SECTION_SEPARATORS[i])
                sep.setFlags(Qt.ItemFlag.NoItemFlags)
                sep.setForeground(QColor("#444d56"))
                sep.setSizeHint(QSize(0, 28))
                font = sep.font()
                font.setPointSize(9)
                font.setBold(True)
                sep.setFont(font)
                self.nav.addItem(sep)
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setSizeHint(QSize(0, 44))
            self.nav.addItem(item)

        self.nav.currentItemChanged.connect(self._on_nav_change)
        sidebar_layout.addWidget(self.nav)

        # VPN status indicator at bottom of sidebar
        self.vpn_status_label = QLabel("  VPN: Not Connected")
        self.vpn_status_label.setStyleSheet("color: #8b949e; font-size: 11px; padding: 8px 16px;")
        sidebar_layout.addWidget(self.vpn_status_label)

        self.fw_status_label = QLabel("  Firewall: Active")
        self.fw_status_label.setStyleSheet("color: #27ae60; font-size: 11px; padding: 4px 16px 8px 16px;")
        sidebar_layout.addWidget(self.fw_status_label)

        root.addWidget(sidebar_container)

        # ── Content area ──────────────────────────────────────────────────────
        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background-color: #1e2329;")

        self._panels = {
            "dashboard": DashboardPanel(),
            "firewall": FirewallPanel(),
            "appcontrol": AppControlPanel(),
            "webfilter": WebFilterPanel(),
            "ips": IPSPanel(),
            "blocked": BlockedSitesPanel(),
            "vpn": VPNPanel(),
            "monitor": MonitorPanel(),
            "logs": LogsPanel(),
            "settings": SettingsPanel(),
        }
        for panel in self._panels.values():
            self.stack.addWidget(panel)

        root.addWidget(self.stack)

        # Select first real item
        for i in range(self.nav.count()):
            item = self.nav.item(i)
            if item and item.data(Qt.ItemDataRole.UserRole):
                self.nav.setCurrentItem(item)
                break

    def _build_status_bar(self):
        sb = self.statusBar()
        self.sb_conn_label = QLabel("Connections: 0")
        self.sb_blocked_label = QLabel("Blocked Today: 0")
        self.sb_threats_label = QLabel("Threats: 0")
        self.sb_version = QLabel("AegisGuard v1.0.0")
        for lbl in (self.sb_conn_label, self.sb_blocked_label,
                    self.sb_threats_label, self.sb_version):
            sb.addWidget(lbl)
            sep = QLabel(" | ")
            sep.setStyleSheet("color: #30363d;")
            sb.addWidget(sep)

    def _on_nav_change(self, current, previous):
        if not current:
            return
        key = current.data(Qt.ItemDataRole.UserRole)
        if key and key in self._panels:
            self.stack.setCurrentWidget(self._panels[key])

    def _update_status(self):
        try:
            import psutil
            conns = psutil.net_connections(kind="inet")
            self.sb_conn_label.setText(f"Connections: {len(conns)}")
        except Exception:
            pass

        try:
            stats = database.get_log_stats()
            self.sb_blocked_label.setText(f"Blocked Today: {stats['today']:,}")
        except Exception:
            pass

        try:
            alerts = ips.get_alerts(1000)
            count = len(alerts)
            self.sb_threats_label.setText(f"Threats: {count}")
            if count > 0:
                self.sb_threats_label.setStyleSheet("color: #e67e22;")
            else:
                self.sb_threats_label.setStyleSheet("")
        except Exception:
            pass

        try:
            from core import vpn_manager
            statuses = vpn_manager.get_all_statuses()
            connected = [s for s in statuses.values() if s.get("status") == "Connected"]
            if connected:
                self.vpn_status_label.setText(f"  VPN: {len(connected)} Connected")
                self.vpn_status_label.setStyleSheet("color: #27ae60; font-size: 11px; padding: 8px 16px;")
            else:
                self.vpn_status_label.setText("  VPN: Not Connected")
                self.vpn_status_label.setStyleSheet("color: #8b949e; font-size: 11px; padding: 8px 16px;")
        except Exception:
            pass
