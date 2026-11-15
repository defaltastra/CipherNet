"""
CipherNet Main Application Shell (PySide6)
Standalone desktop cybersecurity application built with Qt for Python (PySide6).
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, Optional
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ciphernet.modules.creators import CreatorsView
from ciphernet.modules.cryptography import CryptographyView
from ciphernet.modules.intrusion import IntrusionDetectionView
from ciphernet.modules.logs import SecurityLogsView
from ciphernet.modules.network import NetworkMonitorView
from ciphernet.modules.overview import OverviewView
from ciphernet.modules.settings import SettingsView
from ciphernet.services.crypto_service import CryptoService
from ciphernet.services.detection_service import DetectionService
from ciphernet.services.event_service import EventService
from ciphernet.services.network_service import NetworkService
from ciphernet.services.settings_service import SettingsService
from ciphernet.widgets.navigation import Sidebar
from ciphernet.widgets.status_bar import StatusBar


QSS_DIR = Path(__file__).resolve().parent / "styles"


class HelpDialog(QDialog):
    """Modal dialog displaying keyboard navigation and application shortcuts."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("CipherNet – Keyboard Shortcuts")
        self.setFixedSize(480, 420)
        self.setStyleSheet("""
            QDialog { background-color: #18191E; border: 1px solid #FF70A6; border-radius: 8px; }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        title = QLabel("⚡ CIPHERNET NAVIGATION SHORTCUTS")
        title.setStyleSheet("color: #FF70A6; font-size: 15px; font-weight: 800; letter-spacing: 1px;")
        layout.addWidget(title)

        shortcuts = [
            ("1", "Switch to Overview Dashboard"),
            ("2", "Switch to Network Monitor (Sockets & NICs)"),
            ("3", "Switch to Intrusion Detection Simulator"),
            ("4", "Switch to Cryptography Lab (AES, RSA, Hash)"),
            ("5", "Switch to Security Logs & Forensic Ledger"),
            ("6", "Switch to Settings & Preferences"),
            ("7", "Switch to Creators Section (Ilham & Oussama)"),
            ("S", "Toggle IDS Simulation Engine On / Off"),
            ("R", "Force Refresh Active Telemetry"),
            ("? / F1", "Open This Help Menu"),
            ("Ctrl+Q", "Exit CipherNet Application"),
        ]

        text_html = "<div style='line-height: 1.8; font-size: 12px;'>"
        for key, desc in shortcuts:
            text_html += (
                f"<span style='color: #FF70A6; font-weight: bold; font-family: monospace;'>[{key:<6}]</span> "
                f"&nbsp;&nbsp;<span style='color: #F3F4F6;'>{desc}</span><br>"
            )
        text_html += "</div>"

        label = QLabel(text_html)
        label.setTextFormat(Qt.RichText)
        layout.addWidget(label)
        layout.addStretch()

        btn_close = QPushButton("Close (Esc)")
        btn_close.setProperty("class", "btn-primary")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)


class CipherNetApp(QMainWindow):
    """
    Central Standalone PySide6 Desktop Application for CipherNet.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        super().__init__()
        self.setWindowTitle("CipherNet – Network Security & Cryptography Dashboard")
        self.resize(1260, 840)
        self.setMinimumSize(980, 680)

        # 1. Initialize core non-UI services
        self.settings_service = SettingsService(config_path)
        self.event_service = EventService(
            max_capacity=int(self.settings_service.get("max_logs", 1000))
        )
        self.network_service = NetworkService(
            resolve_hostnames=self.settings_service.get("resolve_hostnames", False),
            show_loopback=self.settings_service.get("show_loopback", False),
        )
        self.detection_service = DetectionService(
            event_service=self.event_service,
            intensity=self.settings_service.get("ids_intensity", "Medium"),
        )
        self.crypto_service = CryptoService(event_service=self.event_service)

        self.current_tab = "tab-overview"
        self._timer: Optional[QTimer] = None

        # 2. Build UI layout
        self._build_ui()

        # 3. Setup Global Hotkeys
        self._setup_shortcuts()

        # 4. Apply initial theme and start periodic telemetry
        self.apply_theme()
        self.setup_telemetry_timer()

        if self.settings_service.get("ids_auto_start", False):
            self.detection_service.start_simulation()

        self.update_status_bar()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Left Persistent Sidebar
        self.sidebar = Sidebar()
        self.sidebar.tab_selected.connect(self.switch_tab)
        main_layout.addWidget(self.sidebar)

        # Right Content Area (StackedWidget + StatusBar)
        content_container = QWidget()
        c_layout = QVBoxLayout(content_container)
        c_layout.setContentsMargins(0, 0, 0, 0)
        c_layout.setSpacing(0)

        self.stack = QStackedWidget()
        self.views: Dict[str, QWidget] = {}

        # Instantiate 6 Modules + Creators
        self.view_overview = OverviewView(self.network_service, self.event_service, self.detection_service)
        self.view_network = NetworkMonitorView(self.network_service)
        self.view_ids = IntrusionDetectionView(self.detection_service, self.event_service)
        self.view_crypto = CryptographyView(self.crypto_service)
        self.view_logs = SecurityLogsView(self.event_service)
        self.view_settings = SettingsView(self.settings_service)
        self.view_creators = CreatorsView()

        self._add_view("tab-overview", self.view_overview)
        self._add_view("tab-network", self.view_network)
        self._add_view("tab-ids", self.view_ids)
        self._add_view("tab-crypto", self.view_crypto)
        self._add_view("tab-logs", self.view_logs)
        self._add_view("tab-settings", self.view_settings)
        self._add_view("tab-creators", self.view_creators)

        # Connect immediate theme change signal
        self.view_settings.theme_changed.connect(self.set_theme)

        c_layout.addWidget(self.stack, 1)

        # Bottom Status Bar
        self.status_bar_widget = StatusBar()
        c_layout.addWidget(self.status_bar_widget)

        main_layout.addWidget(content_container, 1)

    def _add_view(self, tab_id: str, view: QWidget) -> None:
        self.views[tab_id] = view
        self.stack.addWidget(view)

    def _setup_shortcuts(self) -> None:
        # Tab shortcuts 1-7
        tabs = [
            ("1", "tab-overview"),
            ("2", "tab-network"),
            ("3", "tab-ids"),
            ("4", "tab-crypto"),
            ("5", "tab-logs"),
            ("6", "tab-settings"),
            ("7", "tab-creators"),
        ]
        for key, tab_id in tabs:
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.activated.connect(lambda tid=tab_id: self.switch_tab(tid))

        # Action shortcuts: S (toggle IDS), R (refresh), F1 / ? (help), Ctrl+Q (quit)
        sc_s = QShortcut(QKeySequence("s"), self)
        sc_s.activated.connect(self.action_toggle_ids)

        sc_r = QShortcut(QKeySequence("r"), self)
        sc_r.activated.connect(self.action_refresh_active)

        sc_help1 = QShortcut(QKeySequence("?"), self)
        sc_help1.activated.connect(self.action_show_help)

        sc_help2 = QShortcut(QKeySequence(Qt.Key_F1), self)
        sc_help2.activated.connect(self.action_show_help)

        sc_quit = QShortcut(QKeySequence("Ctrl+Q"), self)
        sc_quit.activated.connect(self.close)

    def set_theme(self, theme_name: str) -> None:
        """Immediately sets and applies the visual theme."""
        self.settings_service.set("theme", theme_name, auto_save=True)
        self.apply_theme()

    def apply_theme(self) -> None:
        """Loads and applies the QSS stylesheet for the configured visual theme immediately."""
        from PySide6.QtWidgets import QApplication

        theme_name = self.settings_service.get("theme", "charcoal-rose")
        if theme_name == "gruvbox-dark":
            qss_file = QSS_DIR / "gruvbox_dark.qss"
        elif theme_name == "cyber-neon":
            qss_file = QSS_DIR / "cyber_neon.qss"
        else:
            qss_file = QSS_DIR / "cyber_charcoal.qss"

        if not qss_file.exists():
            qss_file = QSS_DIR / "cyber_charcoal.qss"

        if qss_file.exists():
            with open(qss_file, "r", encoding="utf-8") as f:
                stylesheet = f.read()
                app_inst = QApplication.instance()
                if app_inst:
                    app_inst.setStyleSheet(stylesheet)
                else:
                    self.setStyleSheet(stylesheet)

        # Update dynamic chart and radar palettes to match theme immediately
        if hasattr(self, "view_overview") and hasattr(self.view_overview, "traffic_chart"):
            self.view_overview.traffic_chart.apply_theme_colors(theme_name)
        if hasattr(self, "view_ids") and hasattr(self.view_ids, "radar"):
            self.view_ids.radar.apply_theme_colors(theme_name)
        self.update_status_bar()

    def setup_telemetry_timer(self) -> None:
        """Configures recurring periodic telemetry tick timer."""
        interval_secs = float(self.settings_service.get("refresh_rate", 2.0))
        if self._timer:
            self._timer.stop()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.on_telemetry_tick)
        self._timer.start(int(interval_secs * 1000))

    def on_telemetry_tick(self) -> None:
        """Periodic background tick updating telemetry and active views."""
        self.network_service.update_traffic_rates()

        # Update active view
        if self.current_tab == "tab-overview":
            self.view_overview.refresh_data()
        elif self.current_tab == "tab-network":
            self.view_network.update_telemetry_box()
        elif self.current_tab == "tab-ids":
            self.view_ids.update_status_badge()
            self.view_ids.refresh_timeline()
        elif self.current_tab == "tab-crypto":
            self.view_crypto.refresh_entropy()

        self.update_status_bar()

    def update_status_bar(self) -> None:
        tab_names = {
            "tab-overview": "Overview",
            "tab-network": "Network Monitor",
            "tab-ids": "Intrusion Simulator",
            "tab-crypto": "Cryptography Lab",
            "tab-logs": "Security Logs",
            "tab-settings": "Settings",
            "tab-creators": "Creators & About",
        }
        view_label = tab_names.get(self.current_tab, "Overview")
        ids_status = "RUNNING" if self.detection_service.is_running else "IDLE"
        total_alerts = len(self.event_service.get_events(limit=1000))

        rx_rate_str = self.network_service.format_rate(self.network_service.rx_rate)
        tx_rate_str = self.network_service.format_rate(self.network_service.tx_rate)

        self.status_bar_widget.update_telemetry(
            active_view=view_label,
            ids_status=ids_status,
            total_alerts=total_alerts,
            rx_rate_str=rx_rate_str,
            tx_rate_str=tx_rate_str,
        )

    def switch_tab(self, tab_id: str) -> None:
        """Switches active view in the QStackedWidget and updates sidebar selection."""
        if tab_id in self.views:
            self.current_tab = tab_id
            widget = self.views[tab_id]
            self.stack.setCurrentWidget(widget)
            self.sidebar.set_active(tab_id)

            # Immediate refresh of newly selected view
            if tab_id == "tab-overview":
                self.view_overview.refresh_data()
            elif tab_id == "tab-network":
                self.view_network.refresh_connections()
            elif tab_id == "tab-ids":
                self.view_ids.refresh_rules_table()
                self.view_ids.refresh_timeline()
            elif tab_id == "tab-logs":
                self.view_logs.refresh_logs()

            self.update_status_bar()

    def apply_settings(self) -> None:
        """Applies updated configuration options saved from Settings view."""
        self.apply_theme()
        self.network_service.resolve_hostnames = self.settings_service.get("resolve_hostnames", False)
        self.network_service.show_loopback = self.settings_service.get("show_loopback", False)
        self.detection_service.intensity = self.settings_service.get("ids_intensity", "Medium")
        self.setup_telemetry_timer()
        self.update_status_bar()

    def action_toggle_ids(self) -> None:
        """Hotkey 's' to toggle IDS engine."""
        if self.detection_service.is_running:
            self.detection_service.stop_simulation()
        else:
            self.detection_service.start_simulation()
        self.update_status_bar()

    def action_refresh_active(self) -> None:
        """Hotkey 'r' to force refresh current view."""
        self.switch_tab(self.current_tab)

    def action_show_help(self) -> None:
        """Hotkey '?' or F1 to open help dialog."""
        dlg = HelpDialog(self)
        dlg.exec()

    def closeEvent(self, event) -> None:
        """Clean shutdown of background services and timers on window close."""
        if self._timer:
            self._timer.stop()
        if self.detection_service.is_running:
            self.detection_service.stop_simulation()
        event.accept()
