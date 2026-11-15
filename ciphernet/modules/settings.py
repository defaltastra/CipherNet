"""
CipherNet Settings Module (PySide6)
Persistent application configuration management for UI themes, telemetry intervals,
network monitoring options, and IDS simulation controls.
Instantly applies theme changes when selected.
"""

from __future__ import annotations
from typing import Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ciphernet.services.settings_service import SettingsService
from ciphernet.widgets.panels import SectionHeader


THEME_OPTIONS = [
    ("Dark Charcoal & Rose (Default Cybersecurity)", "charcoal-rose"),
    ("Cyber Neon Magenta (Synthwave Cyberpunk)", "cyber-neon"),
    ("Gruvbox Dark Classic (Warm Retro Hacker)", "gruvbox-dark"),
]

INTERVAL_OPTIONS = [
    ("1.0 Second (Realtime Fast)", 1.0),
    ("2.0 Seconds (Recommended)", 2.0),
    ("5.0 Seconds (Low Resource)", 5.0),
    ("10.0 Seconds (Conservative)", 10.0),
]

INTENSITY_OPTIONS = [
    ("Low Intensity (4-7s delay)", "Low"),
    ("Medium Intensity (2-3s delay)", "Medium"),
    ("Aggressive Intensity (0.5-1.5s delay)", "Aggressive"),
]


class SettingsView(QWidget):
    """
    Settings view for configuring application preferences and telemetry tuning.
    Applies visual theme changes immediately upon selection.
    """
    theme_changed = Signal(str)

    def __init__(self, settings_service: SettingsService, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.settings_service = settings_service

        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)

        # -------------------------------------------------------------
        # 1. Interface & Visual Theme (Immediate Live Preview)
        # -------------------------------------------------------------
        layout.addWidget(SectionHeader("Interface & Visual Theme", "Display Theme Applies Instantly Upon Selection"))

        theme_card = QFrame()
        theme_card.setProperty("class", "panel-card")
        theme_card.setStyleSheet("QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 18px; }")
        tc_layout = QHBoxLayout(theme_card)
        tc_layout.setSpacing(24)

        # Theme Column
        t_col = QVBoxLayout()
        t_col.setSpacing(8)
        lbl_theme = QLabel("Active Visual Theme (Live Preview):")
        lbl_theme.setStyleSheet("color: #FFFFFF; font-weight: 700; font-size: 13px;")
        t_col.addWidget(lbl_theme)

        self.combo_theme = QComboBox()
        for label, val in THEME_OPTIONS:
            self.combo_theme.addItem(label, val)
        current_theme = self.settings_service.get("theme", "charcoal-rose")
        idx_t = self.combo_theme.findData(current_theme)
        if idx_t >= 0:
            self.combo_theme.setCurrentIndex(idx_t)

        # Connect immediate theme change!
        self.combo_theme.currentIndexChanged.connect(self._on_theme_selection_changed)
        t_col.addWidget(self.combo_theme)

        tip_theme = QLabel("Switching theme transforms all windows, dialogs, charts, and tables immediately.")
        tip_theme.setStyleSheet("color: #6B7280; font-size: 11px;")
        t_col.addWidget(tip_theme)
        tc_layout.addLayout(t_col, 3)

        # Interval Column
        i_col = QVBoxLayout()
        i_col.setSpacing(8)
        lbl_interval = QLabel("Telemetry Refresh Rate:")
        lbl_interval.setStyleSheet("color: #FFFFFF; font-weight: 700; font-size: 13px;")
        i_col.addWidget(lbl_interval)

        self.combo_interval = QComboBox()
        for label, val in INTERVAL_OPTIONS:
            self.combo_interval.addItem(label, val)
        current_rate = float(self.settings_service.get("refresh_rate", 2.0))
        idx_r = self.combo_interval.findData(current_rate)
        if idx_r >= 0:
            self.combo_interval.setCurrentIndex(idx_r)
        i_col.addWidget(self.combo_interval)

        tip_rate = QLabel("Polling interval for background telemetry workers and charts.")
        tip_rate.setStyleSheet("color: #6B7280; font-size: 11px;")
        i_col.addWidget(tip_rate)
        tc_layout.addLayout(i_col, 2)

        layout.addWidget(theme_card)

        # -------------------------------------------------------------
        # 2. Network Monitoring Preferences
        # -------------------------------------------------------------
        layout.addWidget(SectionHeader("Network Monitoring Preferences", "Telemetry Resolution & Packet Capture Engine"))

        net_card = QFrame()
        net_card.setProperty("class", "panel-card")
        net_card.setStyleSheet("QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 18px; }")
        nc_layout = QVBoxLayout(net_card)
        nc_layout.setSpacing(14)

        self.chk_resolve_dns = QCheckBox("Resolve Remote Hostnames (Asynchronous reverse DNS lookups)")
        self.chk_resolve_dns.setChecked(self.settings_service.get("resolve_hostnames", False))
        nc_layout.addWidget(self.chk_resolve_dns)

        self.chk_show_loopback = QCheckBox("Display Loopback Adapters & Sockets (127.0.0.1 / localhost)")
        self.chk_show_loopback.setChecked(self.settings_service.get("show_loopback", False))
        nc_layout.addWidget(self.chk_show_loopback)

        self.chk_enable_scapy = QCheckBox("Enable Optional Scapy Packet Inspection Engine")
        self.chk_enable_scapy.setChecked(self.settings_service.get("enable_scapy", False))
        nc_layout.addWidget(self.chk_enable_scapy)

        tip_label = QLabel("Note: Scapy raw packet sniffing requires elevated (root/admin) operating system permissions.")
        tip_label.setStyleSheet("color: #FABD2F; font-size: 11px; margin-left: 28px;")
        nc_layout.addWidget(tip_label)

        layout.addWidget(net_card)

        # -------------------------------------------------------------
        # 3. Intrusion Detection Preferences
        # -------------------------------------------------------------
        layout.addWidget(SectionHeader("Intrusion Detection Simulation Preferences", "Attack Simulator Controls & Audit Capacity"))

        ids_card = QFrame()
        ids_card.setProperty("class", "panel-card")
        ids_card.setStyleSheet("QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 18px; }")
        ic_layout = QHBoxLayout(ids_card)
        ic_layout.setSpacing(24)

        # Left IDS Col
        ic_left = QVBoxLayout()
        ic_left.setSpacing(8)
        lbl_ids_rate = QLabel("Default Simulation Rate:")
        lbl_ids_rate.setStyleSheet("color: #FFFFFF; font-weight: 700; font-size: 13px;")
        ic_left.addWidget(lbl_ids_rate)

        self.combo_ids_intensity = QComboBox()
        for label, val in INTENSITY_OPTIONS:
            self.combo_ids_intensity.addItem(label, val)
        cur_intensity = self.settings_service.get("ids_intensity", "Medium")
        idx_i = self.combo_ids_intensity.findData(cur_intensity)
        if idx_i >= 0:
            self.combo_ids_intensity.setCurrentIndex(idx_i)
        ic_left.addWidget(self.combo_ids_intensity)
        ic_layout.addLayout(ic_left, 1)

        # Right IDS Col
        ic_right = QVBoxLayout()
        ic_right.setSpacing(8)
        self.chk_ids_autostart = QCheckBox("Auto-Start IDS Simulation on Application Launch")
        self.chk_ids_autostart.setChecked(self.settings_service.get("ids_auto_start", False))
        ic_right.addWidget(self.chk_ids_autostart)

        lbl_max_logs = QLabel("Max Audit Log Retention Capacity:")
        lbl_max_logs.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        ic_right.addWidget(lbl_max_logs)

        self.input_max_logs = QLineEdit(str(self.settings_service.get("max_logs", 1000)))
        ic_right.addWidget(self.input_max_logs)
        ic_layout.addLayout(ic_right, 1)

        layout.addWidget(ids_card)

        # -------------------------------------------------------------
        # 4. Actions & Persistence
        # -------------------------------------------------------------
        layout.addWidget(SectionHeader("Actions & Persistence", "Persist Configuration to config/settings.json"))

        btn_row = QHBoxLayout()
        btn_row.setSpacing(14)

        self.btn_save = QPushButton("💾 Save All Settings")
        self.btn_save.setProperty("class", "btn-success")
        self.btn_save.clicked.connect(self._on_save_settings)
        btn_row.addWidget(self.btn_save)

        self.btn_reset = QPushButton("↺ Reset to Defaults")
        self.btn_reset.setProperty("class", "btn-danger")
        self.btn_reset.clicked.connect(self._on_reset_settings)
        btn_row.addWidget(self.btn_reset)

        btn_row.addStretch()
        layout.addLayout(btn_row)
        layout.addStretch()

        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def _on_theme_selection_changed(self) -> None:
        """Triggered immediately when user selects a different theme in the dropdown."""
        new_theme = self.combo_theme.currentData()
        if new_theme:
            self.settings_service.set("theme", new_theme, auto_save=True)
            self.theme_changed.emit(new_theme)

            # Apply immediately to top-level window
            win = self.window()
            if hasattr(win, "apply_theme"):
                win.apply_theme()

    def _on_save_settings(self) -> None:
        theme = self.combo_theme.currentData()
        interval = float(self.combo_interval.currentData())
        resolve_dns = self.chk_resolve_dns.isChecked()
        show_lo = self.chk_show_loopback.isChecked()
        enable_scapy = self.chk_enable_scapy.isChecked()
        ids_intensity = self.combo_ids_intensity.currentData()
        ids_auto = self.chk_ids_autostart.isChecked()

        try:
            max_logs = int(self.input_max_logs.text().strip())
        except ValueError:
            max_logs = 1000

        self.settings_service.update({
            "theme": theme,
            "refresh_rate": interval,
            "resolve_hostnames": resolve_dns,
            "show_loopback": show_lo,
            "enable_scapy": enable_scapy,
            "ids_intensity": ids_intensity,
            "ids_auto_start": ids_auto,
            "max_logs": max_logs,
        })

        parent_window = self.window()
        if hasattr(parent_window, "apply_settings"):
            parent_window.apply_settings()

        QMessageBox.information(
            self,
            "Configuration Saved",
            "Settings have been successfully persisted to config/settings.json and applied.",
        )

    def _on_reset_settings(self) -> None:
        reply = QMessageBox.question(
            self,
            "Reset Settings",
            "Are you sure you want to restore factory default configuration?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.settings_service.reset_to_defaults()
            # Reload fields
            current_theme = self.settings_service.get("theme", "charcoal-rose")
            idx_t = self.combo_theme.findData(current_theme)
            if idx_t >= 0:
                self.combo_theme.setCurrentIndex(idx_t)

            self.chk_resolve_dns.setChecked(self.settings_service.get("resolve_hostnames", False))
            self.chk_show_loopback.setChecked(self.settings_service.get("show_loopback", False))
            self.chk_enable_scapy.setChecked(self.settings_service.get("enable_scapy", False))
            self.chk_ids_autostart.setChecked(self.settings_service.get("ids_auto_start", False))
            self.input_max_logs.setText(str(self.settings_service.get("max_logs", 1000)))

            parent_window = self.window()
            if hasattr(parent_window, "apply_settings"):
                parent_window.apply_settings()
            if hasattr(parent_window, "apply_theme"):
                parent_window.apply_theme()
