"""
CipherNet Left Persistent Navigation Sidebar Widget
Provides modern, minimalist navigation buttons with subtle rose accents,
glowing active-tab indicator, and hotkey hints.
"""

from __future__ import annotations
from typing import Dict, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


NAV_ITEMS = [
    ("tab-overview", "Overview", "📊", "1"),
    ("tab-network", "Network Monitor", "🌐", "2"),
    ("tab-ids", "Intrusion Detection", "🛡️", "3"),
    ("tab-crypto", "Cryptography Lab", "🔐", "4"),
    ("tab-logs", "Security Logs", "📜", "5"),
    ("tab-settings", "Settings", "⚙️", "6"),
    ("tab-creators", "Creators & About", "👥", "7"),
]


class Sidebar(QFrame):
    """
    Persistent left sidebar for module navigation with high-contrast active tabs.
    """
    tab_selected = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(240)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header / Brand
        header = QFrame()
        header.setObjectName("sidebar-header")
        h_layout = QVBoxLayout(header)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(4)

        logo_row = QHBoxLayout()
        logo_row.setContentsMargins(0, 0, 0, 0)
        logo_row.setSpacing(10)

        logo_icon = QLabel("⚡")
        logo_icon.setObjectName("sidebar-logo-icon")
        logo_row.addWidget(logo_icon)

        title_col = QVBoxLayout()
        title_col.setSpacing(1)
        title = QLabel("CIPHERNET")
        title.setObjectName("sidebar-title")
        subtitle = QLabel("SECURITY DASHBOARD")
        subtitle.setObjectName("sidebar-subtitle")
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        logo_row.addLayout(title_col)
        logo_row.addStretch()

        h_layout.addLayout(logo_row)
        layout.addWidget(header)

        # Section label
        nav_label = QLabel("NAVIGATION")
        nav_label.setStyleSheet("color: #4B5563; font-size: 10px; font-weight: 800; letter-spacing: 1.5px; padding: 16px 18px 6px 18px;")
        layout.addWidget(nav_label)

        # Navigation Buttons
        nav_container = QWidget()
        nav_layout = QVBoxLayout(nav_container)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(2)

        self.button_group = QButtonGroup(self)
        self.button_group.setExclusive(True)
        self.buttons: Dict[str, QPushButton] = {}

        for tab_id, label, icon, hotkey in NAV_ITEMS:
            btn = QPushButton(f"  {icon}   {label}")
            btn.setCheckable(True)
            btn.setProperty("class", "nav-button")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda checked, tid=tab_id: self._on_btn_clicked(tid))
            self.button_group.addButton(btn)
            nav_layout.addWidget(btn)
            self.buttons[tab_id] = btn

        nav_layout.addStretch()
        layout.addWidget(nav_container, 1)

        # Footer info card
        footer = QFrame()
        footer.setObjectName("sidebar-footer")
        f_layout = QVBoxLayout(footer)
        f_layout.setContentsMargins(14, 12, 14, 14)
        f_layout.setSpacing(6)

        shield_row = QHBoxLayout()
        shield_dot = QLabel("●")
        shield_dot.setStyleSheet("color: #4ECCA3; font-size: 12px;")
        shield_text = QLabel("Shield Core Active")
        shield_text.setStyleSheet("color: #D1D5DB; font-size: 11px; font-weight: 700;")
        shield_row.addWidget(shield_dot)
        shield_row.addWidget(shield_text)
        shield_row.addStretch()
        f_layout.addLayout(shield_row)

        hint = QLabel("Shortcuts: [1-7] Tabs | [S] IDS | [?] Help")
        hint.setStyleSheet("color: #6B7280; font-size: 10px; font-weight: 500;")
        ver = QLabel("CipherNet 1.0.0 (PySide6)")
        ver.setStyleSheet("color: #9CA3AF; font-size: 10px; font-weight: 600;")

        f_layout.addWidget(hint)
        f_layout.addWidget(ver)
        layout.addWidget(footer)

        # Select first tab by default
        self.set_active("tab-overview")

    def _on_btn_clicked(self, tab_id: str) -> None:
        self.tab_selected.emit(tab_id)

    def set_active(self, tab_id: str) -> None:
        """Sets active highlighted navigation button."""
        if tab_id in self.buttons:
            self.buttons[tab_id].setChecked(True)
