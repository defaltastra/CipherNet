"""
CipherNet Persistent Status Bar Widget
Displays active view name, IDS simulation state, total alerts,
and live bandwidth transfer rates with modern cybersecurity styling.
"""

from __future__ import annotations
from typing import Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QWidget,
)


class StatusBar(QFrame):
    """
    Bottom persistent telemetry bar for CipherNet.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(30)
        self.setStyleSheet(
            "QFrame { background-color: #0B0C0E; border-top: 1px solid #1E222B; font-size: 11px; }"
        )

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 0, 18, 0)
        layout.setSpacing(20)

        # Active view label with glowing marker
        view_box = QHBoxLayout()
        view_box.setSpacing(6)
        dot = QLabel("◈")
        dot.setStyleSheet("color: #FF70A6; font-size: 11px;")
        self.view_label = QLabel("VIEW: OVERVIEW")
        self.view_label.setStyleSheet("color: #FF70A6; font-weight: 800; letter-spacing: 0.5px;")
        view_box.addWidget(dot)
        view_box.addWidget(self.view_label)
        layout.addLayout(view_box)

        layout.addWidget(self._create_separator())

        # IDS state badge
        self.ids_label = QLabel("IDS ENGINE: IDLE")
        self.ids_label.setStyleSheet("color: #FABD2F; font-weight: 700;")
        layout.addWidget(self.ids_label)

        layout.addWidget(self._create_separator())

        # Alerts count
        self.alerts_label = QLabel("ALERTS: 0")
        self.alerts_label.setStyleSheet("color: #9CA3AF; font-weight: 600;")
        layout.addWidget(self.alerts_label)

        layout.addStretch()

        # Bandwidth speeds
        self.rate_label = QLabel("↓ 0.0 B/s   ↑ 0.0 B/s")
        self.rate_label.setStyleSheet("color: #4ECCA3; font-weight: 700; font-family: monospace;")
        layout.addWidget(self.rate_label)

        layout.addWidget(self._create_separator())

        # System health indicator
        sys_status = QLabel("● SYSTEM NOMINAL")
        sys_status.setStyleSheet("color: #4ECCA3; font-weight: 800; letter-spacing: 0.5px;")
        layout.addWidget(sys_status)

    def _create_separator(self) -> QLabel:
        sep = QLabel("│")
        sep.setStyleSheet("color: #1E222B; font-weight: bold;")
        return sep

    def update_telemetry(
        self,
        active_view: str,
        ids_status: str,
        total_alerts: int,
        rx_rate_str: str = "0.0 B/s",
        tx_rate_str: str = "0.0 B/s",
    ) -> None:
        self.view_label.setText(f"VIEW: {active_view.upper()}")

        if ids_status.upper() == "RUNNING":
            self.ids_label.setText("IDS ENGINE: ● ARMED & LOGGING")
            self.ids_label.setStyleSheet("color: #FF70A6; font-weight: 800;")
        else:
            self.ids_label.setText("IDS ENGINE: ○ STANDBY")
            self.ids_label.setStyleSheet("color: #FABD2F; font-weight: 700;")

        self.alerts_label.setText(f"ALERTS: {total_alerts}")
        self.rate_label.setText(f"↓ {rx_rate_str}   ↑ {tx_rate_str}")
