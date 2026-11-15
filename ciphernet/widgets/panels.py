"""
CipherNet Custom Qt Widgets and Visual Panels
Provides modern KPI cards, PyQtGraph traffic charts, animated cyber radar,
and cryptographic entropy visualizers for the PySide6 dashboard.
"""

from __future__ import annotations
import math
import random
import time
from typing import List, Optional
import pyqtgraph as pg
from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import (
    QBrush,
    QColor,
    QConicalGradient,
    QFont,
    QLinearGradient,
    QPainter,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


class StatCard(QFrame):
    """
    Modern KPI Metric Card with clean borders, title, large value,
    and descriptive secondary telemetry.
    """

    def __init__(
        self,
        title: str,
        value: str = "---",
        subtext: str = "",
        icon: str = "⚡",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setProperty("class", "stat-card")
        self.setObjectName("stat-card")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(6)

        # Header row with title and icon
        header_row = QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)

        self.title_label = QLabel(title.upper())
        self.title_label.setProperty("class", "stat-card-title")
        self.title_label.setStyleSheet("color: #9CA3AF; font-size: 11px; font-weight: 800; letter-spacing: 1.2px;")
        header_row.addWidget(self.title_label)
        header_row.addStretch()

        self.icon_label = QLabel(icon)
        self.icon_label.setStyleSheet("font-size: 14px; opacity: 0.8;")
        header_row.addWidget(self.icon_label)
        layout.addLayout(header_row)

        # Main numeric value
        self.value_label = QLabel(value)
        self.value_label.setProperty("class", "stat-card-value")
        self.value_label.setStyleSheet("color: #FFFFFF; font-size: 22px; font-weight: 900; margin: 2px 0px; letter-spacing: -0.5px;")
        layout.addWidget(self.value_label)

        # Subtext / context
        self.subtext_label = QLabel(subtext)
        self.subtext_label.setProperty("class", "stat-card-subtext")
        self.subtext_label.setStyleSheet("color: #6B7280; font-size: 11px; font-weight: 500;")
        layout.addWidget(self.subtext_label)
        layout.addStretch()

    def update_card(self, value: str, subtext: Optional[str] = None) -> None:
        self.value_label.setText(value)
        if subtext is not None:
            self.subtext_label.setText(subtext)


class SectionHeader(QWidget):
    """
    Sleek section title with descriptive subtitle and accent indicator.
    """

    def __init__(
        self,
        title: str,
        subtitle: str = "",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(2)

        title_layout = QHBoxLayout()
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(10)

        # Accent marker
        self.accent = QFrame()
        self.accent.setFixedSize(3, 16)
        self.accent.setStyleSheet("background-color: #FF70A6; border-radius: 1px;")
        title_layout.addWidget(self.accent)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: #FFFFFF; font-size: 14px; font-weight: 800; letter-spacing: 0.5px;")
        title_layout.addWidget(self.title_label)
        title_layout.addStretch()

        layout.addLayout(title_layout)

        if subtitle:
            self.subtitle_label = QLabel(subtitle)
            self.subtitle_label.setStyleSheet("color: #9CA3AF; font-size: 11px; margin-left: 13px;")
            layout.addWidget(self.subtitle_label)


class TrafficChart(pg.PlotWidget):
    """
    Hardware-accelerated PyQtGraph Network Telemetry Chart.
    Plots real-time ingress (Rx) and egress (Tx) bandwidth curves with
    anti-aliasing, subtle grid lines, and dynamic theme palette support.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent=parent)
        self.setMouseEnabled(x=False, y=False)
        self.hideButtons()
        self.current_theme = "charcoal-rose"

        self.apply_theme_colors("charcoal-rose")

    def apply_theme_colors(self, theme_name: str) -> None:
        """Dynamically reconfigures chart colors when theme is changed."""
        self.current_theme = theme_name
        self.clear()

        if theme_name == "gruvbox-dark":
            bg_color = "#282828"
            grid_color = "#3C3836"
            text_color = "#A89984"
            rx_color = "#FE8019"      # Orange
            rx_fill = (254, 128, 25, 30)
            tx_color = "#B8BB26"      # Forest Green
            tx_fill = (184, 187, 38, 20)
        elif theme_name == "cyber-neon":
            bg_color = "#130C22"
            grid_color = "#2C1844"
            text_color = "#A79BB8"
            rx_color = "#FF007F"      # Neon Pink
            rx_fill = (255, 0, 127, 35)
            tx_color = "#00F5D4"      # Neon Cyan
            tx_fill = (0, 245, 212, 20)
        else:  # charcoal-rose default
            bg_color = "#12141A"
            grid_color = "#1E232E"
            text_color = "#9CA3AF"
            rx_color = "#FF70A6"      # Rose Accent
            rx_fill = (255, 112, 166, 35)
            tx_color = "#4ECCA3"      # Emerald / Cyan
            tx_fill = (78, 204, 163, 20)

        self.setBackground(bg_color)
        self.showGrid(x=True, y=True, alpha=0.18)

        axis_pen = pg.mkPen(color=grid_color, width=1)
        self.getAxis("left").setPen(axis_pen)
        self.getAxis("bottom").setPen(axis_pen)
        self.getAxis("left").setTextPen(pg.mkColor(text_color))
        self.getAxis("bottom").setTextPen(pg.mkColor(text_color))

        # Setup curves
        self.rx_pen = pg.mkPen(color=rx_color, width=2.5)
        self.rx_brush = pg.mkBrush(*rx_fill)
        self.rx_curve = self.plot(
            name="Rx (Download)",
            pen=self.rx_pen,
            fillLevel=0,
            fillBrush=self.rx_brush,
        )

        self.tx_pen = pg.mkPen(color=tx_color, width=2.0, style=Qt.DashLine)
        self.tx_brush = pg.mkBrush(*tx_fill)
        self.tx_curve = self.plot(
            name="Tx (Upload)",
            pen=self.tx_pen,
            fillLevel=0,
            fillBrush=self.tx_brush,
        )

    def update_data(self, rx_history: List[float], tx_history: List[float]) -> None:
        if not rx_history:
            rx_history = [0.0] * 30
        if not tx_history:
            tx_history = [0.0] * 30

        rx_kb = [v / 1024.0 for v in rx_history]
        tx_kb = [v / 1024.0 for v in tx_history]

        self.rx_curve.setData(rx_kb)
        self.tx_curve.setData(tx_kb)


class CyberRadarWidget(QWidget):
    """
    High-tech Cyber Radar & Threat Severity Meter.
    Renders rotating sweep needle, concentric range rings, and threat blips.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(180, 180)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.angle: float = 0.0
        self.is_active: bool = False
        self.threat_score: int = 20
        self.blips: List[dict] = []
        self.theme_accent = "#FF70A6"
        self.theme_bg = "#0B0C0E"

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_tick)
        self._timer.start(50)  # 20 FPS

    def apply_theme_colors(self, theme_name: str) -> None:
        if theme_name == "gruvbox-dark":
            self.theme_accent = "#FE8019"
            self.theme_bg = "#1D2021"
        elif theme_name == "cyber-neon":
            self.theme_accent = "#FF007F"
            self.theme_bg = "#0A0612"
        else:
            self.theme_accent = "#FF70A6"
            self.theme_bg = "#0B0C0E"
        self.update()

    def set_active(self, active: bool, threat_score: int = 20) -> None:
        self.is_active = active
        self.threat_score = threat_score
        self.update()

    def add_blip(self) -> None:
        """Adds a threat contact blip on the radar sweep."""
        dist = random.uniform(0.2, 0.85)
        angle = random.uniform(0, 360)
        self.blips.append({
            "dist": dist,
            "angle": angle,
            "life": 1.0,
            "color": self.theme_accent,
        })

    def _on_tick(self) -> None:
        if self.is_active:
            self.angle = (self.angle + 3.2) % 360.0
            if random.random() < 0.08:
                self.add_blip()

        for b in self.blips:
            b["life"] -= 0.02
        self.blips = [b for b in self.blips if b["life"] > 0]

        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        size = min(w, h) - 16
        center_x = w / 2.0
        center_y = h / 2.0
        radius = size / 2.0

        if radius <= 10:
            return

        # Background circular fill
        painter.setBrush(QBrush(QColor(self.theme_bg)))
        painter.setPen(QPen(QColor(38, 42, 52), 1.5))
        painter.drawEllipse(QPointF(center_x, center_y), radius, radius)

        # Concentric range rings
        ring_pen = QPen(QColor(38, 42, 52), 1, Qt.DashLine)
        painter.setBrush(Qt.NoBrush)
        painter.setPen(ring_pen)
        painter.drawEllipse(QPointF(center_x, center_y), radius * 0.33, radius * 0.33)
        painter.drawEllipse(QPointF(center_x, center_y), radius * 0.66, radius * 0.66)

        # Crosshairs
        painter.setPen(QPen(QColor(38, 42, 52), 1))
        painter.drawLine(int(center_x - radius), int(center_y), int(center_x + radius), int(center_y))
        painter.drawLine(int(center_x), int(center_y - radius), int(center_x), int(center_y + radius))

        # Sweep Beam (Conical gradient when active)
        if self.is_active:
            gradient = QConicalGradient(center_x, center_y, -self.angle)
            accent_c = QColor(self.theme_accent)
            gradient.setColorAt(0.0, QColor(accent_c.red(), accent_c.green(), accent_c.blue(), 120))
            gradient.setColorAt(0.12, QColor(accent_c.red(), accent_c.green(), accent_c.blue(), 25))
            gradient.setColorAt(0.25, QColor(0, 0, 0, 0))
            gradient.setColorAt(1.0, QColor(0, 0, 0, 0))

            painter.setBrush(QBrush(gradient))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPointF(center_x, center_y), radius, radius)

            # Sweep needle
            rad = math.radians(self.angle)
            needle_x = center_x + radius * math.cos(rad)
            needle_y = center_y + radius * math.sin(rad)
            painter.setPen(QPen(accent_c, 2))
            painter.drawLine(QPointF(center_x, center_y), QPointF(needle_x, needle_y))

        # Render threat blips
        for b in self.blips:
            b_rad = math.radians(b["angle"])
            bx = center_x + radius * b["dist"] * math.cos(b_rad)
            by = center_y + radius * b["dist"] * math.sin(b_rad)
            alpha = int(b["life"] * 255)
            c = QColor(b["color"])
            c.setAlpha(alpha)
            painter.setBrush(QBrush(c))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPointF(bx, by), 4, 4)

        # Center core marker
        core_color = QColor(self.theme_accent) if self.is_active else QColor("#6B7280")
        painter.setBrush(QBrush(core_color))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(center_x, center_y), 4, 4)

        # Status text at bottom
        painter.setPen(QColor("#9CA3AF"))
        painter.setFont(QFont("Arial", 9, QFont.Bold))
        status_str = f"RADAR: {'ACTIVE' if self.is_active else 'STANDBY'}  |  THREAT: {self.threat_score}%"
        painter.drawText(
            QRectF(center_x - radius, center_y + radius - 20, radius * 2, 20),
            Qt.AlignCenter,
            status_str,
        )


class CryptoEntropyWidget(QFrame):
    """
    Live Cryptographic Entropy Streamer.
    Displays dynamic hex blocks and pool metrics.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setProperty("class", "panel-card")
        self.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 8px; padding: 10px; }"
        )

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(16)

        # Label & Metrics
        meta_layout = QVBoxLayout()
        meta_layout.setSpacing(2)
        title = QLabel("CRYPTOGRAPHIC PSEUDO-RANDOM ENTROPY POOL")
        title.setStyleSheet("color: #FF70A6; font-size: 11px; font-weight: 800; letter-spacing: 1.2px;")
        self.status_label = QLabel("Source: os.urandom (CSPRNG) | Pool Health: Nominal (256-bit Entropy)")
        self.status_label.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        meta_layout.addWidget(title)
        meta_layout.addWidget(self.status_label)

        # Stream text display
        self.stream_label = QLabel()
        self.stream_label.setStyleSheet(
            "color: #4ECCA3; font-family: monospace; font-size: 12px; font-weight: 700; background: #0E1015; padding: 6px 12px; border-radius: 6px; border: 1px solid #1E232E;"
        )
        self.stream_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        layout.addLayout(meta_layout)
        layout.addStretch()
        layout.addWidget(self.stream_label)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.advance_cycle)
        self._timer.start(1000)
        self.advance_cycle()

    def advance_cycle(self) -> None:
        """Generates fresh hex entropy stream snippet."""
        import os
        hex_block = os.urandom(16).hex().upper()
        formatted = " ".join([hex_block[i:i+4] for i in range(0, len(hex_block), 4)])
        self.stream_label.setText(f"[ {formatted} ]")
