"""
CipherNet Overview Module (PySide6)
Displays system and network telemetry, KPI stat cards, dynamic PyQtGraph
traffic bandwidth chart, network interfaces table, and live security activity.
"""

from __future__ import annotations
from typing import Optional
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ciphernet.services.detection_service import DetectionService
from ciphernet.services.event_service import EventService
from ciphernet.services.network_service import NetworkService
from ciphernet.widgets.panels import SectionHeader, StatCard, TrafficChart


class OverviewView(QWidget):
    """
    Overview Dashboard displaying live system metrics, bandwidth charts,
    interface tables, and real-time security events.
    """

    def __init__(
        self,
        network_service: NetworkService,
        event_service: EventService,
        detection_service: DetectionService,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.network_service = network_service
        self.event_service = event_service
        self.detection_service = detection_service

        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)

        # -------------------------------------------------------------
        # 1. Top Header Banner
        # -------------------------------------------------------------
        banner = QHBoxLayout()
        banner.setContentsMargins(0, 0, 0, 0)

        header_col = QVBoxLayout()
        header_col.setSpacing(2)
        h_title = QLabel("SYSTEM OVERVIEW & TELEMETRY")
        h_title.setStyleSheet("color: #FFFFFF; font-size: 18px; font-weight: 900; letter-spacing: 0.5px;")
        h_sub = QLabel("Real-Time Interface Metrics, Bandwidth Rates & Active Threat Detection")
        h_sub.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        header_col.addWidget(h_title)
        header_col.addWidget(h_sub)
        banner.addLayout(header_col)
        banner.addStretch()

        # Operational status pill
        status_pill = QFrame()
        status_pill.setStyleSheet(
            "background-color: rgba(78, 204, 163, 0.12); border: 1px solid rgba(78, 204, 163, 0.4); "
            "border-radius: 16px; padding: 6px 14px;"
        )
        sp_layout = QHBoxLayout(status_pill)
        sp_layout.setContentsMargins(0, 0, 0, 0)
        sp_layout.setSpacing(6)
        dot = QLabel("●")
        dot.setStyleSheet("color: #4ECCA3; font-size: 11px;")
        txt = QLabel("TELEMETRY OPERATIONAL")
        txt.setStyleSheet("color: #4ECCA3; font-size: 11px; font-weight: 800; letter-spacing: 0.8px;")
        sp_layout.addWidget(dot)
        sp_layout.addWidget(txt)
        banner.addWidget(status_pill)

        layout.addLayout(banner)

        # -------------------------------------------------------------
        # 2. Top KPI Stat Cards (Grid of 4)
        # -------------------------------------------------------------
        kpi_grid = QGridLayout()
        kpi_grid.setSpacing(14)

        self.card_host = StatCard("System & Host IP", "Scanning...", "Interface: Detecting", icon="🖥️")
        self.card_traffic = StatCard("Network Throughput", "0.0 B/s", "Live Transfer Speed", icon="📶")
        self.card_conns = StatCard("Active Sockets", "0 Conns", "TCP: 0 | UDP: 0 | Listen: 0", icon="🔌")
        self.card_alerts = StatCard("Security Threats", "0 Alerts", "Critical: 0 | High: 0", icon="🛡️")

        kpi_grid.addWidget(self.card_host, 0, 0)
        kpi_grid.addWidget(self.card_traffic, 0, 1)
        kpi_grid.addWidget(self.card_conns, 0, 2)
        kpi_grid.addWidget(self.card_alerts, 0, 3)

        layout.addLayout(kpi_grid)

        # -------------------------------------------------------------
        # 3. Dynamic PyQtGraph Bandwidth Chart
        # -------------------------------------------------------------
        layout.addWidget(SectionHeader("Live Bandwidth Waveform", "Continuous Ingress (Rx) and Egress (Tx) Transfer Rates (KB/s)"))

        chart_card = QFrame()
        chart_card.setProperty("class", "panel-card")
        chart_card.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 8px; }"
        )
        chart_layout = QVBoxLayout(chart_card)
        chart_layout.setContentsMargins(8, 8, 8, 8)

        self.traffic_chart = TrafficChart()
        self.traffic_chart.setMinimumHeight(180)
        self.traffic_chart.setMaximumHeight(230)
        chart_layout.addWidget(self.traffic_chart)

        layout.addWidget(chart_card)

        # -------------------------------------------------------------
        # 4. Network Interfaces Table
        # -------------------------------------------------------------
        layout.addWidget(SectionHeader("Hardware Adapters & Routing", "Active Network Interface Controllers & Physical Links"))

        self.iface_table = QTableWidget()
        self.iface_table.setColumnCount(6)
        self.iface_table.setHorizontalHeaderLabels([
            "Interface", "State", "IPv4 Address", "Link Speed", "Packets (Rx / Tx)", "Errors & Drops"
        ])
        self.iface_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.iface_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.iface_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.iface_table.verticalHeader().setVisible(False)
        self.iface_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.iface_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.iface_table.setAlternatingRowColors(True)
        self.iface_table.setMinimumHeight(140)
        self.iface_table.setMaximumHeight(190)

        layout.addWidget(self.iface_table)

        # -------------------------------------------------------------
        # 5. Bottom Split: Recent Security Feed + Quick Actions
        # -------------------------------------------------------------
        bottom_layout = QHBoxLayout()
        bottom_layout.setSpacing(16)

        # Events Table Column
        events_col = QVBoxLayout()
        events_col.setSpacing(8)
        events_col.addWidget(SectionHeader("Security Activity Feed", "Real-Time Telemetry & IDS Attack Detections"))

        self.events_table = QTableWidget()
        self.events_table.setColumnCount(5)
        self.events_table.setHorizontalHeaderLabels([
            "Time (UTC)", "Severity", "Source Origin", "Threat / Signature", "Mode"
        ])
        self.events_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.events_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.events_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.events_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.events_table.verticalHeader().setVisible(False)
        self.events_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.events_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.events_table.setAlternatingRowColors(True)
        self.events_table.setMinimumHeight(170)

        events_col.addWidget(self.events_table)
        bottom_layout.addLayout(events_col, 3)

        # Quick Actions Panel
        actions_panel = QFrame()
        actions_panel.setProperty("class", "panel-card")
        actions_panel.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        actions_panel.setFixedWidth(250)
        a_layout = QVBoxLayout(actions_panel)
        a_layout.setContentsMargins(14, 14, 14, 14)
        a_layout.setSpacing(12)

        action_title = QLabel("QUICK ACTIONS")
        action_title.setStyleSheet("color: #FF70A6; font-size: 11px; font-weight: 800; letter-spacing: 1.2px;")
        a_layout.addWidget(action_title)

        self.btn_attack = QPushButton("⚡ Simulate Attack Burst")
        self.btn_attack.setProperty("class", "btn-danger")
        self.btn_attack.clicked.connect(self._on_quick_attack)
        a_layout.addWidget(self.btn_attack)

        self.btn_ids_toggle = QPushButton("🛡️ Toggle IDS Simulation")
        self.btn_ids_toggle.setProperty("class", "btn-warning")
        self.btn_ids_toggle.clicked.connect(self._on_quick_ids_toggle)
        a_layout.addWidget(self.btn_ids_toggle)

        self.btn_refresh = QPushButton("🔄 Refresh Telemetry")
        self.btn_refresh.setProperty("class", "btn-primary")
        self.btn_refresh.clicked.connect(self.refresh_data)
        a_layout.addWidget(self.btn_refresh)

        note = QLabel("Simulates controlled attack patterns against detection signatures without production impact.")
        note.setStyleSheet("color: #6B7280; font-size: 11px; margin-top: 6px; line-height: 1.4;")
        note.setWordWrap(True)
        a_layout.addWidget(note)
        a_layout.addStretch()

        bottom_layout.addWidget(actions_panel, 1)
        layout.addLayout(bottom_layout)

        scroll.setWidget(container)
        main_layout.addWidget(scroll)

        # Initial populate
        self.refresh_data()

    def refresh_data(self) -> None:
        """Pulls latest telemetry from services and refreshes all widgets."""
        tx_rate, rx_rate = self.network_service.update_traffic_rates()
        stats = self.network_service.get_summary_stats()
        metrics = self.event_service.get_metrics()

        # Update KPI Cards
        self.card_host.update_card(
            value=stats["local_ip"],
            subtext=f"Host: {stats['hostname']}",
        )
        self.card_traffic.update_card(
            value=f"↓ {self.network_service.format_rate(rx_rate)}",
            subtext=f"↑ {self.network_service.format_rate(tx_rate)} (Egress)",
        )
        self.card_conns.update_card(
            value=f"{stats['total_connections']} Sockets",
            subtext=f"TCP: {stats['tcp_count']} | UDP: {stats['udp_count']} | Listen: {stats['listening_count']}",
        )
        self.card_alerts.update_card(
            value=f"{metrics['total_events']} Events",
            subtext=f"Critical: {metrics['by_severity']['CRITICAL']} | High: {metrics['by_severity']['HIGH']}",
        )

        # Update Chart
        self.traffic_chart.update_data(
            self.network_service.rx_history,
            self.network_service.tx_history,
        )

        # Update Interfaces Table
        ifaces = self.network_service.get_interfaces()
        self.iface_table.setRowCount(len(ifaces))
        for row, iface in enumerate(ifaces):
            item_name = QTableWidgetItem(iface.name)
            item_name.setFont(self._bold_font())
            self.iface_table.setItem(row, 0, item_name)

            state_str = "● UP" if iface.is_up else "○ DOWN"
            item_state = QTableWidgetItem(state_str)
            item_state.setForeground(QColor("#4ECCA3") if iface.is_up else QColor("#FF4D6D"))
            item_state.setFont(self._bold_font())
            self.iface_table.setItem(row, 1, item_state)

            ipv4_str = ", ".join(iface.ipv4_addresses) if iface.ipv4_addresses else "No IPv4"
            self.iface_table.setItem(row, 2, QTableWidgetItem(ipv4_str))

            speed_str = f"{iface.speed_mbps} Mbps" if iface.speed_mbps > 0 else "N/A"
            self.iface_table.setItem(row, 3, QTableWidgetItem(speed_str))

            pkt_str = f"↓{iface.packets_recv:,} / ↑{iface.packets_sent:,}"
            self.iface_table.setItem(row, 4, QTableWidgetItem(pkt_str))

            err_str = f"Err:{iface.errin + iface.errout} Drop:{iface.dropin + iface.dropout}"
            self.iface_table.setItem(row, 5, QTableWidgetItem(err_str))

        # Update Recent Events Table
        recent = self.event_service.get_events(limit=8)
        self.events_table.setRowCount(len(recent))
        sev_colors = {
            "CRITICAL": "#F72585",
            "HIGH": "#FE8019",
            "MEDIUM": "#FABD2F",
            "LOW": "#83A598",
            "INFO": "#4ECCA3",
        }
        for row, ev in enumerate(recent):
            time_str = ev.iso_time.split(" ")[1] if " " in ev.iso_time else ev.iso_time
            self.events_table.setItem(row, 0, QTableWidgetItem(time_str))

            item_sev = QTableWidgetItem(f"[{ev.severity}]")
            item_sev.setForeground(QColor(sev_colors.get(ev.severity, "#FFFFFF")))
            item_sev.setFont(self._bold_font())
            self.events_table.setItem(row, 1, item_sev)

            src_str = f"{ev.source_ip}:{ev.port}" if ev.source_ip and ev.port else (ev.source_ip or "System Internal")
            self.events_table.setItem(row, 2, QTableWidgetItem(src_str))

            self.events_table.setItem(row, 3, QTableWidgetItem(ev.title))

            type_str = "SIMULATED" if ev.simulated else "LIVE"
            item_type = QTableWidgetItem(type_str)
            item_type.setForeground(QColor("#FF70A6") if ev.simulated else QColor("#4ECCA3"))
            item_type.setFont(self._bold_font())
            self.events_table.setItem(row, 4, item_type)

    def _bold_font(self) -> QFont:
        f = QFont()
        f.setBold(True)
        return f

    def _on_quick_attack(self) -> None:
        self.detection_service.trigger_single_attack()
        self.refresh_data()

    def _on_quick_ids_toggle(self) -> None:
        if self.detection_service.is_running:
            self.detection_service.stop_simulation()
        else:
            self.detection_service.start_simulation()
        self.refresh_data()
