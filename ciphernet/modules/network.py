"""
CipherNet Network Monitor Module (PySide6)
Provides real-time inspection of active TCP/UDP sockets, protocol/state filtering,
live search, socket forensics inspector, and interface packet capture status.
Uses background workers to prevent GUI freezes during socket and DNS lookups.
"""

from __future__ import annotations
from typing import List, Optional
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ciphernet.services.network_service import ConnectionInfo, NetworkService
from ciphernet.widgets.panels import SectionHeader
from ciphernet.workers import NetworkTelemetryWorker


PROTOCOL_OPTIONS = [
    ("All Protocols", "ALL"),
    ("TCP Sockets", "TCP"),
    ("UDP Sockets", "UDP"),
]

STATE_OPTIONS = [
    ("All States", "ALL"),
    ("ESTABLISHED", "ESTABLISHED"),
    ("LISTEN", "LISTEN"),
    ("TIME_WAIT", "TIME_WAIT"),
    ("CLOSE_WAIT", "CLOSE_WAIT"),
    ("SYN_SENT", "SYN_SENT"),
]


class NetworkMonitorView(QWidget):
    """
    Network Monitor dashboard view for socket analysis and connection filtering.
    """

    def __init__(self, network_service: NetworkService, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.network_service = network_service
        self.selected_proto = "ALL"
        self.selected_state = "ALL"
        self.search_query = ""
        self.cached_conns: List[ConnectionInfo] = []
        self._worker: Optional[NetworkTelemetryWorker] = None

        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        # Header Title
        header_col = QVBoxLayout()
        header_col.setSpacing(2)
        h_title = QLabel("NETWORK MONITOR & SOCKET FORENSICS")
        h_title.setStyleSheet("color: #FFFFFF; font-size: 18px; font-weight: 900; letter-spacing: 0.5px;")
        h_sub = QLabel("Active TCP & UDP Endpoints, Socket States, and Owning Process Resolution")
        h_sub.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        header_col.addWidget(h_title)
        header_col.addWidget(h_sub)
        main_layout.addLayout(header_col)

        # -------------------------------------------------------------
        # 1. Filter Toolbar
        # -------------------------------------------------------------
        toolbar = QFrame()
        toolbar.setProperty("class", "panel-card")
        toolbar.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 10px 14px; }"
        )
        t_layout = QHBoxLayout(toolbar)
        t_layout.setContentsMargins(4, 4, 4, 4)
        t_layout.setSpacing(12)

        filter_lbl = QLabel("Filter:")
        filter_lbl.setStyleSheet("color: #9CA3AF; font-weight: 800; font-size: 11px; letter-spacing: 1px;")
        t_layout.addWidget(filter_lbl)

        # Protocol dropdown
        self.combo_proto = QComboBox()
        for label, val in PROTOCOL_OPTIONS:
            self.combo_proto.addItem(label, val)
        self.combo_proto.currentIndexChanged.connect(self._on_filter_changed)
        t_layout.addWidget(self.combo_proto)

        # State dropdown
        self.combo_state = QComboBox()
        for label, val in STATE_OPTIONS:
            self.combo_state.addItem(label, val)
        self.combo_state.currentIndexChanged.connect(self._on_filter_changed)
        t_layout.addWidget(self.combo_state)

        # Search Input
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search IP, Port, or Process Name...")
        self.search_input.returnPressed.connect(self._on_filter_changed)
        t_layout.addWidget(self.search_input, 1)

        # Action Buttons
        self.btn_apply = QPushButton("Apply Filter")
        self.btn_apply.setProperty("class", "btn-primary")
        self.btn_apply.clicked.connect(self._on_filter_changed)
        t_layout.addWidget(self.btn_apply)

        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.clicked.connect(self.refresh_connections)
        t_layout.addWidget(self.btn_refresh)

        main_layout.addWidget(toolbar)

        # -------------------------------------------------------------
        # 2. Main Sockets Table
        # -------------------------------------------------------------
        main_layout.addWidget(SectionHeader("Active Sockets & Connections", "Live Network Sockets Enumerated via psutil"))

        self.conns_table = QTableWidget()
        self.conns_table.setColumnCount(6)
        self.conns_table.setHorizontalHeaderLabels([
            "Proto", "Local Address", "Remote Address", "State", "PID", "Process Name"
        ])
        self.conns_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.conns_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.conns_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.conns_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.conns_table.verticalHeader().setVisible(False)
        self.conns_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.conns_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.conns_table.setAlternatingRowColors(True)
        self.conns_table.itemSelectionChanged.connect(self._on_row_selected)

        main_layout.addWidget(self.conns_table, 1)

        # -------------------------------------------------------------
        # 3. Bottom Split Pane (Inspector & Bandwidth/Scapy Box)
        # -------------------------------------------------------------
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background: #1E232E; width: 2px; }")

        # Left: Selected Socket Inspector
        inspector_frame = QFrame()
        inspector_frame.setProperty("class", "panel-card")
        inspector_frame.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 14px; }"
        )
        ins_layout = QVBoxLayout(inspector_frame)
        ins_layout.setContentsMargins(12, 12, 12, 12)
        ins_layout.setSpacing(8)

        ins_title = QLabel("SELECTED SOCKET INSPECTOR")
        ins_title.setStyleSheet("color: #FF70A6; font-size: 11px; font-weight: 800; letter-spacing: 1.2px;")
        ins_layout.addWidget(ins_title)

        self.inspector_text = QLabel("Click any socket row above to inspect detailed endpoint telemetry.")
        self.inspector_text.setStyleSheet("color: #9CA3AF; font-size: 12px; line-height: 1.5;")
        self.inspector_text.setTextFormat(Qt.RichText)
        self.inspector_text.setWordWrap(True)
        ins_layout.addWidget(self.inspector_text)
        ins_layout.addStretch()

        splitter.addWidget(inspector_frame)

        # Right: Interfaces & Telemetry Summary
        telemetry_frame = QFrame()
        telemetry_frame.setProperty("class", "panel-card")
        telemetry_frame.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 14px; }"
        )
        tel_layout = QVBoxLayout(telemetry_frame)
        tel_layout.setContentsMargins(12, 12, 12, 12)
        tel_layout.setSpacing(8)

        tel_title = QLabel("INTERFACE BANDWIDTH & SCAPY STATUS")
        tel_title.setStyleSheet("color: #4ECCA3; font-size: 11px; font-weight: 800; letter-spacing: 1.2px;")
        tel_layout.addWidget(tel_title)

        self.telemetry_text = QLabel()
        self.telemetry_text.setStyleSheet("color: #F3F4F6; font-size: 12px; line-height: 1.5;")
        self.telemetry_text.setTextFormat(Qt.RichText)
        self.telemetry_text.setWordWrap(True)
        tel_layout.addWidget(self.telemetry_text)
        tel_layout.addStretch()

        splitter.addWidget(telemetry_frame)

        main_layout.addWidget(splitter)

        # Load initial data
        self.refresh_connections()

    def _on_filter_changed(self) -> None:
        self.selected_proto = self.combo_proto.currentData()
        self.selected_state = self.combo_state.currentData()
        self.search_query = self.search_input.text().strip()
        self.refresh_connections()

    def refresh_connections(self) -> None:
        """Runs background worker to poll active sockets and metrics without blocking GUI."""
        if self._worker and self._worker.isRunning():
            return

        self._worker = NetworkTelemetryWorker(
            network_service=self.network_service,
            protocol_filter=self.selected_proto,
            state_filter=self.selected_state,
            search_filter=self.search_query,
            parent=self,
        )
        self._worker.data_ready.connect(self._on_worker_data_ready)
        self._worker.start()

    def _on_worker_data_ready(self, stats: dict, ifaces: list, conns: list) -> None:
        self.cached_conns = conns

        self.conns_table.setRowCount(len(self.cached_conns))
        for row, c in enumerate(self.cached_conns):
            # Protocol
            proto_item = QTableWidgetItem(c.protocol)
            proto_color = "#4ECCA3" if c.protocol == "TCP" else "#FF70A6"
            proto_item.setForeground(QColor(proto_color))
            proto_item.setFont(self._bold_font())
            self.conns_table.setItem(row, 0, proto_item)

            # Local Address
            self.conns_table.setItem(row, 1, QTableWidgetItem(f"{c.local_ip}:{c.local_port}"))

            # Remote Address
            r_str = f"{c.remote_ip}:{c.remote_port}"
            if c.remote_host:
                r_str += f" ({c.remote_host})"
            self.conns_table.setItem(row, 2, QTableWidgetItem(r_str))

            # State
            state_colors = {
                "ESTABLISHED": "#4ECCA3",
                "LISTEN": "#FABD2F",
                "TIME_WAIT": "#83A598",
                "CLOSE_WAIT": "#FF4D6D",
                "OPEN": "#61AFEF",
            }
            state_item = QTableWidgetItem(c.state)
            state_item.setForeground(QColor(state_colors.get(c.state, "#FFFFFF")))
            state_item.setFont(self._bold_font())
            self.conns_table.setItem(row, 3, state_item)

            # PID
            pid_str = str(c.pid) if c.pid else "N/A"
            self.conns_table.setItem(row, 4, QTableWidgetItem(pid_str))

            # Process Name
            proc_item = QTableWidgetItem(c.process_name)
            if c.process_name != "N/A":
                proc_item.setFont(self._bold_font())
            else:
                proc_item.setForeground(QColor("#6B7280"))
            self.conns_table.setItem(row, 5, proc_item)

        self.update_telemetry_box(ifaces)

    def update_telemetry_box(self, ifaces: Optional[list] = None) -> None:
        if ifaces is None:
            ifaces = self.network_service.get_interfaces()

        tx_rate, rx_rate = self.network_service.update_traffic_rates()
        iface_names = ", ".join([f.name for f in ifaces[:3]])
        if len(ifaces) > 3:
            iface_names += f" (+{len(ifaces) - 3} more)"

        html = (
            f"<div style='line-height: 1.6; font-size: 12px;'>"
            f"<b>Bandwidth Speeds:</b> &nbsp;<span style='color: #4ECCA3; font-weight: bold;'>Rx: {self.network_service.format_rate(rx_rate)}</span> "
            f"&nbsp;│&nbsp; <span style='color: #FF70A6; font-weight: bold;'>Tx: {self.network_service.format_rate(tx_rate)}</span><br>"
            f"<b>Active Filtered Sockets:</b> &nbsp;<span style='color: #FFFFFF; font-weight: bold;'>{len(self.cached_conns)} conns</span><br>"
            f"<b>Packet Sniffing Engine:</b> &nbsp;<span style='color: #FABD2F;'>{self.network_service.scapy_status}</span><br>"
            f"<b>Detected Hardware NICs:</b> &nbsp;<span style='color: #9CA3AF;'>{len(ifaces)} active ({iface_names})</span>"
            f"</div>"
        )
        self.telemetry_text.setText(html)

    def _on_row_selected(self) -> None:
        selected_rows = self.conns_table.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        if 0 <= row < len(self.cached_conns):
            c = self.cached_conns[row]
            html = (
                f"<div style='line-height: 1.7; font-size: 12px;'>"
                f"<b>Protocol:</b> &nbsp;<span style='color: #FF70A6; font-weight: bold;'>{c.protocol}</span><br>"
                f"<b>Local Socket Endpoint:</b> &nbsp;<span style='color: #FFFFFF; font-family: monospace;'>{c.local_ip}:{c.local_port}</span><br>"
                f"<b>Remote Socket Endpoint:</b> &nbsp;<span style='color: #FFFFFF; font-family: monospace;'>{c.remote_ip}:{c.remote_port}</span><br>"
                f"<b>Resolved Hostname:</b> &nbsp;<span style='color: #83A598;'>{c.remote_host or 'N/A'}</span><br>"
                f"<b>Connection State:</b> &nbsp;<span style='color: #FABD2F; font-weight: bold;'>{c.state}</span><br>"
                f"<b>Process:</b> &nbsp;<span style='color: #4ECCA3; font-weight: bold;'>{c.process_name}</span> &nbsp;(PID: {c.pid or 'N/A'})"
                f"</div>"
            )
            self.inspector_text.setText(html)

    def _bold_font(self) -> QFont:
        f = QFont()
        f.setBold(True)
        return f
