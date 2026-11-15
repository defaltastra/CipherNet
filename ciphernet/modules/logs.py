"""
CipherNet Security Logs Module (PySide6)
Chronological forensic audit ledger with multi-facet filters,
JSON audit export functionality, and deep metadata inspection.
"""

from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import List, Optional
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ciphernet.services.event_service import EventService, SecurityEvent
from ciphernet.widgets.panels import SectionHeader


SEVERITY_FILTER_OPTIONS = [
    ("All Severities", "ALL"),
    ("CRITICAL Alerts", "CRITICAL"),
    ("HIGH Alerts", "HIGH"),
    ("MEDIUM Alerts", "MEDIUM"),
    ("LOW Alerts", "LOW"),
    ("INFO Records", "INFO"),
]

CATEGORY_FILTER_OPTIONS = [
    ("All Categories", "ALL"),
    ("Simulation Events", "SIMULATION"),
    ("Network Telemetry", "NETWORK"),
    ("Cryptography Audits", "CRYPTO"),
    ("System Notices", "SYSTEM"),
]


class SecurityLogsView(QWidget):
    """
    Forensic security log ledger and audit trail explorer.
    """

    def __init__(self, event_service: EventService, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.event_service = event_service
        self.severity_filter = "ALL"
        self.category_filter = "ALL"
        self.search_filter = ""
        self.cached_logs: List[SecurityEvent] = []

        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        # Header Title
        header_col = QVBoxLayout()
        header_col.setSpacing(2)
        h_title = QLabel("SECURITY LOGS & FORENSIC LEDGER")
        h_title.setStyleSheet("color: #FFFFFF; font-size: 18px; font-weight: 900; letter-spacing: 0.5px;")
        h_sub = QLabel("Immutable Event Bus Records, Telemetry Benchmarks, and Structured JSON SIEM Exports")
        h_sub.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        header_col.addWidget(h_title)
        header_col.addWidget(h_sub)
        main_layout.addLayout(header_col)

        # -------------------------------------------------------------
        # 1. Filters & Action Toolbar
        # -------------------------------------------------------------
        toolbar = QFrame()
        toolbar.setProperty("class", "panel-card")
        toolbar.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 10px 14px; }"
        )
        t_layout = QHBoxLayout(toolbar)
        t_layout.setContentsMargins(4, 4, 4, 4)
        t_layout.setSpacing(12)

        lbl = QLabel("Filters:")
        lbl.setStyleSheet("color: #9CA3AF; font-weight: 800; font-size: 11px; letter-spacing: 1px;")
        t_layout.addWidget(lbl)

        # Severity filter
        self.combo_severity = QComboBox()
        for label, val in SEVERITY_FILTER_OPTIONS:
            self.combo_severity.addItem(label, val)
        self.combo_severity.currentIndexChanged.connect(self._on_filters_changed)
        t_layout.addWidget(self.combo_severity)

        # Category filter
        self.combo_category = QComboBox()
        for label, val in CATEGORY_FILTER_OPTIONS:
            self.combo_category.addItem(label, val)
        self.combo_category.currentIndexChanged.connect(self._on_filters_changed)
        t_layout.addWidget(self.combo_category)

        # Search Query Input
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search logs by keyword, IP, title...")
        self.search_input.returnPressed.connect(self._on_filters_changed)
        t_layout.addWidget(self.search_input, 1)

        self.btn_search = QPushButton("🔍 Search")
        self.btn_search.setProperty("class", "btn-primary")
        self.btn_search.clicked.connect(self._on_filters_changed)
        t_layout.addWidget(self.btn_search)

        self.btn_export = QPushButton("💾 Export to JSON")
        self.btn_export.setProperty("class", "btn-success")
        self.btn_export.clicked.connect(self._on_export_logs)
        t_layout.addWidget(self.btn_export)

        self.btn_clear = QPushButton("🗑 Clear Logs")
        self.btn_clear.setProperty("class", "btn-danger")
        self.btn_clear.clicked.connect(self._on_clear_logs)
        t_layout.addWidget(self.btn_clear)

        main_layout.addWidget(toolbar)

        # -------------------------------------------------------------
        # 2. Main Logs Table
        # -------------------------------------------------------------
        main_layout.addWidget(SectionHeader("Audit Trail & Security Events", "Chronological Log Stream with Real-Time Filtering"))

        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(6)
        self.logs_table.setHorizontalHeaderLabels([
            "Time (UTC)", "Severity", "Category", "Event Title", "Origin / Source", "Simulated?"
        ])
        self.logs_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.logs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.logs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.logs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.logs_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.logs_table.verticalHeader().setVisible(False)
        self.logs_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.logs_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.logs_table.setAlternatingRowColors(True)
        self.logs_table.itemSelectionChanged.connect(self._on_log_selected)

        main_layout.addWidget(self.logs_table, 2)

        # -------------------------------------------------------------
        # 3. Forensic Metadata Inspector Panel
        # -------------------------------------------------------------
        main_layout.addWidget(SectionHeader("Selected Event Inspector", "Forensic Data & JSON Metadata"))

        inspector_card = QFrame()
        inspector_card.setProperty("class", "panel-card")
        inspector_card.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        ic_layout = QVBoxLayout(inspector_card)
        ic_layout.setContentsMargins(12, 12, 12, 12)

        self.inspector_label = QLabel("Click any security event row above to inspect complete forensic metadata.")
        self.inspector_label.setStyleSheet("color: #9CA3AF; font-size: 12px; line-height: 1.6;")
        self.inspector_label.setTextFormat(Qt.RichText)
        self.inspector_label.setWordWrap(True)
        ic_layout.addWidget(self.inspector_label)
        ic_layout.addStretch()

        main_layout.addWidget(inspector_card, 1)

        # Initial populate
        self.refresh_logs()

    def _on_filters_changed(self) -> None:
        self.severity_filter = self.combo_severity.currentData()
        self.category_filter = self.combo_category.currentData()
        self.search_filter = self.search_input.text().strip()
        self.refresh_logs()

    def refresh_logs(self) -> None:
        self.cached_logs = self.event_service.get_events(
            limit=250,
            severity=self.severity_filter,
            category=self.category_filter,
            search_query=self.search_filter,
            reverse=True,
        )

        self.logs_table.setRowCount(len(self.cached_logs))

        sev_colors = {
            "CRITICAL": "#F72585",
            "HIGH": "#FE8019",
            "MEDIUM": "#FABD2F",
            "LOW": "#83A598",
            "INFO": "#4ECCA3",
        }

        cat_colors = {
            "SIMULATION": "#FF70A6",
            "NETWORK": "#83A598",
            "CRYPTO": "#FABD2F",
            "SYSTEM": "#9CA3AF",
        }

        for row, ev in enumerate(self.cached_logs):
            self.logs_table.setItem(row, 0, QTableWidgetItem(ev.iso_time))

            item_sev = QTableWidgetItem(f"[{ev.severity}]")
            item_sev.setForeground(QColor(sev_colors.get(ev.severity, "#FFFFFF")))
            item_sev.setFont(self._bold_font())
            self.logs_table.setItem(row, 1, item_sev)

            item_cat = QTableWidgetItem(ev.category)
            item_cat.setForeground(QColor(cat_colors.get(ev.category, "#FFFFFF")))
            item_cat.setFont(self._bold_font())
            self.logs_table.setItem(row, 2, item_cat)

            self.logs_table.setItem(row, 3, QTableWidgetItem(ev.title))

            src_str = f"{ev.source_ip}:{ev.port}" if ev.source_ip and ev.port else (ev.source_ip or "System Internal")
            self.logs_table.setItem(row, 4, QTableWidgetItem(src_str))

            sim_str = "YES (SIM)" if ev.simulated else "NO (LIVE)"
            item_sim = QTableWidgetItem(sim_str)
            item_sim.setForeground(QColor("#FF70A6") if ev.simulated else QColor("#4ECCA3"))
            item_sim.setFont(self._bold_font())
            self.logs_table.setItem(row, 5, item_sim)

    def _on_log_selected(self) -> None:
        selected_rows = self.logs_table.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        if 0 <= row < len(self.cached_logs):
            ev = self.cached_logs[row]
            meta_json = json.dumps(ev.metadata, indent=2)
            html = (
                f"<div style='line-height: 1.7; font-size: 12px;'>"
                f"<b>Event ID:</b> &nbsp;<span style='color: #F72585; font-family: monospace; font-weight: bold;'>{ev.id}</span> &nbsp;│&nbsp; "
                f"<b>Timestamp:</b> &nbsp;<span style='color: #83A598;'>{ev.iso_time}</span> &nbsp;(Unix: {ev.timestamp})<br>"
                f"<b>Severity:</b> &nbsp;<span style='color: #FF70A6; font-weight: bold;'>{ev.severity}</span> &nbsp;│&nbsp; "
                f"<b>Category:</b> &nbsp;<span style='color: #FABD2F; font-weight: bold;'>{ev.category}</span><br>"
                f"<b>Event Title:</b> &nbsp;<span style='color: #FFFFFF; font-weight: bold;'>{ev.title}</span><br>"
                f"<b>Forensic Details:</b> &nbsp;<span style='color: #F3F4F6;'>{ev.details}</span><br>"
                f"<b>Source → Target:</b> &nbsp;<span>{ev.source_ip or 'None'} → {ev.target_ip or 'None'}:{ev.port or 'None'}</span><br>"
                f"<b>Metadata Object:</b><br><pre style='color: #9CA3AF; margin: 4px 0; font-family: monospace;'>{meta_json}</pre>"
                f"</div>"
            )
            self.inspector_label.setText(html)

    def _on_export_logs(self) -> None:
        default_dir = Path("logs")
        default_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        default_filename = str(default_dir / f"ciphernet_audit_{ts}.json")

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Audit Logs to JSON",
            default_filename,
            "JSON Files (*.json);;All Files (*)",
        )

        if file_path:
            out = self.event_service.export_to_json(file_path)
            QMessageBox.information(
                self,
                "Audit Logs Exported",
                f"Successfully exported security logs to:\n{out}",
            )

    def _on_clear_logs(self) -> None:
        reply = QMessageBox.question(
            self,
            "Confirm Clear Logs",
            "Are you sure you want to purge all stored security events?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.event_service.clear()
            self.refresh_logs()

    def _bold_font(self) -> QFont:
        f = QFont()
        f.setBold(True)
        return f
