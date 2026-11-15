"""
CipherNet Intrusion Detection Simulator Module (PySide6)
Interactive rule-based IDS engine simulating cyber attack patterns,
evaluating security signatures, radar sweeps, and threat timeline forensics.
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
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ciphernet.services.detection_service import DetectionService, SIMULATION_SCENARIOS
from ciphernet.services.event_service import EventService, SecurityEvent
from ciphernet.widgets.panels import CyberRadarWidget, SectionHeader


INTENSITY_OPTIONS = [
    ("Low (4-7s delay)", "Low"),
    ("Medium (2-3s delay)", "Medium"),
    ("Aggressive (0.5-1.5s delay)", "Aggressive"),
]

SCENARIO_OPTIONS = [
    ("Random Scenario Mix", "random"),
    ("Nmap Stealth SYN Port Scan", "scenario_port_scan"),
    ("Distributed SYN Flood (DoS)", "scenario_syn_flood"),
    ("Metasploit / C2 Beacon (Port 4444)", "scenario_c2_beacon"),
    ("SSH Credential Brute-Force", "scenario_ssh_brute"),
    ("DNS Tunneling Exfiltration", "scenario_exfil"),
    ("Benign NTP / HTTPS Telemetry", "scenario_benign"),
]


class IntrusionDetectionView(QWidget):
    """
    Intrusion Detection Simulator & Signature Engine View.
    """

    def __init__(
        self,
        detection_service: DetectionService,
        event_service: EventService,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.detection_service = detection_service
        self.event_service = event_service
        self.selected_scenario = "random"
        self.cached_alerts: List[SecurityEvent] = []

        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        # Header Title
        header_col = QVBoxLayout()
        header_col.setSpacing(2)
        h_title = QLabel("INTRUSION DETECTION SIMULATOR")
        h_title.setStyleSheet("color: #FFFFFF; font-size: 18px; font-weight: 900; letter-spacing: 0.5px;")
        h_sub = QLabel("Rule-Based Signature Engine, Simulated Threat Vectors, and Forensic Event Inspection")
        h_sub.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        header_col.addWidget(h_title)
        header_col.addWidget(h_sub)
        main_layout.addLayout(header_col)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background: #1E232E; width: 2px; }")

        # -------------------------------------------------------------
        # LEFT COLUMN: Radar, Simulator Controls & Rules Checklist
        # -------------------------------------------------------------
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 12, 0)
        left_layout.setSpacing(12)

        left_layout.addWidget(SectionHeader("IDS Engine & Threat Radar", "Simulation Controller & Sweep Meter"))

        # Animated Cyber Radar
        radar_container = QFrame()
        radar_container.setProperty("class", "panel-card")
        radar_container.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 6px; }"
        )
        rc_layout = QVBoxLayout(radar_container)
        rc_layout.setContentsMargins(4, 4, 4, 4)
        self.radar = CyberRadarWidget()
        self.radar.setMinimumHeight(150)
        rc_layout.addWidget(self.radar)
        left_layout.addWidget(radar_container)

        # Engine Status Badge
        self.status_badge = QLabel()
        self.status_badge.setStyleSheet(
            "padding: 8px 12px; border-radius: 8px; background-color: #151820; border: 1px solid #1E232E; font-size: 11px;"
        )
        left_layout.addWidget(self.status_badge)

        # Action Button Row (Start / Stop)
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self.btn_start = QPushButton("▶ Start Engine")
        self.btn_start.setProperty("class", "btn-success")
        self.btn_start.clicked.connect(self._on_start_engine)
        btn_row.addWidget(self.btn_start)

        self.btn_stop = QPushButton("■ Stop Engine")
        self.btn_stop.setProperty("class", "btn-danger")
        self.btn_stop.clicked.connect(self._on_stop_engine)
        btn_row.addWidget(self.btn_stop)

        left_layout.addLayout(btn_row)

        # Scenario Selector
        left_layout.addWidget(QLabel("Simulation Scenario:"))
        self.combo_scenario = QComboBox()
        for label, val in SCENARIO_OPTIONS:
            self.combo_scenario.addItem(label, val)
        self.combo_scenario.currentIndexChanged.connect(self._on_scenario_changed)
        left_layout.addWidget(self.combo_scenario)

        # Intensity Selector
        left_layout.addWidget(QLabel("Attack Intensity / Rate:"))
        self.combo_intensity = QComboBox()
        for label, val in INTENSITY_OPTIONS:
            self.combo_intensity.addItem(label, val)
        idx = self.combo_intensity.findData(self.detection_service.intensity)
        if idx >= 0:
            self.combo_intensity.setCurrentIndex(idx)
        self.combo_intensity.currentIndexChanged.connect(self._on_intensity_changed)
        left_layout.addWidget(self.combo_intensity)

        # Fire Attack Burst Button
        self.btn_fire = QPushButton("⚡ Fire Attack Burst Now")
        self.btn_fire.setProperty("class", "btn-primary")
        self.btn_fire.clicked.connect(self._on_fire_attack)
        left_layout.addWidget(self.btn_fire)

        # Rules Table
        left_layout.addWidget(SectionHeader("Configured Detection Rules", "Double-Click Row to Toggle Active / Disabled"))
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(5)
        self.rules_table.setHorizontalHeaderLabels([
            "Rule ID", "Threat Name", "Severity", "Matches", "Status"
        ])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.rules_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.rules_table.verticalHeader().setVisible(False)
        self.rules_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.rules_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.cellDoubleClicked.connect(self._on_rule_double_clicked)
        left_layout.addWidget(self.rules_table, 1)

        splitter.addWidget(left_widget)

        # -------------------------------------------------------------
        # RIGHT COLUMN: Simulated Alert Timeline & Forensics Inspector
        # -------------------------------------------------------------
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(12, 0, 0, 0)
        right_layout.setSpacing(12)

        right_layout.addWidget(SectionHeader("Simulated Alert Timeline", "Real-Time Synthetic Threat Signatures"))

        self.timeline_table = QTableWidget()
        self.timeline_table.setColumnCount(6)
        self.timeline_table.setHorizontalHeaderLabels([
            "Time (UTC)", "Severity", "Origin IP", "Target Port", "Description", "Type"
        ])
        self.timeline_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.timeline_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.timeline_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.timeline_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.timeline_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.timeline_table.verticalHeader().setVisible(False)
        self.timeline_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.timeline_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.timeline_table.setAlternatingRowColors(True)
        self.timeline_table.itemSelectionChanged.connect(self._on_alert_selected)

        right_layout.addWidget(self.timeline_table, 2)

        # Threat Inspection Panel
        right_layout.addWidget(SectionHeader("Threat Forensics Inspector", "Detailed Attack Packet Attributes"))

        inspector_card = QFrame()
        inspector_card.setProperty("class", "panel-card")
        inspector_card.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        ic_layout = QVBoxLayout(inspector_card)
        ic_layout.setContentsMargins(12, 12, 12, 12)

        self.inspector_label = QLabel("Select an alert in the timeline above to inspect forensic details.")
        self.inspector_label.setStyleSheet("color: #9CA3AF; font-size: 12px; line-height: 1.6;")
        self.inspector_label.setTextFormat(Qt.RichText)
        self.inspector_label.setWordWrap(True)
        ic_layout.addWidget(self.inspector_label)
        ic_layout.addStretch()

        right_layout.addWidget(inspector_card, 1)

        splitter.addWidget(right_widget)
        main_layout.addWidget(splitter)

        # Initialize
        self.refresh_rules_table()
        self.refresh_timeline()
        self.update_status_badge()

    def update_status_badge(self) -> None:
        running = self.detection_service.is_running
        metrics = self.event_service.get_metrics()
        crit_count = metrics["by_severity"]["CRITICAL"]
        high_count = metrics["by_severity"]["HIGH"]
        threat_score = min(100, 15 + (crit_count * 15 + high_count * 8))

        if running:
            self.status_badge.setText(
                f"<b style='color: #4ECCA3;'>● ENGINE ARMED</b> &nbsp;// Simulating attack patterns at "
                f"<b style='color: #FF70A6;'>{self.detection_service.intensity} rate</b>"
            )
            self.radar.set_active(True, threat_score)
        else:
            self.status_badge.setText(
                "<b style='color: #FABD2F;'>○ ENGINE STANDBY</b> &nbsp;// Simulation idle. Awaiting trigger."
            )
            self.radar.set_active(False, threat_score)

    def refresh_rules_table(self) -> None:
        rules = self.detection_service.get_rules()
        self.rules_table.setRowCount(len(rules))

        sev_colors = {
            "CRITICAL": "#F72585",
            "HIGH": "#FE8019",
            "MEDIUM": "#FABD2F",
            "LOW": "#83A598",
            "INFO": "#4ECCA3",
        }

        for row, r in enumerate(rules):
            item_id = QTableWidgetItem(r.id)
            item_id.setFont(self._bold_font())
            self.rules_table.setItem(row, 0, item_id)

            self.rules_table.setItem(row, 1, QTableWidgetItem(r.name))

            item_sev = QTableWidgetItem(r.default_severity)
            item_sev.setForeground(QColor(sev_colors.get(r.default_severity, "#FFFFFF")))
            item_sev.setFont(self._bold_font())
            self.rules_table.setItem(row, 2, item_sev)

            self.rules_table.setItem(row, 3, QTableWidgetItem(str(r.match_count)))

            status_str = "ACTIVE" if r.enabled else "DISABLED"
            item_st = QTableWidgetItem(status_str)
            item_st.setForeground(QColor("#4ECCA3") if r.enabled else QColor("#FF4D6D"))
            item_st.setFont(self._bold_font())
            self.rules_table.setItem(row, 4, item_st)

    def refresh_timeline(self) -> None:
        self.cached_alerts = self.event_service.get_events(limit=35, category="SIMULATION")
        self.timeline_table.setRowCount(len(self.cached_alerts))

        sev_colors = {
            "CRITICAL": "#F72585",
            "HIGH": "#FE8019",
            "MEDIUM": "#FABD2F",
            "LOW": "#83A598",
            "INFO": "#4ECCA3",
        }

        for row, ev in enumerate(self.cached_alerts):
            time_str = ev.iso_time.split(" ")[1] if " " in ev.iso_time else ev.iso_time
            self.timeline_table.setItem(row, 0, QTableWidgetItem(time_str))

            item_sev = QTableWidgetItem(f"[{ev.severity}]")
            item_sev.setForeground(QColor(sev_colors.get(ev.severity, "#FFFFFF")))
            item_sev.setFont(self._bold_font())
            self.timeline_table.setItem(row, 1, item_sev)

            src_str = ev.source_ip or "Simulated Host"
            self.timeline_table.setItem(row, 2, QTableWidgetItem(src_str))

            port_str = f"Port {ev.port}" if ev.port else "N/A"
            self.timeline_table.setItem(row, 3, QTableWidgetItem(port_str))

            title_clean = ev.title.replace("[SIMULATED] ", "")
            self.timeline_table.setItem(row, 4, QTableWidgetItem(title_clean))

            badge_item = QTableWidgetItem("[SIMULATED]")
            badge_item.setForeground(QColor("#FF70A6"))
            badge_item.setFont(self._bold_font())
            self.timeline_table.setItem(row, 5, badge_item)

    def _on_alert_selected(self) -> None:
        selected_rows = self.timeline_table.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        if 0 <= row < len(self.cached_alerts):
            ev = self.cached_alerts[row]
            html = (
                f"<div style='line-height: 1.7; font-size: 12px;'>"
                f"<b>Threat Title:</b> &nbsp;<span style='color: #FFFFFF; font-weight: bold;'>{ev.title}</span><br>"
                f"<b>Severity Rating:</b> &nbsp;<span style='color: #F72585; font-weight: bold;'>{ev.severity}</span> &nbsp;│&nbsp; "
                f"<b>Timestamp:</b> &nbsp;<span style='color: #83A598;'>{ev.iso_time}</span><br>"
                f"<b>Attack Vector:</b> &nbsp;<span style='color: #FF70A6; font-family: monospace;'>{ev.source_ip}</span> &nbsp;→&nbsp; "
                f"<b>Target:</b> &nbsp;<span style='font-family: monospace;'>{ev.target_ip or 'Local'}:{ev.port or 'N/A'}</span><br>"
                f"<b>Forensic Details:</b> &nbsp;<span style='color: #FABD2F;'>{ev.details}</span><br>"
                f"<b>Simulation Tag:</b> &nbsp;<span style='color: #FF70A6; font-style: italic;'>TRUE_SIMULATION (Synthetic event isolated from live network)</span>"
                f"</div>"
            )
            self.inspector_label.setText(html)

    def _on_rule_double_clicked(self, row: int, col: int) -> None:
        rules = self.detection_service.get_rules()
        if 0 <= row < len(rules):
            r = rules[row]
            self.detection_service.set_rule_enabled(r.id, not r.enabled)
            self.refresh_rules_table()

    def _on_start_engine(self) -> None:
        self.detection_service.start_simulation()
        self.update_status_badge()
        self.refresh_timeline()

    def _on_stop_engine(self) -> None:
        self.detection_service.stop_simulation()
        self.update_status_badge()
        self.refresh_timeline()

    def _on_scenario_changed(self) -> None:
        self.selected_scenario = self.combo_scenario.currentData()

    def _on_intensity_changed(self) -> None:
        self.detection_service.intensity = self.combo_intensity.currentData()
        self.update_status_badge()

    def _on_fire_attack(self) -> None:
        scenario_arg = None if self.selected_scenario == "random" else self.selected_scenario
        self.detection_service.trigger_single_attack(scenario_arg)
        self.radar.add_blip()
        self.refresh_rules_table()
        self.refresh_timeline()
        self.update_status_badge()

    def _bold_font(self) -> QFont:
        f = QFont()
        f.setBold(True)
        return f
