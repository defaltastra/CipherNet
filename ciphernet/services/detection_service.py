"""
CipherNet Intrusion Detection Simulator & Rule Engine
Simulates realistic cyber attack vectors, evaluates threat signatures,
and generates structured alerts with severity ratings while clearly
distinguishing simulated activity from real telemetry.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import random
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from ciphernet.services.event_service import EventService, SecurityEvent


@dataclass
class DetectionRule:
    id: str
    name: str
    description: str
    default_severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    category: str
    enabled: bool = True
    match_count: int = 0


DEFAULT_RULES: List[DetectionRule] = [
    DetectionRule(
        id="RULE_PORT_SCAN",
        name="TCP Port Sweep / Reconnaissance",
        description="Detects sequential or multi-port probes indicative of nmap or masscan sweeps.",
        default_severity="HIGH",
        category="RECON",
        enabled=True,
    ),
    DetectionRule(
        id="RULE_SYN_FLOOD",
        name="TCP SYN Flood / DoS Signature",
        description="Detects anomalous bursts of incomplete handshake attempts exhausting backlog.",
        default_severity="CRITICAL",
        category="DOS",
        enabled=True,
    ),
    DetectionRule(
        id="RULE_SUSPICIOUS_PORT",
        name="C2 & Backdoor Communication",
        description="Detects connection attempts to notorious malware/trojan ports (4444, 1337, 31337, 9001).",
        default_severity="CRITICAL",
        category="EXPLOIT",
        enabled=True,
    ),
    DetectionRule(
        id="RULE_SSH_BRUTE_FORCE",
        name="SSH/FTP Service Brute Force",
        description="Identifies repeated authentication spikes and rapid reconnects against ports 22 and 21.",
        default_severity="HIGH",
        category="BRUTE_FORCE",
        enabled=True,
    ),
    DetectionRule(
        id="RULE_DATA_EXFILTRATION",
        name="Data Exfiltration via DNS Tunnel",
        description="Flags abnormal payload volume, base64 subdomains, and anomalous outbound egress.",
        default_severity="CRITICAL",
        category="EXFILTRATION",
        enabled=True,
    ),
    DetectionRule(
        id="RULE_BENIGN_TRAFFIC",
        name="Benign Telemetry & Health Probe",
        description="Categorizes routine NTP, HTTPS CDN, and ICMP keepalive signals.",
        default_severity="INFO",
        category="BENIGN",
        enabled=True,
    ),
]


SIMULATION_SCENARIOS = [
    {
        "id": "scenario_port_scan",
        "name": "Nmap Stealth SYN Port Scan",
        "rule_id": "RULE_PORT_SCAN",
        "severity": "HIGH",
        "source_pool": ["198.51.100.23", "203.0.113.88", "185.220.101.5"],
        "ports": [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080],
        "title": "Port Scan Detected: Rapid Sweep Across Range",
        "details": "Source IP initiated sequential TCP SYN probes against 13 host ports in 400ms.",
    },
    {
        "id": "scenario_syn_flood",
        "name": "Distributed TCP SYN Flood (DoS)",
        "rule_id": "RULE_SYN_FLOOD",
        "severity": "CRITICAL",
        "source_pool": ["192.0.2.14", "192.0.2.45", "192.0.2.99", "192.0.2.112"],
        "ports": [80, 443],
        "title": "SYN Flood Denial of Service Anomaly",
        "details": "Ingress rate exceeded threshold: 1,420 half-open connections with spoofed source headers.",
    },
    {
        "id": "scenario_c2_beacon",
        "name": "Metasploit / Cobalt Strike C2 Beacon",
        "rule_id": "RULE_SUSPICIOUS_PORT",
        "severity": "CRITICAL",
        "source_pool": ["10.0.4.88", "172.16.2.140"],
        "ports": [4444, 1337, 31337, 9001],
        "title": "Suspicious C2 Traffic to Port {port}",
        "details": "Reverse shell session beacon detected to external host. Signature matches Meterpreter payload.",
    },
    {
        "id": "scenario_ssh_brute",
        "name": "SSH Credential Dictionary Attack",
        "rule_id": "RULE_SSH_BRUTE_FORCE",
        "severity": "HIGH",
        "source_pool": ["45.33.32.156", "185.190.140.2"],
        "ports": [22],
        "title": "SSH Service Brute Force Activity",
        "details": "Failed authentication count reached 48 attempts in 10 seconds. Target user: 'root', 'admin'.",
    },
    {
        "id": "scenario_exfil",
        "name": "DNS Tunneling Covert Data Exfiltration",
        "rule_id": "RULE_DATA_EXFILTRATION",
        "severity": "CRITICAL",
        "source_pool": ["10.0.1.50"],
        "ports": [53],
        "title": "Covert Data Exfiltration via DNS Tunnel",
        "details": "High entropy TXT query burst detected (480 KB exfiltrated via 'x9f2.covert.attacker-c2.net').",
    },
    {
        "id": "scenario_benign",
        "name": "Routine NTP / HTTPS Telemetry",
        "rule_id": "RULE_BENIGN_TRAFFIC",
        "severity": "INFO",
        "source_pool": ["17.253.52.125", "142.250.190.46"],
        "ports": [123, 443],
        "title": "Standard Network Keepalive",
        "details": "Routine cryptographic time synchronization handshake verified.",
    },
]


class DetectionService:
    """Manages the Intrusion Detection simulation loop, rule evaluations, and alert timeline."""

    def __init__(self, event_service: EventService, intensity: str = "Medium") -> None:
        self.event_service = event_service
        self.intensity = intensity  # Low, Medium, Aggressive
        self.rules: Dict[str, DetectionRule] = {r.id: r for r in DEFAULT_RULES}
        self.is_running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._recent_alerts: List[SecurityEvent] = []

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        """Toggles a detection rule on or off."""
        with self._lock:
            if rule_id in self.rules:
                self.rules[rule_id].enabled = enabled
                return True
        return False

    def get_rules(self) -> List[DetectionRule]:
        """Returns list of all configured detection rules."""
        with self._lock:
            return list(self.rules.values())

    def start_simulation(self) -> bool:
        """Starts background simulated attack stream."""
        with self._lock:
            if self.is_running:
                return True
            self.is_running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._simulation_loop, daemon=True)
            self._thread.start()

        self.event_service.log(
            title="IDS Simulation Engine Started",
            details=f"Attack simulator is active. Intensity: {self.intensity}. Evaluating rules against simulated traffic.",
            severity="INFO",
            category="SIMULATION",
            simulated=True,
        )
        return True

    def stop_simulation(self) -> bool:
        """Stops background simulated attack stream."""
        with self._lock:
            if not self.is_running:
                return True
            self.is_running = False
            self._stop_event.set()

        self.event_service.log(
            title="IDS Simulation Engine Suspended",
            details="Attack simulation suspended by operator. Rule engine idle.",
            severity="INFO",
            category="SIMULATION",
            simulated=True,
        )
        return True

    def trigger_single_attack(self, scenario_id: Optional[str] = None) -> Optional[SecurityEvent]:
        """Triggers an instantaneous attack simulation scenario."""
        scenario = None
        if scenario_id:
            for s in SIMULATION_SCENARIOS:
                if s["id"] == scenario_id:
                    scenario = s
                    break
        if not scenario:
            scenario = random.choice(SIMULATION_SCENARIOS)

        return self._execute_scenario(scenario)

    def _execute_scenario(self, scenario: Dict[str, Any]) -> Optional[SecurityEvent]:
        rule_id = scenario["rule_id"]
        rule = self.rules.get(rule_id)

        # If corresponding rule is disabled, threat goes undetected or skipped
        if rule and not rule.enabled:
            return None

        src_ip = random.choice(scenario["source_pool"])
        target_ip = "192.168.1.105"
        port = random.choice(scenario["ports"])

        details = scenario["details"].format(port=port)
        title = scenario["title"].format(port=port)
        severity = scenario["severity"]

        if rule:
            rule.match_count += 1

        event = self.event_service.log(
            title=f"[SIMULATED] {title}",
            details=details,
            severity=severity,
            category="SIMULATION",
            source_ip=src_ip,
            target_ip=target_ip,
            port=port,
            simulated=True,
            metadata={
                "scenario": scenario["name"],
                "rule_matched": rule.name if rule else "Generic Rule",
                "simulated_tag": "TRUE_SIMULATION",
            },
        )

        with self._lock:
            self._recent_alerts.append(event)
            if len(self._recent_alerts) > 50:
                self._recent_alerts = self._recent_alerts[-50:]

        return event

    def _simulation_loop(self) -> None:
        """Background thread generating periodic attacks based on intensity."""
        while not self._stop_event.is_set():
            if self.intensity == "Low":
                sleep_interval = random.uniform(4.0, 7.0)
            elif self.intensity == "Aggressive":
                sleep_interval = random.uniform(0.6, 1.5)
            else:  # Medium
                sleep_interval = random.uniform(1.8, 3.2)

            # Sleep in small increments for responsive shutdown
            slept = 0.0
            while slept < sleep_interval and not self._stop_event.is_set():
                time.sleep(0.2)
                slept += 0.2

            if self._stop_event.is_set():
                break

            self._execute_scenario(random.choice(SIMULATION_SCENARIOS))

    def get_recent_alerts(self, limit: int = 15) -> List[SecurityEvent]:
        """Returns most recent simulated and detected security alerts."""
        with self._lock:
            return list(reversed(self._recent_alerts[-limit:]))
