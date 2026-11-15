"""
CipherNet Event Service
Central event bus and chronological audit logger for network, IDS, and crypto events.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import threading
import time
from typing import Any, Callable, Dict, List, Optional
import uuid


SEVERITY_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
CATEGORIES = ("SIMULATION", "NETWORK", "CRYPTO", "SYSTEM")


@dataclass
class SecurityEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: float = field(default_factory=time.time)
    iso_time: str = ""
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    category: str = "SYSTEM"  # SIMULATION, NETWORK, CRYPTO, SYSTEM
    title: str = ""
    details: str = ""
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    port: Optional[int] = None
    simulated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.iso_time:
            dt = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
            self.iso_time = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        self.severity = self.severity.upper()
        if self.severity not in SEVERITY_LEVELS:
            self.severity = "INFO"
        self.category = self.category.upper()
        if self.category not in CATEGORIES:
            self.category = "SYSTEM"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EventService:
    """Thread-safe event registry with filtering, metrics, and JSON export."""

    def __init__(self, max_capacity: int = 1000) -> None:
        self.max_capacity = max_capacity
        self._events: List[SecurityEvent] = []
        self._lock = threading.RLock()
        self._listeners: List[Callable[[SecurityEvent], None]] = []

        # Seed with initial system startup events
        self.log(
            title="CipherNet Security Engine Initialized",
            details="Core security event bus and telemetry monitors started.",
            severity="INFO",
            category="SYSTEM",
            simulated=False,
            metadata={"version": "1.0.0", "author": "CipherNet Team"},
        )

    def subscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a callback for new events."""
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def unsubscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Remove a callback."""
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def log(
        self,
        title: str,
        details: str = "",
        severity: str = "INFO",
        category: str = "SYSTEM",
        source_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        port: Optional[int] = None,
        simulated: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        """Log a new security/system/crypto event."""
        event = SecurityEvent(
            title=title,
            details=details,
            severity=severity,
            category=category,
            source_ip=source_ip,
            target_ip=target_ip,
            port=port,
            simulated=simulated,
            metadata=metadata or {},
        )

        listeners_to_call: List[Callable[[SecurityEvent], None]] = []
        with self._lock:
            self._events.append(event)
            # Enforce max capacity ring buffer
            if len(self._events) > self.max_capacity:
                self._events = self._events[-self.max_capacity:]
            listeners_to_call = list(self._listeners)

        # Notify subscribers without holding lock
        for cb in listeners_to_call:
            try:
                cb(event)
            except Exception:
                pass

        return event

    def get_events(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        simulated_only: Optional[bool] = None,
        search_query: Optional[str] = None,
        reverse: bool = True,
    ) -> List[SecurityEvent]:
        """Query events with optional filtering, returned in chronological or reverse order."""
        with self._lock:
            events = list(self._events)

        if severity and severity.upper() != "ALL":
            sev = severity.upper()
            events = [e for e in events if e.severity == sev]

        if category and category.upper() != "ALL":
            cat = category.upper()
            events = [e for e in events if e.category == cat]

        if simulated_only is not None:
            events = [e for e in events if e.simulated == simulated_only]

        if search_query:
            query = search_query.lower()
            events = [
                e
                for e in events
                if query in e.title.lower()
                or query in e.details.lower()
                or (e.source_ip and query in e.source_ip.lower())
                or (e.target_ip and query in e.target_ip.lower())
                or query in e.category.lower()
                or query in e.severity.lower()
            ]

        if reverse:
            events.reverse()

        return events[:limit]

    def get_metrics(self) -> Dict[str, Any]:
        """Calculates security metrics and counters."""
        with self._lock:
            events = list(self._events)

        total = len(events)
        by_severity = {s: 0 for s in SEVERITY_LEVELS}
        by_category = {c: 0 for c in CATEGORIES}
        simulated_count = 0
        real_count = 0

        for e in events:
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
            by_category[e.category] = by_category.get(e.category, 0) + 1
            if e.simulated:
                simulated_count += 1
            else:
                real_count += 1

        critical_or_high = by_severity["CRITICAL"] + by_severity["HIGH"]

        return {
            "total_events": total,
            "by_severity": by_severity,
            "by_category": by_category,
            "simulated_events": simulated_count,
            "real_events": real_count,
            "critical_or_high": critical_or_high,
            "last_event_time": events[-1].iso_time if events else "N/A",
        }

    def clear(self) -> None:
        """Clears all stored events."""
        with self._lock:
            self._events.clear()
            self.log(
                title="Event Log Purged",
                details="Security event log history was cleared by user.",
                severity="INFO",
                category="SYSTEM",
            )

    def export_to_json(self, export_path: str | Path) -> str:
        """Exports all security logs to a JSON file."""
        export_path = Path(export_path)
        export_path.parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            data = [e.to_dict() for e in self._events]

        payload = {
            "application": "CipherNet Security Suite",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_records": len(data),
            "events": data,
        }

        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        return str(export_path.resolve())
