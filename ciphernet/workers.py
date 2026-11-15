"""
CipherNet Background Asynchronous Workers
Ensures the PySide6 GUI remains responsive and never freezes during
expensive system calls, network socket polling, RSA key generation,
or large file checksum computation.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Optional
from PySide6.QtCore import QObject, QThread, Signal

from ciphernet.services.crypto_service import CryptoService
from ciphernet.services.network_service import ConnectionInfo, NetworkInterfaceInfo, NetworkService


class NetworkTelemetryWorker(QThread):
    """
    Background worker thread for polling network telemetry,
    calculating bandwidth rates, scanning interfaces, and resolving sockets.
    """
    data_ready = Signal(dict, list, list)  # (summary_stats, interfaces, connections)
    error_occurred = Signal(str)

    def __init__(
        self,
        network_service: NetworkService,
        protocol_filter: str = "ALL",
        state_filter: str = "ALL",
        search_filter: str = "",
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self.network_service = network_service
        self.protocol_filter = protocol_filter
        self.state_filter = state_filter
        self.search_filter = search_filter

    def run(self) -> None:
        try:
            self.network_service.update_traffic_rates()
            stats = self.network_service.get_summary_stats()
            ifaces = self.network_service.get_interfaces()
            conns = self.network_service.get_connections(
                protocol_filter=self.protocol_filter,
                state_filter=self.state_filter,
                search_filter=self.search_filter,
            )
            self.data_ready.emit(stats, ifaces, conns)
        except Exception as ex:
            self.error_occurred.emit(str(ex))


class RsaKeyGenWorker(QThread):
    """
    Background worker thread for generating 2048/4096-bit RSA key pairs
    without stalling the UI.
    """
    keypair_generated = Signal(dict)
    error_occurred = Signal(str)

    def __init__(
        self,
        crypto_service: CryptoService,
        key_size: int = 2048,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self.crypto_service = crypto_service
        self.key_size = key_size

    def run(self) -> None:
        try:
            res = self.crypto_service.generate_rsa_keypair(self.key_size)
            self.keypair_generated.emit(res)
        except Exception as ex:
            self.error_occurred.emit(str(ex))


class FileIntegrityWorker(QThread):
    """
    Background worker thread for streaming file chunks to compute cryptographic digests.
    """
    verification_done = Signal(dict)
    error_occurred = Signal(str)

    def __init__(
        self,
        crypto_service: CryptoService,
        file_path: str,
        expected_hash: str,
        algorithm: str = "SHA-256",
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self.crypto_service = crypto_service
        self.file_path = file_path
        self.expected_hash = expected_hash
        self.algorithm = algorithm

    def run(self) -> None:
        try:
            res = self.crypto_service.verify_file_integrity(
                file_path=self.file_path,
                expected_hash=self.expected_hash,
                algorithm=self.algorithm,
            )
            self.verification_done.emit(res)
        except Exception as ex:
            self.error_occurred.emit(str(ex))
