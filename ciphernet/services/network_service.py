"""
CipherNet Network Service
Retrieves cross-platform network interface states, active TCP/UDP connections,
traffic bandwidth rates, and optional packet capture via Scapy.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import socket
import time
from typing import Any, Dict, List, Optional, Tuple
import psutil


@dataclass
class NetworkInterfaceInfo:
    name: str
    is_up: bool
    speed_mbps: int = 0
    mtu: int = 0
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    mac_address: str = "N/A"
    netmask: str = "N/A"
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    errin: int = 0
    errout: int = 0
    dropin: int = 0
    dropout: int = 0


@dataclass
class ConnectionInfo:
    protocol: str  # TCP or UDP
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    pid: Optional[int] = None
    process_name: str = "N/A"
    remote_host: Optional[str] = None


class NetworkService:
    """Manages real-time network interface metrics and socket telemetry."""

    def __init__(self, resolve_hostnames: bool = False, show_loopback: bool = False) -> None:
        self.resolve_hostnames = resolve_hostnames
        self.show_loopback = show_loopback
        self._last_io = psutil.net_io_counters()
        self._last_time = time.time()
        self._tx_rate: float = 0.0  # bytes/sec
        self._rx_rate: float = 0.0  # bytes/sec
        self._tx_history: List[float] = [0.0] * 30
        self._rx_history: List[float] = [0.0] * 30
        self._dns_cache: Dict[str, str] = {}
        self._scapy_available: bool = False
        self._scapy_active: bool = False
        self._scapy_status_message: str = "Uninitialized"

        self._check_scapy_availability()

    def _check_scapy_availability(self) -> None:
        """Check if Scapy is installed and if raw socket access is permitted."""
        try:
            import scapy.all as _
            self._scapy_available = True
            self._scapy_status_message = "Scapy installed (Requires root for raw capture)"
        except ImportError:
            self._scapy_available = False
            self._scapy_status_message = "Scapy not installed"

    @property
    def is_scapy_available(self) -> bool:
        return self._scapy_available

    @property
    def scapy_status(self) -> str:
        return self._scapy_status_message

    def update_traffic_rates(self) -> Tuple[float, float]:
        """Calculates current Tx and Rx rates (bytes per second) and updates history."""
        current_time = time.time()
        try:
            current_io = psutil.net_io_counters()
        except Exception:
            return self._tx_rate, self._rx_rate

        time_delta = current_time - self._last_time
        if time_delta >= 0.2:  # Avoid division by zero or jitter
            tx_delta = max(0, current_io.bytes_sent - self._last_io.bytes_sent)
            rx_delta = max(0, current_io.bytes_recv - self._last_io.bytes_recv)

            self._tx_rate = tx_delta / time_delta
            self._rx_rate = rx_delta / time_delta

            self._last_io = current_io
            self._last_time = current_time

            self._tx_history.append(self._tx_rate)
            self._rx_history.append(self._rx_rate)
            if len(self._tx_history) > 30:
                self._tx_history = self._tx_history[-30:]
            if len(self._rx_history) > 30:
                self._rx_history = self._rx_history[-30:]

        return self._tx_rate, self._rx_rate

    @property
    def tx_rate(self) -> float:
        return self._tx_rate

    @property
    def rx_rate(self) -> float:
        return self._rx_rate

    @property
    def tx_history(self) -> List[float]:
        return list(self._tx_history)

    @property
    def rx_history(self) -> List[float]:
        return list(self._rx_history)

    def get_interfaces(self) -> List[NetworkInterfaceInfo]:
        """Gathers detailed information for all network interfaces."""
        interfaces: List[NetworkInterfaceInfo] = []
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            io_per_nic = psutil.net_io_counters(pernic=True)
        except Exception:
            return []

        # If user disabled loopback, but loopback is the only interface on system (e.g. containers),
        # allow loopback so interface list is never completely empty.
        available_names = list(addrs.keys())
        only_loopback = all(n.startswith("lo") or n == "loopback" for n in available_names)

        for name, addr_list in addrs.items():
            is_lo = name.startswith("lo") or name == "loopback"
            if not self.show_loopback and is_lo and not only_loopback:
                continue

            stat = stats.get(name)
            is_up = stat.isup if stat else False
            speed = stat.speed if stat else 0
            mtu = stat.mtu if stat else 0

            ipv4s = []
            ipv6s = []
            mac = "N/A"
            netmask = "N/A"

            for a in addr_list:
                # AF_INET is IPv4
                if a.family == socket.AF_INET:
                    ipv4s.append(a.address)
                    if a.netmask:
                        netmask = a.netmask
                # AF_INET6 is IPv6
                elif hasattr(socket, "AF_INET6") and a.family == socket.AF_INET6:
                    # Strip interface scope identifier if present
                    ipv6s.append(a.address.split("%")[0])
                # AF_LINK / AF_PACKET is MAC address
                elif hasattr(psutil, "AF_LINK") and a.family == psutil.AF_LINK:
                    mac = a.address or "N/A"

            nic_io = io_per_nic.get(name)

            interfaces.append(
                NetworkInterfaceInfo(
                    name=name,
                    is_up=is_up,
                    speed_mbps=speed,
                    mtu=mtu,
                    ipv4_addresses=ipv4s,
                    ipv6_addresses=ipv6s,
                    mac_address=mac,
                    netmask=netmask,
                    bytes_sent=nic_io.bytes_sent if nic_io else 0,
                    bytes_recv=nic_io.bytes_recv if nic_io else 0,
                    packets_sent=nic_io.packets_sent if nic_io else 0,
                    packets_recv=nic_io.packets_recv if nic_io else 0,
                    errin=nic_io.errin if nic_io else 0,
                    errout=nic_io.errout if nic_io else 0,
                    dropin=nic_io.dropin if nic_io else 0,
                    dropout=nic_io.dropout if nic_io else 0,
                )
            )

        return interfaces

    def get_primary_ip_and_host(self) -> Tuple[str, str]:
        """Finds primary local IPv4 address and system hostname."""
        hostname = socket.gethostname()
        local_ip = "127.0.0.1"
        s = None
        try:
            # Connect UDP socket to public DNS without sending packets to find route
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            # Fallback to interface scan
            for iface in self.get_interfaces():
                if iface.is_up and iface.ipv4_addresses:
                    local_ip = iface.ipv4_addresses[0]
                    break
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        return local_ip, hostname

    def get_connections(
        self,
        protocol_filter: str = "ALL",  # ALL, TCP, UDP
        state_filter: str = "ALL",     # ALL, ESTABLISHED, LISTEN, etc.
        search_filter: str = "",
    ) -> List[ConnectionInfo]:
        """
        Retrieves active network sockets and connections.
        Handles permission errors seamlessly.
        """
        connections: List[ConnectionInfo] = []

        try:
            # 'inet' returns both TCP and UDP
            net_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            try:
                # Fallback to tcp if full inet is restricted
                net_conns = psutil.net_connections(kind="tcp")
            except Exception:
                net_conns = []
        except Exception:
            net_conns = []

        proto_filter = protocol_filter.upper()
        st_filter = state_filter.upper()
        search = search_filter.lower().strip()

        for c in net_conns:
            # Determine protocol
            if c.type == socket.SOCK_STREAM:
                proto = "TCP"
            elif c.type == socket.SOCK_DGRAM:
                proto = "UDP"
            else:
                proto = "RAW"

            if proto_filter != "ALL" and proto != proto_filter:
                continue

            # Connection state
            state = c.status if c.status else ("OPEN" if proto == "UDP" else "UNKNOWN")
            if st_filter != "ALL" and state.upper() != st_filter:
                continue

            l_ip = c.laddr.ip if c.laddr else "*"
            l_port = c.laddr.port if c.laddr else 0
            r_ip = c.raddr.ip if c.raddr else "*"
            r_port = c.raddr.port if c.raddr else 0

            # Filter out loopback if requested
            if not self.show_loopback:
                if l_ip.startswith("127.") or r_ip.startswith("127."):
                    continue

            # Resolve Process Name safely
            pname = "N/A"
            if c.pid:
                try:
                    p = psutil.Process(c.pid)
                    pname = p.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pname = "Protected/Terminated"
                except Exception:
                    pname = "Unknown"

            # Optional Hostname lookup
            r_host = None
            if self.resolve_hostnames and r_ip not in ("*", "0.0.0.0", "::", "127.0.0.1"):
                if r_ip in self._dns_cache:
                    r_host = self._dns_cache[r_ip]
                else:
                    try:
                        # Quick cached lookup
                        r_host = socket.gethostbyaddr(r_ip)[0]
                        self._dns_cache[r_ip] = r_host
                    except Exception:
                        self._dns_cache[r_ip] = r_ip
                        r_host = r_ip

            # Text Search Filter
            if search:
                matched = (
                    search in l_ip.lower()
                    or search in str(l_port)
                    or search in r_ip.lower()
                    or search in str(r_port)
                    or search in state.lower()
                    or search in pname.lower()
                    or (r_host and search in r_host.lower())
                )
                if not matched:
                    continue

            connections.append(
                ConnectionInfo(
                    protocol=proto,
                    local_ip=l_ip,
                    local_port=l_port,
                    remote_ip=r_ip,
                    remote_port=r_port,
                    state=state,
                    pid=c.pid,
                    process_name=pname,
                    remote_host=r_host,
                )
            )

        return connections

    def get_summary_stats(self) -> Dict[str, Any]:
        """Provides quick aggregate metrics for dashboard."""
        try:
            conns = self.get_connections()
        except Exception:
            conns = []

        tcp_count = sum(1 for c in conns if c.protocol == "TCP")
        udp_count = sum(1 for c in conns if c.protocol == "UDP")
        listen_count = sum(1 for c in conns if c.state == "LISTEN")
        estab_count = sum(1 for c in conns if c.state == "ESTABLISHED")

        local_ip, hostname = self.get_primary_ip_and_host()

        return {
            "hostname": hostname,
            "local_ip": local_ip,
            "total_connections": len(conns),
            "tcp_count": tcp_count,
            "udp_count": udp_count,
            "listening_count": listen_count,
            "established_count": estab_count,
            "tx_rate": self._tx_rate,
            "rx_rate": self._rx_rate,
        }

    @staticmethod
    def format_bytes(num_bytes: float) -> str:
        """Formats raw byte counts into human-readable strings."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:3.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} PB"

    @staticmethod
    def format_rate(bytes_per_sec: float) -> str:
        """Formats transfer rate into human-readable string."""
        return f"{NetworkService.format_bytes(bytes_per_sec)}/s"
