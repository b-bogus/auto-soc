from datetime import datetime
from typing import Literal
from pydantic import BaseModel

class WindowsProcess(BaseModel):
    """A running process on a simulated Windows endpoint."""
    pid: int
    ppid: int                          # Parent PID
    name: str                          # e.g. "svchost.exe"
    exe_path: str                      # e.g. "C:\\Windows\\System32\\svchost.exe"
    command_line: str                   # Full command line
    user: str                          # e.g. "NT AUTHORITY\\SYSTEM"
    started_at: datetime
    sha256: str | None = None                 # File hash (None for system processes)

class NetworkConnection(BaseModel):
    """An active or completed network connection."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: Literal["tcp", "udp"]
    state: Literal["established", "closed", "syn_sent", "time_wait"]
    process_name: str                  # Process that owns this connection
    bytes_sent: int
    bytes_received: int

class WindowsEndpoint(BaseModel):
    """Full state of a simulated Windows workstation or server."""
    hostname: str                      # e.g. "WKSTN-042"
    os_version: str                    # e.g. "Windows 11 23H2"
    role: Literal["workstation", "server", "domain_controller"]
    ip_address: str
    mac_address: str
    domain: str                        # e.g. "CORP.LOCAL"
    logged_in_users: list[str]         # Currently logged-in users
    processes: list[WindowsProcess]
    active_connections: list[NetworkConnection]

class SystemEmulatorConfig(BaseModel):
    """Configuration for the system emulation."""
    endpoint_count: int = 5            # Number of endpoints to simulate
    events_per_cycle: int = 50         # Events generated per emulation cycle
    cycle_duration_minutes: int = 15   # Simulated time per cycle
    roles: list[Literal["workstation", "server", "domain_controller"]] = [
        "workstation", "workstation", "workstation",
        "server", "domain_controller"
    ]
    event_weights: dict[str, float] = {
        "process_start": 0.20,
        "process_stop": 0.10,
        "network_connection": 0.15,
        "file_operation": 0.12,
        "registry_modification": 0.05,
        "user_logon": 0.08,
        "user_logoff": 0.03,
        "service_state_change": 0.04,
        "scheduled_task_run": 0.05,
        "windows_update": 0.03,
        "dns_query": 0.10,
        "defender_scan": 0.03,
        "usb_device": 0.02,
    }
