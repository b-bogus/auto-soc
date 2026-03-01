import random
import uuid
from datetime import datetime, timedelta, timezone
from auto_soc.models.system_emulator import (
    WindowsEndpoint, WindowsProcess, NetworkConnection, SystemEmulatorConfig
)
from auto_soc.models.siem import SIEMEvent
from auto_soc.stores.system_emulator_store import SystemEmulatorStore


_COMMON_PROCESSES = [
    ("chrome.exe",  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
    ("explorer.exe","C:\\Windows\\explorer.exe"),
    ("cmd.exe",     "C:\\Windows\\System32\\cmd.exe"),
    ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    ("winword.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
    ("Teams.exe",   "C:\\Users\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"),
]

_COMMON_DOMAINS = [
    "google.com", "microsoft.com", "windowsupdate.com",
    "office365.com", "teams.microsoft.com", "api.github.com",
    "ocsp.digicert.com", "ctldl.windowsupdate.com",
]


class SystemEmulator:
    """Plain Python class. Generates realistic Windows OS telemetry. No LLM needed."""

    def __init__(self, config: SystemEmulatorConfig):
        self.store = SystemEmulatorStore()
        self.config = config

    def initialize(self) -> list[WindowsEndpoint]:
        """Bootstrap N endpoints with OS version, domain, users, and base processes."""
        for i in range(self.config.endpoint_count):
            role = self.config.roles[i % len(self.config.roles)]
            hostname = (
                f"WKSTN-{i+1:03d}" if role == "workstation"
                else f"DC-{i+1:03d}" if role == "domain_controller"
                else f"SRV-{i+1:03d}"
            )
            users = [f"CORP\\user{i+1}"] if role in ("workstation",) else []

            sys_proc = WindowsProcess(
                pid=4, ppid=0, name="System",
                exe_path="System", command_line="System",
                user="NT AUTHORITY\\SYSTEM",
                started_at=self.store.current_time - timedelta(days=random.randint(1, 30))
            )
            lsass = WindowsProcess(
                pid=random.randint(500, 900), ppid=4,
                name="lsass.exe",
                exe_path="C:\\Windows\\System32\\lsass.exe",
                command_line="C:\\Windows\\system32\\lsass.exe",
                user="NT AUTHORITY\\SYSTEM",
                started_at=self.store.current_time - timedelta(days=random.randint(1, 30))
            )

            endpoint = WindowsEndpoint(
                hostname=hostname,
                os_version="Windows 11 23H2" if role == "workstation" else "Windows Server 2022",
                role=role,
                ip_address=f"10.0.1.{100 + i}",
                mac_address=f"00:1A:2B:3C:4D:{i:02X}",
                domain="CORP.LOCAL",
                logged_in_users=users,
                processes=[sys_proc, lsass],
                active_connections=[]
            )
            self.store.endpoints[hostname] = endpoint

        return list(self.store.endpoints.values())

    def run_cycle(self) -> list[SIEMEvent]:
        """Generate one cycle of OS events across all endpoints. Updates endpoint state."""
        self.store.current_time += timedelta(minutes=self.config.cycle_duration_minutes)
        self.store.cycle_count += 1

        all_events: list[SIEMEvent] = []
        event_types = list(self.config.event_weights.keys())
        weights = list(self.config.event_weights.values())
        events_per_endpoint = max(1, self.config.events_per_cycle // max(1, len(self.store.endpoints)))

        for hostname, endpoint in self.store.endpoints.items():
            for _ in range(events_per_endpoint):
                event_type = random.choices(event_types, weights=weights, k=1)[0]
                ts = self.store.current_time + timedelta(
                    seconds=random.randint(0, self.config.cycle_duration_minutes * 60)
                )
                event = self._generate_event(endpoint, event_type, ts)
                if event:
                    all_events.append(event)

        self.store.generated_events.extend(all_events)
        return all_events

    def _generate_event(
        self, endpoint: WindowsEndpoint, event_type: str, ts: datetime
    ) -> SIEMEvent | None:
        eid = str(uuid.uuid4())
        user = endpoint.logged_in_users[0] if endpoint.logged_in_users else "NT AUTHORITY\\SYSTEM"

        if event_type == "process_start":
            proc_name, exe_path = random.choice(_COMMON_PROCESSES)
            new_pid = random.randint(1000, 65535)
            parent = random.choice(endpoint.processes) if endpoint.processes else None
            ppid = parent.pid if parent else 4

            proc = WindowsProcess(
                pid=new_pid, ppid=ppid, name=proc_name,
                exe_path=exe_path, command_line=f'"{exe_path}"',
                user=user, started_at=ts
            )
            endpoint.processes.append(proc)

            return SIEMEvent(
                event_id=eid, timestamp=ts, source_system="edr", severity="info",
                raw_log=(
                    f"EventID=4688 ProcessCreate: {proc_name} PID={new_pid} "
                    f"PPID={ppid} User={user} Host={endpoint.hostname}"
                ),
                parsed_fields={
                    "action": "process_create", "hostname": endpoint.hostname,
                    "user": user, "process_name": proc_name, "exe_path": exe_path,
                    "pid": new_pid, "ppid": ppid, "src_ip": endpoint.ip_address,
                }
            )

        elif event_type == "process_stop":
            if len(endpoint.processes) <= 2:  # Keep System + lsass alive
                return None
            proc = random.choice(endpoint.processes[2:])
            endpoint.processes.remove(proc)

            return SIEMEvent(
                event_id=eid, timestamp=ts, source_system="edr", severity="info",
                raw_log=f"EventID=4689 ProcessTerminate: {proc.name} PID={proc.pid} Host={endpoint.hostname}",
                parsed_fields={
                    "action": "process_terminate", "hostname": endpoint.hostname,
                    "process_name": proc.name, "pid": proc.pid, "src_ip": endpoint.ip_address,
                }
            )

        elif event_type == "network_connection":
            if not endpoint.processes:
                return None
            proc = random.choice(endpoint.processes)
            dst_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            port = random.choice([443, 443, 443, 80, 8080])

            conn = NetworkConnection(
                src_ip=endpoint.ip_address, src_port=random.randint(10000, 60000),
                dst_ip=dst_ip, dst_port=port, protocol="tcp",
                state="established", process_name=proc.name,
                bytes_sent=random.randint(200, 5000),
                bytes_received=random.randint(500, 50000)
            )
            endpoint.active_connections.append(conn)

            return SIEMEvent(
                event_id=eid, timestamp=ts, source_system="firewall", severity="info",
                raw_log=(
                    f"ALLOW TCP {endpoint.ip_address}:{conn.src_port} -> {dst_ip}:{port} "
                    f"proc={proc.name} host={endpoint.hostname}"
                ),
                parsed_fields={
                    "action": "network_connect", "hostname": endpoint.hostname,
                    "src_ip": endpoint.ip_address, "dst_ip": dst_ip, "dst_port": port,
                    "protocol": "tcp", "process_name": proc.name,
                }
            )

        elif event_type == "dns_query":
            proc = random.choice(endpoint.processes) if endpoint.processes else None
            domain = random.choice(_COMMON_DOMAINS)

            return SIEMEvent(
                event_id=eid, timestamp=ts, source_system="dns", severity="info",
                raw_log=f"DNS QUERY {domain} A from {endpoint.ip_address}",
                parsed_fields={
                    "action": "dns_query", "hostname": endpoint.hostname,
                    "domain": domain, "query_type": "A",
                    "src_ip": endpoint.ip_address,
                    "process_name": proc.name if proc else None,
                }
            )

        elif event_type == "user_logon":
            return SIEMEvent(
                event_id=eid, timestamp=ts, source_system="auth", severity="info",
                raw_log=f"EventID=4624 Logon: User={user} Host={endpoint.hostname} Type=Interactive",
                parsed_fields={
                    "action": "user_logon", "hostname": endpoint.hostname,
                    "user": user, "logon_type": "Interactive",
                    "src_ip": endpoint.ip_address,
                }
            )

        elif event_type == "user_logoff":
            return SIEMEvent(
                event_id=eid, timestamp=ts, source_system="auth", severity="info",
                raw_log=f"EventID=4634 Logoff: User={user} Host={endpoint.hostname}",
                parsed_fields={
                    "action": "user_logoff", "hostname": endpoint.hostname,
                    "user": user, "src_ip": endpoint.ip_address,
                }
            )

        elif event_type == "file_operation":
            proc = random.choice(endpoint.processes) if endpoint.processes else None
            path = random.choice([
                "C:\\Users\\Documents\\report.docx",
                "C:\\Windows\\Temp\\tmp_file.dat",
                "C:\\Program Files\\update.msi",
            ])
            op = random.choice(["ReadFile", "WriteFile", "CreateFile"])
            return SIEMEvent(
                event_id=eid, timestamp=ts, source_system="edr", severity="info",
                raw_log=f"FileSystem {op}: {path} by {proc.name if proc else 'System'} on {endpoint.hostname}",
                parsed_fields={
                    "action": op.lower(), "hostname": endpoint.hostname,
                    "file_path": path, "process_name": proc.name if proc else "System",
                    "src_ip": endpoint.ip_address,
                }
            )

        else:
            # Generic fallback for remaining event types
            return SIEMEvent(
                event_id=eid, timestamp=ts, source_system="edr", severity="info",
                raw_log=f"OS Event: {event_type} on {endpoint.hostname}",
                parsed_fields={
                    "action": event_type, "hostname": endpoint.hostname,
                    "src_ip": endpoint.ip_address,
                }
            )

    def get_endpoint(self, hostname: str) -> WindowsEndpoint | None:
        return self.store.get_endpoint(hostname)

    def get_endpoints(self) -> list[WindowsEndpoint]:
        return list(self.store.endpoints.values())
