import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from pathlib import Path

# Load .env BEFORE importing PydanticAI — the Agent constructor reads GOOGLE_API_KEY from os.environ
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from pydantic_ai import Agent, RunContext
from auto_soc.config import settings
from auto_soc.models.siem import SIEMEvent
from auto_soc.models.system_emulator import (
    WindowsEndpoint, 
    SystemEmulatorConfig, 
    WindowsProcess,
    NetworkConnection
)
from auto_soc.stores.system_emulator_store import SystemEmulatorStore

@dataclass
class SystemEmulatorDeps:
    store: SystemEmulatorStore
    config: SystemEmulatorConfig

# Initialize the agent with the API key from settings if available
system_emulator_agent = Agent(
    "google-gla:gemini-3.1-pro",
    deps_type=SystemEmulatorDeps,
    output_type=list[SIEMEvent],
    system_prompt=(
        "You are a System Emulator. Given the current state of a Windows endpoint, "
        "decide what OS events should happen next (process execution, network connections) "
        "and generate realistic SIEMEvents simulating background noise."
    ),
)


def _generate_event_id() -> str:
    return str(uuid.uuid4())

def _get_random_ip() -> str:
    """Generate a realistic looking IP address for external connections."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

@system_emulator_agent.tool
async def initialize_endpoints(ctx: RunContext[SystemEmulatorDeps]) -> list[WindowsEndpoint]:
    """Bootstrap N endpoints with OS, services, users, and initial process trees."""
    store = ctx.deps.store
    config = ctx.deps.config
    
    endpoints = []
    for i in range(config.endpoint_count):
        role = config.roles[i % len(config.roles)]
        hostname = f"WKSTN-{i+1:03d}" if role == "workstation" else f"SRV-{i+1:03d}"
        
        # Build an initial SYSTEM idle process
        sys_proc = WindowsProcess(
            pid=4,
            ppid=0,
            name="System",
            exe_path="System",
            command_line="System",
            user="NT AUTHORITY\\SYSTEM",
            started_at=store.current_time - timedelta(days=random.randint(1, 30))
        )
        
        # Log in a default user for workstations
        users = [f"CORP\\user{i+1}"] if role == "workstation" else []
        
        endpoint = WindowsEndpoint(
            hostname=hostname,
            os_version="Windows 11 23H2" if role == "workstation" else "Windows Server 2022",
            role=role,
            ip_address=f"10.0.1.{100+i}",
            mac_address=f"00:1A:2B:3C:4D:{i:02X}",
            domain="CORP.LOCAL",
            logged_in_users=users,
            processes=[sys_proc],
            active_connections=[]
        )
        store.endpoints[hostname] = endpoint
        endpoints.append(endpoint)
        
    return endpoints

@system_emulator_agent.tool
async def run_emulation_cycle(ctx: RunContext[SystemEmulatorDeps], endpoint_hostname: str) -> list[SIEMEvent]:
    """Generate one cycle of OS events for a specific endpoint. Updates endpoint state."""
    store = ctx.deps.store
    config = ctx.deps.config
    endpoint = store.get_endpoint(endpoint_hostname)
    
    if not endpoint:
        raise ValueError(f"Endpoint {endpoint_hostname} not found")

    new_events = []
    
    # Simple simulation logic for v1: randomly pick event types based on weights
    event_types = list(config.event_weights.keys())
    weights = list(config.event_weights.values())
    
    for _ in range(config.events_per_cycle // config.endpoint_count):
        event_type = random.choices(event_types, weights=weights, k=1)[0]
        timestamp = store.current_time + timedelta(seconds=random.randint(0, config.cycle_duration_minutes * 60))
        
        if event_type == "process_start":
            user = endpoint.logged_in_users[0] if endpoint.logged_in_users else "NT AUTHORITY\\SYSTEM"
            proc_name = random.choice(["chrome.exe", "svchost.exe", "outlook.exe", "cmd.exe"])
            new_pid = random.randint(1000, 9999)
            
            proc = WindowsProcess(
                pid=new_pid,
                ppid=4, # parent is System for simplicity in this stub
                name=proc_name,
                exe_path=f"C:\\Windows\\System32\\{proc_name}",
                command_line=f"{proc_name}",
                user=user,
                started_at=timestamp
            )
            endpoint.processes.append(proc)
            
            event = SIEMEvent(
                event_id=_generate_event_id(),
                timestamp=timestamp,
                source_system="edr",
                severity="info",
                raw_log=f"Process Create: {proc_name} pid={new_pid} user={user}",
                parsed_fields={
                    "action": "process_create",
                    "hostname": endpoint.hostname,
                    "user": user,
                    "process_name": proc_name,
                    "exe_path": proc.exe_path,
                    "pid": new_pid,
                    "ppid": 4,
                }
            )
            new_events.append(event)
            
        elif event_type == "network_connection":
            if not endpoint.processes:
                continue
            proc = random.choice(endpoint.processes)
            dst_ip = _get_random_ip()
            port = random.choice([443, 80, 8080, 53])
            
            conn = NetworkConnection(
                src_ip=endpoint.ip_address,
                src_port=random.randint(10000, 60000),
                dst_ip=dst_ip,
                dst_port=port,
                protocol="tcp" if port != 53 else "udp",
                state="established",
                process_name=proc.name,
                bytes_sent=random.randint(100, 5000),
                bytes_received=random.randint(100, 50000)
            )
            endpoint.active_connections.append(conn)
            
            event = SIEMEvent(
                event_id=_generate_event_id(),
                timestamp=timestamp,
                source_system="firewall",
                severity="info",
                raw_log=f"Network Connect: {proc.name} -> {dst_ip}:{port}",
                parsed_fields={
                    "action": "network_connect",
                    "hostname": endpoint.hostname,
                    "src_ip": conn.src_ip,
                    "dst_ip": conn.dst_ip,
                    "dst_port": conn.dst_port,
                    "protocol": conn.protocol,
                    "process_name": conn.process_name
                }
            )
            new_events.append(event)
            
        elif event_type == "dns_query":
             if not endpoint.processes:
                continue
             proc = random.choice(endpoint.processes)
             domain = random.choice(["google.com", "microsoft.com", "api.github.com", "windowsupdate.com"])
             
             event = SIEMEvent(
                event_id=_generate_event_id(),
                timestamp=timestamp,
                source_system="dns",
                severity="info",
                raw_log=f"DNS Query: {domain} by {proc.name}",
                parsed_fields={
                    "action": "dns_query",
                    "hostname": endpoint.hostname,
                    "query_name": domain,
                    "process_name": proc.name,
                    "query_type": "A"
                }
            )
             new_events.append(event)
             
        # Add basic fallbacks for other event types to avoid crashing
        else:
             event = SIEMEvent(
                event_id=_generate_event_id(),
                timestamp=timestamp,
                source_system="os_telemetry",
                severity="info",
                raw_log=f"OS Event: {event_type}",
                parsed_fields={
                    "action": event_type,
                    "hostname": endpoint.hostname,
                }
            )
             new_events.append(event)
             
    store.generated_events.extend(new_events)
    return new_events

@system_emulator_agent.tool
async def run_all_endpoints_cycle(ctx: RunContext[SystemEmulatorDeps]) -> list[SIEMEvent]:
    """Generate one cycle of OS events across all endpoints."""
    all_events = []
    
    # Advance time at the start of a cycle
    ctx.deps.store.current_time += timedelta(minutes=ctx.deps.config.cycle_duration_minutes)
    ctx.deps.store.cycle_count += 1
    
    for hostname in ctx.deps.store.endpoints.keys():
        events = await run_emulation_cycle(ctx, endpoint_hostname=hostname)
        all_events.extend(events)
        
    return all_events

@system_emulator_agent.tool
async def get_endpoint_state(ctx: RunContext[SystemEmulatorDeps], hostname: str) -> WindowsEndpoint:
    """Retrieve current state for an endpoint."""
    endpoint = ctx.deps.store.get_endpoint(hostname)
    if not endpoint:
        raise ValueError(f"Endpoint {hostname} not found")
    return endpoint

@system_emulator_agent.tool
async def inject_os_events(ctx: RunContext[SystemEmulatorDeps], events: list[SIEMEvent]) -> list[str]:
    """Push generated OS events into the SIEM event store. (In simulation, we return their IDs)"""
    # In a full run, this would interface with SIEMStore. For now, it's a pass-through.
    return [e.event_id for e in events]
