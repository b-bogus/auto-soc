"""
RedTeamAgent — autonomous PydanticAI Agent.

The LLM is given the current IOC/TTP watchlist and the available endpoints,
and autonomously decides how to structure a multi-phase attack scenario.
It uses tools to inspect the environment and inject attack events into the SIEM.
"""
import uuid
import random
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field

from pydantic_ai import Agent, RunContext
from auto_soc.utils.ollama_model import make_model
from auto_soc.config import settings

from auto_soc.models.siem import SIEMEvent
from auto_soc.models.red_team import AttackPhase, AttackScenario, RedTeamConfig


@dataclass
class RedTeamDeps:
    """Dependencies injected into every tool call."""
    threat_intel_watchlist: dict        # {"iocs": list[IOC], "ttps": list[TTP]}
    siem_ingest_fn: object              # callable: siem.ingest_batch(events)
    available_endpoints: list[dict]     # [{"hostname": ..., "ip": ..., "role": ...}]
    config: RedTeamConfig
    scenarios: list[AttackScenario]     # populated by the agent during its run
    staged_phases: list[dict] = field(default_factory=list)  # buffer: {mitre_id, description, events}


red_team_agent = Agent(
    make_model(),
    deps_type=RedTeamDeps,
    output_type=str,
    retries=3,
    system_prompt="""You are a Red Team Operator executing an adversary simulation.
You MUST follow these exact steps by calling the tools in order:

STEP 1: Call get_watchlist() to retrieve available IOCs and TTPs.
STEP 2: Call get_available_targets() to retrieve available endpoints.
STEP 3: Call generate_attack_events() for each attack phase, using a real IOC value from Step 1 and a real hostname from Step 2.
STEP 4: Call inject_scenario() with only the scenario_name and target_endpoint. Events are assembled automatically from your generate_attack_events calls — do NOT pass events.

DO NOT describe your plan in text. DO NOT skip any step. Execute all 4 steps by calling the tools.
After inject_scenario() is called, briefly summarize what you did in one sentence.""",
)


@red_team_agent.tool
async def get_watchlist(ctx: RunContext[RedTeamDeps]) -> dict:
    """Fetch current IOC and TTP watchlist. Returns {"iocs": [...], "ttps": [...]}."""
    wl = ctx.deps.threat_intel_watchlist
    return {
        "iocs": [
            {"id": ioc.id, "type": ioc.type, "value": ioc.value,
             "severity": ioc.severity, "tags": ioc.tags}
            for ioc in wl.get("iocs", [])
        ],
        "ttps": [
            {"id": ttp.id, "mitre_id": ttp.mitre_id, "name": ttp.name,
             "tactic": ttp.tactic}
            for ttp in wl.get("ttps", [])
        ],
    }


@red_team_agent.tool
async def get_available_targets(ctx: RunContext[RedTeamDeps]) -> list[dict]:
    """Return the list of simulated endpoints that can be targeted."""
    return ctx.deps.available_endpoints


@red_team_agent.tool
async def generate_attack_events(
    ctx: RunContext[RedTeamDeps],
    mitre_id: str,
    target_hostname: str,
    target_ip: str,
    ioc_value: str,
    ioc_type: str,
    description: str,
) -> dict:
    """
    Generate realistic SIEMEvents for one attack phase and stage them for injection.
    Returns a confirmation dict. The agent calls this once per phase.
    """
    ts = datetime.now(timezone.utc)
    events = []

    # Map MITRE tactic to realistic event pattern
    if mitre_id.startswith("T1566"):  # Phishing / Initial Access
        if ioc_type == "email":
            sender = ioc_value
            extra_fields = {"src_email": ioc_value}
        elif ioc_type == "domain":
            sender = f"spoofed-sender@{ioc_value}"
            extra_fields = {"domain": ioc_value}
        else:
            sender = "spoofed-sender@evil.com"
            extra_fields = {}
        events.append(_make_event(
            source="email_gateway", severity="high", ts=ts,
            raw=f"DELIVERED phish email with attachment to {target_hostname} from {sender}",
            fields={"action": "email_delivered", "hostname": target_hostname,
                    "src_ip": target_ip, "user": "CORP\\user1", **extra_fields}
        ))
    elif mitre_id.startswith("T1059"):  # Script Execution
        events.append(_make_event(
            source="edr", severity="high", ts=ts + timedelta(seconds=5),
            raw=f"EventID=4688 ProcessCreate: powershell.exe -enc JABhAD0A... PID=9999 Host={target_hostname}",
            fields={"action": "process_create", "hostname": target_hostname,
                    "src_ip": target_ip, "process_name": "powershell.exe",
                    "user": "CORP\\user1", "file_hash": ioc_value if ioc_type == "sha256" else None}
        ))
    elif mitre_id.startswith("T1071"):  # C2 Communication
        c2_ip = ioc_value if ioc_type == "ipv4" else "203.0.113.42"
        c2_domain = ioc_value if ioc_type == "domain" else None
        events.append(_make_event(
            source="firewall", severity="high", ts=ts + timedelta(seconds=15),
            raw=f"ALLOW TCP {target_ip}:49201 -> {c2_ip}:443 proc=powershell.exe host={target_hostname}",
            fields={"action": "network_connect", "hostname": target_hostname,
                    "src_ip": target_ip, "dst_ip": c2_ip, "dst_port": 443,
                    "process_name": "powershell.exe", "domain": c2_domain}
        ))
        if c2_domain:
            events.append(_make_event(
                source="dns", severity="medium", ts=ts + timedelta(seconds=14),
                raw=f"DNS QUERY {c2_domain} A from {target_ip}",
                fields={"action": "dns_query", "hostname": target_hostname,
                        "src_ip": target_ip, "domain": c2_domain}
            ))
    elif mitre_id.startswith("T1486"):  # Ransomware / Impact
        events.append(_make_event(
            source="edr", severity="critical", ts=ts + timedelta(seconds=30),
            raw=f"FileSystem MassEncrypt: C:\\Users\\* by vssadmin.exe on {target_hostname}",
            fields={"action": "mass_file_encrypt", "hostname": target_hostname,
                    "src_ip": target_ip, "process_name": "vssadmin.exe",
                    "file_hash": ioc_value if ioc_type == "sha256" else None}
        ))
    else:
        # Generic fallback for any other MITRE technique
        events.append(_make_event(
            source="edr", severity="medium", ts=ts,
            raw=f"Suspicious activity ({mitre_id}): {description} on {target_hostname}",
            fields={"action": "suspicious_activity", "hostname": target_hostname,
                    "src_ip": target_ip, "dst_ip": ioc_value if ioc_type == "ipv4" else None,
                    "domain": ioc_value if ioc_type == "domain" else None}
        ))

    ctx.deps.staged_phases.append({
        "mitre_id": mitre_id,
        "description": description,
        "events": events,
    })
    return {"staged": True, "phase_index": len(ctx.deps.staged_phases) - 1, "event_count": len(events)}


@red_team_agent.tool
async def inject_scenario(
    ctx: RunContext[RedTeamDeps],
    scenario_name: str,
    target_endpoint: str,
) -> dict:
    """
    Inject a complete attack scenario into the SIEM using all staged phases from
    previous generate_attack_events calls.
    Returns {"scenario_id": ..., "events_injected": int, "phases": int}.
    """
    scenario_id = str(uuid.uuid4())
    all_events: list[SIEMEvent] = []
    attack_phases: list[AttackPhase] = []

    for i, phase_dict in enumerate(ctx.deps.staged_phases):
        phase_events = phase_dict["events"]
        all_events.extend(phase_events)
        attack_phases.append(AttackPhase(
            order=i + 1,
            mitre_id=phase_dict["mitre_id"],
            description=phase_dict["description"],
            target_endpoint=target_endpoint,
            generated_events=[e.model_dump(mode="json") for e in phase_events],
        ))

    # Inject into SIEM
    ctx.deps.siem_ingest_fn(all_events)

    # Store the scenario
    scenario = AttackScenario(
        scenario_id=scenario_id,
        name=scenario_name,
        phases=attack_phases,
    )
    ctx.deps.scenarios.append(scenario)

    return {
        "scenario_id": scenario_id,
        "events_injected": len(all_events),
        "phases": len(attack_phases),
    }


@red_team_agent.tool
async def get_detection_report(ctx: RunContext[RedTeamDeps], scenario_id: str) -> dict:
    """
    Return a post-injection summary: how many events were injected for this scenario.
    Full detection rate is computed by the Orchestrator after correlation runs.
    """
    for scenario in ctx.deps.scenarios:
        if scenario.scenario_id == scenario_id:
            total_events = sum(len(p.generated_events) for p in scenario.phases)
            return {
                "scenario_id": scenario_id,
                "name": scenario.name,
                "phases": len(scenario.phases),
                "events_injected": total_events,
                "note": "Run SIEM correlation to determine detection rate.",
            }
    return {"error": f"Scenario {scenario_id} not found."}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_event(
    source: str, severity: str, ts: datetime, raw: str, fields: dict
) -> SIEMEvent:
    return SIEMEvent(
        timestamp=ts,
        source_system=source,
        severity=severity,
        raw_log=raw,
        parsed_fields={k: v for k, v in fields.items() if v is not None},
    )
