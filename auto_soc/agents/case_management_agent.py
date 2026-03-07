"""
CaseManagementAgent — autonomous PydanticAI Agent.

Given a SIEMAlert, the agent autonomously:
  1. Fetches the triggering events and surrounding context from the SIEM
  2. Looks up IOC/TTP details from ThreatIntel
  3. Weighs evidence and forms a hypothesis
  4. Returns structured AnalystReasoning with verdict + recommended actions
"""
from dataclasses import dataclass

from pydantic_ai import Agent, RunContext
from auto_soc.utils.ollama_model import make_ollama_model
from auto_soc.config import settings

from auto_soc.models.siem import SIEMAlert, SIEMEvent
from auto_soc.models.threat_intel import IOC, TTP
from auto_soc.models.case_management import AnalystReasoning, MitigationAction, Incident


@dataclass
class CaseManagementDeps:
    """Dependencies injected into every tool call."""
    alert: SIEMAlert
    siem_store: object          # SIEM instance (has .events_by_id, .get_event_context())
    threat_intel: object        # ThreatIntel instance (has .get_ioc(), .get_ttp())
    incidents: list[Incident]   # Running list, appended to by the Orchestrator


case_management_agent = Agent(
    make_ollama_model(),
    deps_type=CaseManagementDeps,
    output_type=AnalystReasoning,
    system_prompt="""You are a Tier 2 SOC Analyst at a financial institution.
You receive a SIEM alert and must determine whether it is a true positive or false positive.

Your workflow:
1. Call get_alert_events() to see the events that triggered the alert
2. Call get_event_context() on the most suspicious event to gather surrounding activity
3. Call get_ioc_details() to understand the threat context of involved IOCs
4. Weigh evidence for and against your hypothesis
5. Return a structured AnalystReasoning with verdict and recommended_actions

Be specific in evidence_for and evidence_against — cite hostnames, IPs, process names.
For true_positive verdict, always include at least one concrete MitigationAction.""",
)


@case_management_agent.tool
async def get_alert_events(ctx: RunContext[CaseManagementDeps]) -> list[dict]:
    """Fetch all SIEM events that triggered this alert."""
    store = ctx.deps.siem_store
    events = []
    for event_id in ctx.deps.alert.matched_events:
        event = store.events_by_id.get(event_id)
        if event:
            events.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "source_system": event.source_system,
                "severity": event.severity,
                "raw_log": event.raw_log,
                "parsed_fields": event.parsed_fields,
                "matched_ioc_ids": event.matched_ioc_ids,
            })
    return events


@case_management_agent.tool
async def get_event_context(
    ctx: RunContext[CaseManagementDeps],
    event_id: str,
    window_seconds: int = 300,
) -> list[dict]:
    """Get surrounding events on the same hostname within a time window."""
    store = ctx.deps.siem_store
    events = store.get_event_context(event_id, window_seconds)
    return [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat(),
            "source_system": e.source_system,
            "raw_log": e.raw_log,
            "parsed_fields": e.parsed_fields,
        }
        for e in events[:20]   # Cap context at 20 to avoid token overflow
    ]


@case_management_agent.tool
async def get_ioc_details(
    ctx: RunContext[CaseManagementDeps],
    ioc_ids: list[str],
) -> list[dict]:
    """Fetch IOC context from ThreatIntel for a list of IOC IDs."""
    ti = ctx.deps.threat_intel
    results = []
    for ioc_id in ioc_ids:
        ioc = ti.get_ioc(ioc_id)
        if ioc:
            results.append({
                "id": ioc.id,
                "type": ioc.type,
                "value": ioc.value,
                "severity": ioc.severity,
                "tags": ioc.tags,
                "confidence": ioc.confidence,
                "context": ioc.context,
            })
    return results


@case_management_agent.tool
async def get_ttp_details(
    ctx: RunContext[CaseManagementDeps],
    ttp_ids: list[str],
) -> list[dict]:
    """Fetch TTP context from ThreatIntel."""
    ti = ctx.deps.threat_intel
    results = []
    for ttp_id in ttp_ids:
        ttp = ti.get_ttp(ttp_id)
        if ttp:
            results.append({
                "id": ttp.id,
                "mitre_id": ttp.mitre_id,
                "name": ttp.name,
                "tactic": ttp.tactic,
                "description": ttp.description,
            })
    return results
