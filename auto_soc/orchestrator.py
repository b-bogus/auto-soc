"""
orchestrator.py — Plain Python async script that sequences the full simulation.

Phases:
  1. Threat Intel   — fetch, filter, assess relevance (1 LLM call)
  2. SIEM Config    — load watchlist into SIEM
  3. Background     — SystemEmulator generates benign OS telemetry
  4. Red Team       — autonomous PydanticAI Agent plans & injects attack
  5. Detection      — SIEM runs correlation rules
  6. Incident Resp  — autonomous PydanticAI Agent triages each alert
  7. Reporting      — build run summary
"""
import uuid
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path

# ── Logfire observability ──────────────────────────────────────────────────────
# Reads LOGFIRE_TOKEN from env/.env automatically.
# Shows every agent step, tool call, and LLM message in the Logfire UI.
import logfire
from dotenv import load_dotenv
load_dotenv()
logfire.configure()
logfire.instrument_pydantic_ai()

# ── Logging setup ─────────────────────────────────────────────────────────────
# Emit to stdout so `tee` captures it alongside print() output.
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
))

# Show every tool call and LLM message from PydanticAI
logging.getLogger("pydantic_ai").setLevel(logging.DEBUG)
logging.getLogger("pydantic_ai").addHandler(_handler)
logging.getLogger("pydantic_ai").propagate = False

# Also capture httpx so we can see the raw Ollama requests/responses
logging.getLogger("httpx").setLevel(logging.INFO)
logging.getLogger("httpx").addHandler(_handler)
logging.getLogger("httpx").propagate = False

# Our own logger for orchestrator events
log = logging.getLogger("auto_soc")
log.setLevel(logging.DEBUG)
log.addHandler(_handler)
log.propagate = False

# Agent timeout in seconds — 1200s = 20 min, needed for qwen2.5:32b on CPU
# (~3 min per call × 4+ tool-calling round-trips per autonomous agent)
AGENT_TIMEOUT = 1200

from auto_soc.models.threat_intel import RelevanceConfig
from auto_soc.models.red_team import RedTeamConfig
from auto_soc.models.system_emulator import SystemEmulatorConfig
from auto_soc.models.siem import CorrelationRule, SIEMAlert
from auto_soc.models.case_management import Incident, AnalystReasoning

from auto_soc.agents.threat_intel import ThreatIntel
from auto_soc.agents.system_emulator import SystemEmulator
from auto_soc.agents.siem import SIEMStore
from auto_soc.agents.red_team_agent import red_team_agent, RedTeamDeps
from auto_soc.agents.case_management_agent import case_management_agent, CaseManagementDeps


@dataclass
class SimulationConfig:
    background_cycles: int = 3
    relevance_config: RelevanceConfig = field(default_factory=RelevanceConfig)
    red_team_config: RedTeamConfig = field(default_factory=RedTeamConfig)
    emulator_config: SystemEmulatorConfig = field(default_factory=SystemEmulatorConfig)


@dataclass
class RunReport:
    run_id: str
    started_at: datetime
    completed_at: datetime | None = None
    ioc_count: int = 0
    ttp_count: int = 0
    background_events: int = 0
    attack_events: int = 0
    alerts_fired: int = 0
    incidents_created: int = 0
    true_positives: int = 0
    false_positives: int = 0
    detection_rate: float | None = None
    incidents: list[Incident] = field(default_factory=list)


async def run_simulation(config: SimulationConfig | None = None) -> RunReport:
    if config is None:
        config = SimulationConfig()

    run_id = str(uuid.uuid4())[:8]
    report = RunReport(run_id=run_id, started_at=datetime.now(timezone.utc))
    print(f"\n{'='*60}")
    print(f"  Autonomous SOC Simulation — run_id: {run_id}")
    print(f"{'='*60}\n")

    # ── Phase 1: Threat Intel ─────────────────────────────────────────────────
    print("Phase 1 — Threat Intel Ingestion")
    ti = ThreatIntel(config.relevance_config)
    raw_items = ti.fetch_feed()
    print(f"  Fetched {len(raw_items)} raw items from feed")

    filtered = ti.filter_stage1(raw_items)
    print(f"  Stage 1 filter kept {len(filtered)} items")

    iocs, ttps = await ti.assess_relevance(filtered)
    print(f"  LLM assessed {len(filtered)} items → {len(iocs)} IOCs, {len(ttps)} TTPs kept")

    report_obj = ti.upsert(iocs, ttps, feed_name="simulated-osint", raw_count=len(raw_items))
    report.ioc_count = len(iocs)
    report.ttp_count = len(ttps)
    print(f"  Watchlist: {len(iocs)} IOCs | {len(ttps)} TTPs\n")

    # ── Phase 2: SIEM Configuration ───────────────────────────────────────────
    print("Phase 2 — SIEM Configuration")
    siem = SIEMStore()
    siem.load_watchlist(iocs, ttps)

    # Add a default IOC-match rule
    ioc_rule = CorrelationRule(
        name="IOC Match — Known Malicious Indicator",
        description="Fires when any parsed field matches a known IOC in the watchlist.",
        match_logic="ioc_match",
        severity="high",
        mitre_ids=["T1071", "T1566", "T1059"],
    )
    siem.add_rule(ioc_rule)
    print(f"  Loaded {len(iocs)} IOCs into watchlist, 1 correlation rule active\n")

    # ── Phase 3: Background Noise ─────────────────────────────────────────────
    print("Phase 3 — Background OS Telemetry")
    emulator = SystemEmulator(config.emulator_config)
    endpoints = emulator.initialize()
    print(f"  Initialized {len(endpoints)} endpoints: {[ep.hostname for ep in endpoints]}")

    total_bg_events = 0
    for cycle in range(config.background_cycles):
        bg_events = emulator.run_cycle()
        siem.ingest_batch(bg_events)
        total_bg_events += len(bg_events)
        print(f"  Cycle {cycle+1}/{config.background_cycles}: {len(bg_events)} events ingested")

    report.background_events = total_bg_events
    print(f"  Total background events: {total_bg_events}\n")

    # ── Phase 4: Red Team Attack ──────────────────────────────────────────────
    print("Phase 4 — Red Team Attack (autonomous agent)")
    rt_scenarios: list = []
    rt_deps = RedTeamDeps(
        threat_intel_watchlist=ti.get_watchlist(),
        siem_ingest_fn=siem.ingest_batch,
        available_endpoints=[
            {"hostname": ep.hostname, "ip": ep.ip_address, "role": ep.role}
            for ep in endpoints
        ],
        config=config.red_team_config,
        scenarios=rt_scenarios,
    )

    log.info("Red team agent starting (timeout=%ds)...", AGENT_TIMEOUT)
    rt_result = await asyncio.wait_for(
        red_team_agent.run(
            "Execute the attack simulation now. "
            "Step 1: call get_watchlist(). "
            "Step 2: call get_available_targets(). "
            "Step 3: call generate_attack_events() for 2-3 ATT&CK phases (T1566 phishing, T1059 execution, T1071 C2). "
            "Step 4: call inject_scenario() with the results.",
            deps=rt_deps,
        ),
        timeout=AGENT_TIMEOUT,
    )
    # The agent's final output is a text summary (output_type=str).
    # The real scenario is built by the inject_scenario tool and stored in rt_deps.scenarios.
    log.info("Red team agent summary: %s", rt_result.output[:200] if rt_result.output else "(none)")
    if rt_deps.scenarios:
        scenario = rt_deps.scenarios[-1]
    else:
        # Agent completed but never called inject_scenario — create minimal record
        from auto_soc.models.red_team import AttackScenario as _AS
        scenario = _AS(name="(no scenario injected)", phases=[])
    attack_event_count = sum(len(p.generated_events) for p in scenario.phases)
    report.attack_events = attack_event_count
    print(f"  Scenario: '{scenario.name}' — {len(scenario.phases)} phases, {attack_event_count} events injected\n")

    # ── Phase 5: Detection ────────────────────────────────────────────────────
    print("Phase 5 — SIEM Correlation")
    alerts = siem.run_correlation()
    report.alerts_fired = len(alerts)
    print(f"  {len(alerts)} alert(s) fired\n")

    if not alerts:
        print("  ⚠ No alerts fired. Check IOC values in attack events match the watchlist.\n")

    # ── Phase 6: Incident Response ────────────────────────────────────────────
    print("Phase 6 — Incident Response (autonomous agent, per alert)")
    incidents: list[Incident] = []
    true_positives = 0
    false_positives = 0

    for i, alert in enumerate(alerts):
        print(f"  Triaging alert {i+1}/{len(alerts)}: {alert.alert_id[:8]}...")
        cm_deps = CaseManagementDeps(
            alert=alert,
            siem_store=siem,
            threat_intel=ti,
            incidents=incidents,
        )
        log.info("Case management agent starting for alert %s...", alert.alert_id[:8])
        cm_result = await asyncio.wait_for(
            case_management_agent.run(
                f"Investigate alert {alert.alert_id}. "
                f"Rule: '{alert.rule.name}'. "
                f"Matched events: {len(alert.matched_events)}. "
                f"Matched IOCs: {alert.matched_iocs}.",
                deps=cm_deps,
            ),
            timeout=AGENT_TIMEOUT,
        )
        reasoning: AnalystReasoning = cm_result.output

        # Determine priority from alert severity
        priority_map = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
        incident = Incident(
            title=f"Alert: {alert.rule.name} — {alert.alert_id[:8]}",
            source_alert_id=alert.alert_id,
            priority=priority_map.get(alert.severity, "P3"),
            analyst_reasoning=reasoning,
            mitigation_actions=reasoning.recommended_actions,
            timeline=[f"Alert fired at {alert.triggered_at.isoformat()}",
                      f"Analyst verdict: {reasoning.verdict} (confidence: {reasoning.confidence:.0%})"],
        )
        incidents.append(incident)

        if reasoning.verdict == "true_positive":
            true_positives += 1
        elif reasoning.verdict == "false_positive":
            false_positives += 1

        print(f"    Verdict: {reasoning.verdict} (confidence {reasoning.confidence:.0%})")
        if reasoning.recommended_actions:
            print(f"    Actions: {[a.action_type for a in reasoning.recommended_actions]}")

    report.incidents_created = len(incidents)
    report.true_positives = true_positives
    report.false_positives = false_positives
    report.incidents = incidents

    # ── Phase 7: Reporting ────────────────────────────────────────────────────
    print(f"\nPhase 7 — Run Report")
    if report.attack_events > 0:
        report.detection_rate = min(1.0, report.alerts_fired / max(1, len(scenario.phases)))
    report.completed_at = datetime.now(timezone.utc)
    elapsed = (report.completed_at - report.started_at).total_seconds()

    print(f"{'─'*40}")
    print(f"  Run ID:           {run_id}")
    print(f"  Duration:         {elapsed:.1f}s")
    print(f"  IOCs in watchlist:{report.ioc_count}")
    print(f"  TTPs in watchlist:{report.ttp_count}")
    print(f"  Background events:{report.background_events}")
    print(f"  Attack events:    {report.attack_events}")
    print(f"  Alerts fired:     {report.alerts_fired}")
    print(f"  Incidents created:{report.incidents_created}")
    print(f"  True positives:   {report.true_positives}")
    print(f"  False positives:  {report.false_positives}")
    if report.detection_rate is not None:
        print(f"  Detection rate:   {report.detection_rate:.0%}")
    print(f"{'─'*40}\n")

    # ── Save report to disk ───────────────────────────────────────────────────
    output_dir = Path(__file__).parent.parent / "output"
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / f"{run_id}.json"

    report_dict = {
        "run_id": report.run_id,
        "started_at": report.started_at.isoformat(),
        "completed_at": report.completed_at.isoformat() if report.completed_at else None,
        "ioc_count": report.ioc_count,
        "ttp_count": report.ttp_count,
        "background_events": report.background_events,
        "attack_events": report.attack_events,
        "alerts_fired": report.alerts_fired,
        "incidents_created": report.incidents_created,
        "true_positives": report.true_positives,
        "false_positives": report.false_positives,
        "detection_rate": report.detection_rate,
        "incidents": [i.model_dump(mode="json") for i in report.incidents],
    }
    output_file.write_text(json.dumps(report_dict, indent=2))
    print(f"  Report saved to: {output_file}")

    # ── Upload to ADLS ────────────────────────────────────────────────────────
    try:
        from azure.identity import DefaultAzureCredential
        from azure.storage.blob import BlobServiceClient
        from auto_soc.config import settings as _s
        credential = DefaultAzureCredential()
        blob_client = BlobServiceClient(
            account_url=f"https://{_s.adls_account}.blob.core.windows.net",
            credential=credential,
        ).get_blob_client(container=_s.adls_container, blob=f"{run_id}.json")
        blob_client.upload_blob(json.dumps(report_dict, indent=2), overwrite=True)
        print(f"  Report uploaded to ADLS: {_s.adls_container}/{run_id}.json\n")
    except Exception as e:
        print(f"  ADLS upload skipped: {e}\n")

    # ── Push per-incident documents to AI Search ──────────────────────────────
    # The blob indexer can't reach inside nested incidents[], so we push directly.
    # Each incident becomes a searchable document with IOCs, verdict, and actions.
    try:
        import urllib.request as _urlreq
        import urllib.parse as _urlparse
        from auto_soc.config import settings as _s

        if _s.ai_search_key and report.incidents:
            run_date_str = report.started_at.strftime("%Y-%m-%d")
            docs = []
            for inc in report.incidents:
                r = inc.analyst_reasoning
                # Extract IOC values from matched events (via source_alert_id → alert)
                ioc_values = list(inc.mitigation_actions and
                    {a.target for a in inc.mitigation_actions if a.target} or set())
                action_strs = [
                    f"{a.action_type}({a.target})" + (f": {a.notes}" if a.notes else "")
                    for a in (inc.mitigation_actions or [])
                ]
                docs.append({
                    "@search.action": "mergeOrUpload",
                    "id": f"{run_id}-{inc.source_alert_id[:8]}",
                    "run_id": run_id,
                    "run_date": run_date_str,
                    "title": inc.title,
                    "verdict": r.verdict if r else None,
                    "confidence": r.confidence if r else None,
                    "hypothesis": r.hypothesis if r else None,
                    "summary": r.summary if r else None,
                    "evidence_for": list(r.evidence_for) if r and r.evidence_for else [],
                    "evidence_against": list(r.evidence_against) if r and r.evidence_against else [],
                    "mitre_ids": list(r.mitre_ids) if r and r.mitre_ids else [],
                    "iocs": ioc_values,
                    "actions": action_strs,
                })

            payload = json.dumps({"value": docs}).encode()
            url = (f"{_s.ai_search_endpoint}/indexes/{_s.ai_search_index}"
                   f"/docs/index?api-version=2024-07-01")
            req = _urlreq.Request(
                url, data=payload,
                headers={"Content-Type": "application/json", "api-key": _s.ai_search_key},
                method="POST",
            )
            with _urlreq.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
                pushed = sum(1 for d in result.get("value", []) if d.get("status"))
            print(f"  AI Search: {pushed}/{len(docs)} incidents indexed\n")
        else:
            print(f"  AI Search push skipped (key not set or no incidents)\n")
    except Exception as e:
        print(f"  AI Search push skipped: {e}\n")

    return report


# ── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    asyncio.run(run_simulation())
