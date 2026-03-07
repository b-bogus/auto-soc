"""
ThreatIntel — plain Python class with one targeted PydanticAI LLM call.

Flow:
  1. fetch_feed()        — simulates OSINT pull (returns raw dicts)
  2. filter_stage1()     — fast rule-based pre-filter (no LLM)
  3. assess_relevance()  — single structured LLM call for contextual judgment
  4. upsert()            — stores IOCs/TTPs and returns a report
  5. get_watchlist()     — returns current active IOCs + TTPs
"""
import uuid
import random
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel
from pydantic_ai import Agent
from auto_soc.utils.ollama_model import make_ollama_model
from auto_soc.config import settings

from auto_soc.models.threat_intel import IOC, TTP, ThreatIntelReport, RelevanceConfig


# ── Output schema for the single LLM relevance call ──────────────────────────

class ItemAssessment(BaseModel):
    item_index: int           # index into the filtered list
    relevant: bool
    confidence: float         # 0.0 – 1.0
    context: str              # one sentence: why this matters to the org
    mitre_ids: list[str]      # associated ATT&CK technique IDs


class BatchRelevanceResult(BaseModel):
    assessments: list[ItemAssessment]
    feed_summary: str         # executive summary of the whole batch


# One-shot structured extraction agent (not an autonomous loop)
_relevance_agent = Agent(
    make_ollama_model(),
    output_type=BatchRelevanceResult,
    system_prompt=(
        "You are a Threat Intelligence analyst at a financial institution. "
        "Given a list of candidate indicators, assess which are relevant "
        "to a financial sector target. Return a structured assessment for every item."
    ),
)


# ── Realistic sample OSINT data (simulates feed fetch) ───────────────────────

_SAMPLE_IOC_DATA = [
    {"type": "ipv4",   "value": "45.155.205.233", "source": "abuse.ch",   "severity": "high",     "tags": ["cobalt-strike", "c2"],       "confidence": 0.92},
    {"type": "domain", "value": "evil-update.net", "source": "OTX",        "severity": "critical", "tags": ["phishing", "financial"],     "confidence": 0.88},
    {"type": "sha256", "value": "a1b2c3d4e5f6" + "0" * 52, "source": "VirusTotal", "severity": "high", "tags": ["ransomware", "banking"], "confidence": 0.79},
    {"type": "url",    "value": "http://cdn-js.biz/update.js", "source": "urlhaus", "severity": "medium", "tags": ["dropper"],           "confidence": 0.65},
    {"type": "ipv4",   "value": "192.0.2.1",      "source": "internal",   "severity": "low",      "tags": ["internal-test"],             "confidence": 0.30},
    {"type": "cve",    "value": "CVE-2024-21413", "source": "NVD",         "severity": "critical", "tags": ["outlook", "rce", "financial"], "confidence": 0.99},
    {"type": "domain", "value": "legitimate.com", "source": "noise-feed", "severity": "info",     "tags": ["benign"],                    "confidence": 0.10},
    {"type": "email",  "value": "ceo@evilcorp.ru", "source": "OTX",       "severity": "high",     "tags": ["phishing", "financial"],     "confidence": 0.81},
    {"type": "ipv4",   "value": "203.0.113.42",   "source": "abuse.ch",   "severity": "high",     "tags": ["c2", "apt"],                 "confidence": 0.85},
    {"type": "domain", "value": "secure-login-bank.tk", "source": "phishtank", "severity": "critical", "tags": ["phishing", "banking"],  "confidence": 0.95},
]

_SAMPLE_TTP_DATA = [
    {"mitre_id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access",
     "description": "Adversaries send spearphishing emails with malicious attachments."},
    {"mitre_id": "T1059.001", "name": "PowerShell",               "tactic": "Execution",
     "description": "Adversaries use PowerShell to execute malicious commands."},
    {"mitre_id": "T1071.001", "name": "Web Protocols (C2)",       "tactic": "Command and Control",
     "description": "Adversaries use HTTP/S for C2 communications."},
    {"mitre_id": "T1486",     "name": "Data Encrypted for Impact","tactic": "Impact",
     "description": "Adversaries encrypt data on target systems for ransom."},
    {"mitre_id": "T1021.001", "name": "Remote Desktop Protocol",  "tactic": "Lateral Movement",
     "description": "Adversaries use RDP to move laterally through the network."},
]


# ── ThreatIntel class ─────────────────────────────────────────────────────────

class ThreatIntel:
    """Plain Python class. Only assess_relevance() makes an LLM call."""

    def __init__(self, config: RelevanceConfig):
        self.config = config
        self._iocs: dict[str, IOC] = {}   # keyed by IOC.id
        self._ttps: dict[str, TTP] = {}   # keyed by TTP.id
        self._reports: list[ThreatIntelReport] = []

    def fetch_feed(self, feed_url: str = "simulated") -> list[dict]:
        """Simulate pulling from an OSINT feed. Returns raw dicts."""
        now = datetime.now(timezone.utc)
        result = []
        for item in _SAMPLE_IOC_DATA:
            result.append({
                **item,
                "first_seen": (now - timedelta(days=random.randint(1, 60))).isoformat(),
                "last_seen":  (now - timedelta(days=random.randint(0, 5))).isoformat(),
                "feed_url": feed_url,
            })
        return result

    def fetch_ttps(self) -> list[dict]:
        """Simulate pulling TTP data (e.g. from MITRE ATT&CK navigator)."""
        return list(_SAMPLE_TTP_DATA)

    def filter_stage1(self, raw_items: list[dict]) -> list[dict]:
        """
        Fast rule-based pre-filter. No LLM.
        Drops items that fail ANY of:
          - last_seen within max_age_days
          - confidence >= min_confidence
          - severity in allowed range
          - tags intersect with sector_tags (for IOCs with tags)
          - already in our store (dedup by value)
        """
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        min_rank = severity_rank.get(self.config.min_severity, 2)
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=self.config.max_age_days)

        kept = []
        existing_values = {ioc.value for ioc in self._iocs.values()}

        for item in raw_items:
            if item.get("source") in self.config.excluded_sources:
                continue
            if item.get("confidence", 0) < self.config.min_confidence:
                continue
            if severity_rank.get(item.get("severity", "info"), 0) < min_rank:
                continue
            last_seen_str = item.get("last_seen", "")
            try:
                last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                if last_seen < cutoff:
                    continue
            except Exception:
                continue
            if item.get("value") in existing_values:
                continue
            kept.append(item)

        return kept

    async def assess_relevance(self, filtered_items: list[dict]) -> tuple[list[IOC], list[TTP]]:
        """
        Single PydanticAI LLM call to assess contextual relevance.
        Returns (iocs, ttps) — only items the LLM marks as relevant.
        """
        if not filtered_items:
            return [], []

        # Build a concise prompt payload
        items_text = "\n".join(
            f"[{i}] type={item.get('type')} value={item.get('value')} "
            f"severity={item.get('severity')} tags={item.get('tags')} "
            f"confidence={item.get('confidence')}"
            for i, item in enumerate(filtered_items)
        )
        prompt = (
            f"Org profile: financial institution, uses Microsoft 365, Windows workstations.\n"
            f"Assess relevance of these {len(filtered_items)} candidate indicators:\n\n"
            f"{items_text}"
        )

        result = await _relevance_agent.run(prompt)
        batch: BatchRelevanceResult = result.output

        now = datetime.now(timezone.utc)
        iocs: list[IOC] = []

        for assessment in batch.assessments:
            if not assessment.relevant:
                continue
            idx = assessment.item_index
            if idx >= len(filtered_items):
                continue
            raw = filtered_items[idx]
            ioc = IOC(
                id=str(uuid.uuid4()),
                type=raw["type"],
                value=raw["value"],
                source=raw.get("source", "unknown"),
                severity=raw["severity"],
                tags=raw.get("tags", []),
                first_seen=datetime.fromisoformat(raw["first_seen"].replace("Z", "+00:00")),
                last_seen=datetime.fromisoformat(raw["last_seen"].replace("Z", "+00:00")),
                confidence=assessment.confidence,
                context=assessment.context,
            )
            iocs.append(ioc)

        # TTPs come from the separate TTP feed, mapped to MITRE IDs from assessments
        all_mitre_ids = {mid for a in batch.assessments for mid in a.mitre_ids}
        ttps: list[TTP] = []
        for raw_ttp in _SAMPLE_TTP_DATA:
            if raw_ttp["mitre_id"] in all_mitre_ids:
                ttp = TTP(
                    id=str(uuid.uuid4()),
                    mitre_id=raw_ttp["mitre_id"],
                    name=raw_ttp["name"],
                    tactic=raw_ttp["tactic"],
                    description=raw_ttp["description"],
                    severity="high",
                    confidence=0.8,
                )
                ttps.append(ttp)

        return iocs, ttps

    def upsert(
        self,
        iocs: list[IOC],
        ttps: list[TTP],
        feed_name: str = "simulated",
        raw_count: int = 0,
        summary: str = "",
    ) -> ThreatIntelReport:
        """Store IOCs/TTPs and produce a ThreatIntelReport."""
        for ioc in iocs:
            self._iocs[ioc.id] = ioc
        for ttp in ttps:
            self._ttps[ttp.id] = ttp

        report = ThreatIntelReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.now(timezone.utc),
            source_feed=feed_name,
            raw_item_count=raw_count,
            relevant_item_count=len(iocs),
            iocs=iocs,
            ttps=ttps,
            summary=summary or f"Ingested {len(iocs)} IOCs and {len(ttps)} TTPs from {feed_name}.",
        )
        self._reports.append(report)
        return report

    def get_watchlist(self) -> dict:
        """Return current active IOCs and TTPs."""
        return {
            "iocs": list(self._iocs.values()),
            "ttps": list(self._ttps.values()),
        }

    def get_ioc(self, ioc_id: str) -> IOC | None:
        return self._iocs.get(ioc_id)

    def get_ttp(self, ttp_id: str) -> TTP | None:
        return self._ttps.get(ttp_id)
