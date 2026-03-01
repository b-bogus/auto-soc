from datetime import datetime
from auto_soc.models.siem import SIEMEvent, SIEMAlert, CorrelationRule
from auto_soc.models.threat_intel import IOC, TTP


class SIEMStore:
    def __init__(self):
        self.events: list[SIEMEvent] = []
        self.events_by_id: dict[str, SIEMEvent] = {}
        self.alerts: list[SIEMAlert] = []
        self.alerts_by_id: dict[str, SIEMAlert] = {}
        self.rules: list[CorrelationRule] = []
        # field_index: field_name → { field_value → [event_id] }
        self.field_index: dict[str, dict[str, list[str]]] = {}
        # IOC lookup: ioc_value → IOC
        self._ioc_lookup: dict[str, IOC] = {}
        # TTP lookup: mitre_id → TTP
        self._ttp_lookup: dict[str, TTP] = {}

    def load_watchlist(self, iocs: list[IOC], ttps: list[TTP]) -> None:
        self._ioc_lookup = {ioc.value: ioc for ioc in iocs}
        self._ttp_lookup = {ttp.mitre_id: ttp for ttp in ttps}

    def _index_event(self, event: SIEMEvent) -> None:
        for field, value in event.parsed_fields.items():
            if value is None:
                continue
            str_val = str(value)
            self.field_index.setdefault(field, {}).setdefault(str_val, []).append(event.event_id)
            # Real-time IOC match
            if str_val in self._ioc_lookup:
                event.matched_ioc_ids.append(self._ioc_lookup[str_val].id)

    def ingest(self, event: SIEMEvent) -> str:
        self.events.append(event)
        self.events_by_id[event.event_id] = event
        self._index_event(event)
        return event.event_id

    def ingest_batch(self, events: list[SIEMEvent]) -> list[str]:
        return [self.ingest(e) for e in events]

    def search(self, query: dict) -> list[SIEMEvent]:
        """Filter events matching ALL query field:value pairs."""
        results = None
        for field, value in query.items():
            hit_ids = set(self.field_index.get(field, {}).get(str(value), []))
            results = hit_ids if results is None else results & hit_ids
        if results is None:
            return []
        return [self.events_by_id[eid] for eid in results if eid in self.events_by_id]

    def get_event_context(self, event_id: str, window_seconds: int = 300) -> list[SIEMEvent]:
        """Surrounding events on same hostname within a time window."""
        anchor = self.events_by_id.get(event_id)
        if not anchor:
            return []
        hostname = anchor.parsed_fields.get("hostname")
        t0, t1 = (
            anchor.timestamp.timestamp() - window_seconds,
            anchor.timestamp.timestamp() + window_seconds,
        )
        return [
            e for e in self.events
            if e.parsed_fields.get("hostname") == hostname
            and t0 <= e.timestamp.timestamp() <= t1
            and e.event_id != event_id
        ]

    def run_correlation(self, rule_id: str | None = None) -> list[SIEMAlert]:
        """Run correlation rules against the event store. Returns new alerts."""
        rules = [r for r in self.rules if r.enabled]
        if rule_id:
            rules = [r for r in rules if r.rule_id == rule_id]

        new_alerts: list[SIEMAlert] = []
        for rule in rules:
            if rule.match_logic == "ioc_match":
                new_alerts.extend(self._run_ioc_match(rule))
            elif rule.match_logic == "threshold":
                new_alerts.extend(self._run_threshold(rule))
        self.alerts.extend(new_alerts)
        for alert in new_alerts:
            self.alerts_by_id[alert.alert_id] = alert
        return new_alerts

    def _run_ioc_match(self, rule: CorrelationRule) -> list[SIEMAlert]:
        import uuid
        from datetime import timezone
        alerts = []
        for event in self.events:
            if event.matched_ioc_ids:
                alert = SIEMAlert(
                    alert_id=str(uuid.uuid4()),
                    triggered_at=datetime.now(timezone.utc),
                    rule=rule,
                    matched_events=[event.event_id],
                    matched_iocs=event.matched_ioc_ids,
                    matched_ttps=event.matched_ttp_ids,
                    severity=rule.severity,
                    status="new",
                    summary=f"IOC match on {event.parsed_fields.get('hostname', 'unknown')}: {event.raw_log[:80]}"
                )
                alerts.append(alert)
        return alerts

    def _run_threshold(self, rule: CorrelationRule) -> list[SIEMAlert]:
        # Placeholder — detailed implementation in future milestone
        return []

    def update_alert_status(self, alert_id: str, status: str) -> SIEMAlert | None:
        alert = self.alerts_by_id.get(alert_id)
        if alert:
            alert.status = status
        return alert

    def add_rule(self, rule: CorrelationRule) -> None:
        self.rules.append(rule)
