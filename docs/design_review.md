# Technical Specification — Design Review

> **Reviewer:** Claude Opus  
> **Date:** 2026-03-01  
> **Verdict:** The spec is a solid *conceptual* design, but has several architectural issues that will cause real problems during implementation. See below.

---

## Finding 1: "LangGraph" vs PydanticAI — The Spec Contradicts Itself

**Severity:** High

Line 11 of the spec says the system uses "LangGraph-powered agents", but all the actual code and the previous conversation's version of this spec use **PydanticAI**. These are fundamentally different frameworks:

| | LangGraph | PydanticAI |
|---|---|---|
| **Architecture** | Graph-based state machine, nodes + edges | Agent with tools, structured output |
| **State** | Explicit graph state passed between nodes | Dependencies injected via `RunContext` |
| **Control flow** | You define the graph topology | The LLM decides which tools to call |

**Recommendation:** Pick one. Since the code already uses PydanticAI, update the spec to match. But also consider: **do you actually want the LLM to decide tool order?** For a simulation with a fixed orchestration flow, PydanticAI's "LLM picks tools" model may be overkill (see Finding 3).

---

## Finding 2: Over-Reliance on LLM for Deterministic Work

**Severity:** High

The spec uses the LLM in places where it adds cost/latency but no value:

| Use Case | Current Design | Better Approach |
|---|---|---|
| **TI Relevance Filter Stage 1** | Tool called by LLM agent | Pure Python function — it's just checking `confidence >= 0.4` and `last_seen` recency |
| **SIEM Correlation** | LLM agent with tools | Pure Python — IOC matching is a dict lookup, TTP pattern matching is sequence detection |
| **System Emulator** | LLM agent that picks events | Pure Python — it's weighted random sampling from a fixed distribution |
| **Background noise generation** | Was `generate_background_noise` tool | Now replaced by System Emulator (good), but still registered as an `Agent` |

The LLM should only be used where **judgment** is needed:
1. ✅ TI Stage 2 relevance (contextual assessment)
2. ✅ Red Team scenario planning (creative attack design)
3. ✅ Analyst triage reasoning (hypothesis formation)
4. ✅ Report summarization

Everything else is deterministic logic that should be plain Python functions, not LLM tool calls.

**Recommendation:** The SystemEmulatorAgent, SIEMAgent correlation engine, and TI Stage 1 filter should be **plain Python classes**, not PydanticAI Agents. Reserve `Agent()` for the 3-4 places where LLM reasoning is genuinely needed.

---

## Finding 3: The Orchestrator Is a Rigid Script, Not an Agent

**Severity:** Medium

The spec describes 7 sequential phases run by an "Orchestrator" that calls tools in a fixed order. This is just a Python script with function calls — there's no agentic behavior. That's actually **fine** for a v1, but the spec doesn't acknowledge this tension.

The question is: what's the *point* of using PydanticAI Agents if the orchestrator pre-determines every action? The LLM never gets to *decide* anything about control flow.

**Two valid paths:**

| Path A: Script Orchestrator | Path B: Agentic Orchestrator |
|---|---|
| `orchestrator.py` is a plain async function that calls tools in sequence | The Orchestrator itself is a PydanticAI Agent that decides what to do next |
| Simpler, predictable, debuggable | More interesting demo, exercises real agent reasoning |
| Current spec implies this | Would require significant redesign |

**Recommendation:** For v1, lean into Path A explicitly. Make the orchestrator a plain `async def run_simulation()` that calls subsystem functions directly. This is simpler and more reliable. The individual agents (TI, CM, RT) still use LLM reasoning internally — just not for control flow.

---

## Finding 4: The System Emulator Shouldn't Be an LLM Agent

**Severity:** Medium

The `SystemEmulatorAgent` is defined as a `PydanticAI Agent` with `output_type=list[SIEMEvent]`, but its tool functions are entirely deterministic:
- `initialize_endpoints` → builds fixed endpoint objects
- `run_emulation_cycle` → weighted random event selection
- `inject_os_events` → pass-through to SIEM

There's **zero LLM reasoning** happening here. Making it an Agent means:
- Every import loads PydanticAI and validates the Google API key (we already hit this bug)
- The `system_prompt` is never actually used since the tools are called directly
- It creates a false expectation that the LLM is involved in event generation

**Recommendation:** Refactor `SystemEmulatorAgent` to be a plain Python class:

```python
class SystemEmulator:
    def __init__(self, config: SystemEmulatorConfig):
        self.store = SystemEmulatorStore()
        self.config = config
    
    def initialize_endpoints(self) -> list[WindowsEndpoint]: ...
    def run_cycle(self) -> list[SIEMEvent]: ...
```

This removes the PydanticAI dependency, the API key requirement, and the `load_dotenv` hack.

---

## Finding 5: Missing Boundary Between Event Generation and SIEM Injection

**Severity:** Medium

The spec conflates two concerns in the System Emulator:
1. **Generating events** (creating `SIEMEvent` objects with realistic data)
2. **Injecting events into the SIEM** (calling `ingest_events_batch`)

The System Emulator should *only* generate events and return them. The **Orchestrator** should decide when and how to inject them into the SIEM. This keeps the components decoupled and testable.

Currently the spec has `inject_os_events` as a System Emulator tool, but it should be the Orchestrator calling `siem_agent.ingest_events_batch()`.

**Recommendation:** Remove `inject_os_events` from System Emulator. The flow becomes:
```
events = system_emulator.run_cycle()
siem.ingest_events_batch(events)
```

---

## Finding 6: The Red Team Design Is Circular

**Severity:** Low (by design, but worth flagging)

The Red Team reads the IOC watchlist and then deliberately uses those exact IOCs in its attack events. This *guarantees* detection by the SIEM's `ioc_match` rule. The simulation always "succeeds" because the attacker is cooperating with the defender.

This is fine for a **detection validation** use case ("did our pipeline actually fire an alert?"), but it's not realistic adversary simulation. A real attacker doesn't use IOCs that are already on the watchlist.

**Recommendation:** This is actually fine for the stated scope. Just be explicit in the spec that the Red Team's purpose is **detection pipeline validation**, not realistic adversary emulation. The `difficulty` parameter partially addresses this, but even on `hard`, the IOCs are still from the watchlist.

---

## Finding 7: Missing Project Scaffolding

**Severity:** Low

The project currently has no:
- `pyproject.toml` — no dependency management
- `__init__.py` in `models/`, `stores/`, `agents/` — imports may silently fail
- `.gitignore` — `.env` and `output/` should be ignored
- `README.md` — no setup instructions

**Recommendation:** Create these before writing more agent code.

---

## Summary of Recommendations

| # | Change | Impact | Effort |
|---|---|---|---|
| 1 | Fix "LangGraph" → PydanticAI in spec | Consistency | 5 min |
| 2 | Make SystemEmulator a plain class, not an Agent | Removes API key dependency, simplifies imports | 30 min |
| 3 | Make SIEM correlation a plain class, not an Agent | Faster, deterministic, testable | 30 min |
| 4 | Make Orchestrator an explicit script, not implied | Clarity | 15 min |
| 5 | Decouple event generation from SIEM injection | Better architecture | 15 min |
| 6 | Add project scaffolding (pyproject.toml, .gitignore, etc.) | Needed before serious development | 20 min |
| 7 | Clarify Red Team's purpose as pipeline validation | Documentation | 5 min |

> [!IMPORTANT]
> **The biggest design mistake** is making every subsystem a PydanticAI Agent. Only 3 components genuinely need LLM reasoning: ThreatIntelAgent (Stage 2), RedTeamAgent (scenario planning), and CaseManagementAgent (analyst triage). Everything else — SystemEmulator, SIEM correlation, persistence — should be plain Python classes that the orchestrator calls directly.
