# auto-soc

A SOC (Security Operations Centre) simulation built with [PydanticAI](https://ai.pydantic.dev/) autonomous agents. Runs a full attack-and-detect cycle — red team plants attacks, a SIEM fires alerts, and a Tier 2 analyst agent triages each one. Results are uploaded to Azure and indexed for RAG so agents learn from past runs.

## What it does

Each simulation run goes through 7 phases:

```
1. Threat Intel   — fetch IOCs/TTPs, assess relevance (1 LLM call)
2. SIEM Config    — load watchlist into in-memory SIEM
3. Background     — SystemEmulator generates benign OS telemetry
4. Red Team       — autonomous agent plans & injects attack traffic
5. Detection      — SIEM correlation rules fire alerts
6. Incident Resp  — autonomous agent triages each alert (1 LLM call per alert)
7. Reporting      — build JSON run report, upload to ADLS, index in AI Search
```

**Detection rate** (how many alerts the analyst correctly identified as true positives) is the primary metric.

| Run | Model | Detection |
|-----|-------|-----------|
| 062cb4c3 | qwen2.5:32b (CPU Ollama) | 0% |
| c6d33878 | gpt-4o-mini via Azure | 67% |
| 0011682e | gpt-4o-mini via Azure | 100% |

## Architecture

```
Your machine
├── orchestrator.py          # sequences phases 1–7
├── agents/
│   ├── threat_intel.py      # assesses IOC/TTP relevance
│   ├── red_team_agent.py    # PydanticAI autonomous attack planner
│   └── case_management_agent.py  # PydanticAI autonomous SOC analyst
├── models/                  # Pydantic models (SIEM, ThreatIntel, Cases)
└── utils/
    ├── ollama_model.py      # local Ollama / llama.cpp backend
    └── azure_model.py       # Azure APIM + AI Foundry backend

Azure (all in rg-ben_boogaerts-2345, swedencentral)
├── APIM (BBAPIM, Consumption)     — LLM gateway, managed identity auth
├── AI Foundry                     — gpt-4o-mini deployment
├── ADLS Gen2 (bbadls2345)         — stores run JSON reports
└── AI Search (bbsearch2345)       — indexes incidents for RAG
```

The case management agent calls `search_past_incidents()` before reasoning about each alert, giving it institutional memory across runs.

## Requirements

- Python 3.11+
- For local LLM: Ollama or llama.cpp server
- For Azure LLM: Azure subscription with APIM + AI Foundry set up

```bash
pip install -e .
```

## Configuration

Copy `.env.example` to `.env` and fill in the values:

```bash
# LLM backend — pick one
LLM_PROVIDER=ollama          # or: azure

# Local Ollama / llama.cpp
OLLAMA_HOST=http://localhost:11434/v1
OLLAMA_MODEL=qwen2.5:32b

# Azure APIM + Foundry (if LLM_PROVIDER=azure)
APIM_ENDPOINT=https://<your-apim>.azure-api.net/openai
APIM_KEY=<your-apim-subscription-key>
APIM_DEPLOYMENT=gpt-4o-mini
APIM_API_VERSION=2024-10-21

# Azure ADLS Gen2 (optional — run reports uploaded after each run)
ADLS_ACCOUNT=<storage-account-name>
ADLS_CONTAINER=simulations

# Azure AI Search (optional — enables RAG across past runs)
AI_SEARCH_ENDPOINT=https://<service>.search.windows.net
AI_SEARCH_KEY=<admin-key>
AI_SEARCH_INDEX=incidents

# Logfire observability (optional)
LOGFIRE_TOKEN=<token>
```

## Running a simulation

```bash
cd auto-soc
python -m auto_soc.orchestrator
```

Output is saved to `output/<run-id>.json`. If ADLS and AI Search are configured, the report is also uploaded and each incident is indexed automatically.

## Observability

Instrument with [Logfire](https://logfire.pydantic.dev/) — every agent step, tool call, and LLM message is traced. Set `LOGFIRE_TOKEN` in `.env` to enable.

## Azure setup

See `notes/azure-cli-commands.md` for all `az` CLI commands used to provision the infrastructure, and `notes/rag-ai-search-setup.md` for the AI Search index design.

The key points:
- APIM uses a **system-assigned managed identity** with `Cognitive Services User` role on Foundry — no Foundry key stored anywhere
- ADLS auth uses `DefaultAzureCredential` (picks up `az login` session locally, managed identity on a VM)
- AI Search index management requires the **REST API** directly — `az search` only manages the service, not indexes

## Project layout

```
auto_soc/
├── agents/          PydanticAI agents + tool definitions
├── models/          Pydantic data models
├── stores/          In-memory data stores (SIEM events, system state)
├── utils/           LLM model factories
├── config.py        pydantic-settings config (reads from .env)
└── orchestrator.py  Main simulation runner
scripts/
└── logfire_query.py  Query Logfire spans via API
notes/               Study notes + benchmarks (gitignored)
output/              Run reports, JSON (gitignored)
```
