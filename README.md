# SentinelScan — Agentic Malware Triage & Threat-Intel Copilot

**Track 03 · Trustworthy, Responsible & Secure AI** — Agentic AI Hackathon 2026

A SOC analyst drops in a suspicious file. Five agents classify it, scan it, ground
every claim in MITRE ATT&CK, score their own confidence **and risk separately**,
and either auto-file a report — or escalate to a human with the full reasoning trace.

---

## The demo: attack + defense from one team

We built **two** projects for this hackathon:

**1. CyberRecon** — a working QR-based command-and-control framework. It bypasses
browser isolation by encoding C2 commands as QR codes rendered in a headless
browser. Commands travel as **pixels**, which traditional network security never
inspects. The technique is based on **Mandiant's 2024 research** into browser-isolation
bypasses. CyberRecon is real, working offensive tooling: QR decoder client,
keylogger, screenshot capture, webcam, GPS, persistence, and self-destruct.

**2. SentinelScan** — the defensive agentic AI that catches it. **This is what we're
submitting.** SentinelScan detects CyberRecon's behavior:
- **Statically** — by reading its source code
- **Live** — by watching its processes and network connections in real time

Why this matters: **we can prove the defender works.** Most hackathon projects defend
against hypothetical threats. We defend against our own, real C2 framework — verified
in the eval set, verified in the live demo, with real MITRE ATT&CK citations.

> **Note:** CyberRecon is included in `demo_samples/` as `cyberrecon_*.py` — the source
> files SentinelScan analyzes. It is never executed during the demo. All C2 addresses
> are `127.0.0.1`; the samples are read as text, not run.

---

## How SentinelScan works

```
                    ┌──────────────────────────────────────────┐
   File or          │              ORCHESTRATOR                │
   live snapshot ──►│   SimpleOrchestrator (graph.py)          │
                    │   - shared PipelineState                 │
                    │   - Tracer logs every step + reason      │
                    └──────┬─────────┬──────────┬──────────┬───┘
                           ▼         ▼          ▼          ▼
                    ┌──────────┐ ┌────────┐ ┌────────┐ ┌────────┐
                    │ 1 INTAKE │ │2 ANALYZ│ │3 RETR. │ │4 SCORER│
                    │ classify │►│ 19     │►│ ATT&CK │►│ conf + │
                    │ artifact │ │ rules  │ │ cite   │ │ risk   │
                    └──────────┘ └────────┘ └────────┘ └────────┘
                                                            │
                                                            ▼
                                                    ┌──────────────┐
                                                    │ 5 ROUTER     │
                                                    │ ALLOW/       │
                                                    │ ESCALATE/    │
                                                    │ AUTO_REPORT  │
                                                    └──────────────┘
```

### The 5 agents

| Agent | What it does |
|---|---|
| **Intake** (`agents/intake.py`) | Classifies the artifact (Python, PowerShell, exe, dropper candidate) |
| **Static Analyzer** (`agents/analyzer_agent.py`) | Runs 19 behavior rules via FastMCP tools. Detects keylogging, C2, exfiltration, persistence, self-destruct, anti-VM, etc. |
| **RAG Retriever** (`agents/retriever_agent.py`) | Queries a TF-IDF index over 25 ATT&CK chunks. Every detection cites a technique with a similarity score. |
| **Scorer** (`agents/scorer.py`) | Computes confidence (weighted sum) and risk (independent red-flag class). |
| **Router** (`agents/router_agent.py`) | ALLOW / ESCALATE / AUTO_REPORT. Escalates when uncertain or red-flagged. |

### The Red-Flag Governor

The scorer computes **two independent signals**:

- **Confidence** — how sure is the system the verdict is correct? (0–1)
- **Risk** — how dangerous is it *if* real? (low/medium/high/critical)

Certain combinations force **CRITICAL** regardless of confidence:

- `self_destruct` + any `persistence` behavior → real implant, not a prank
- Any live secret (AWS key, API token) found in the artifact

**Why this matters:** a file can score 0.95 confidence and still be **refused
auto-approval** if the red flag fires. High confidence does not override safety.

---

## What the demo_samples contain

25 labeled samples in `demo_samples/`:

| Category | Count | Purpose |
|---|---|---|
| **cyberrecon_*.py** | 5 | Real CyberRecon source files — the demo villain |
| **mal_*.py** | 17 | Synthetic malware samples covering every rule |
| **evasion_*.py** | 3 | Obfuscated samples that demonstrate the escalation band |
| **ben_*.py** | 4 | Clean code that must not false-positive |

Every sample is labeled in `eval/gold_set.jsonl` with expected behaviors.

---

## The three mandatory bars

| Bar | Where in SentinelScan |
|---|---|
| **Multi-agent / tool-using** | 5 agents (intake → static-analyzer → retriever → scorer → router); analyzer calls **FastMCP tools** |
| **RAG / tool-verified grounding** | 25 curated ATT&CK chunks; every detection cited to a retrieved technique with similarity score |
| **Explicit confidence check** | Confidence = weighted sum. Risk = **independent** red-flag classification. Three-way router. |

## Confidence vs. Risk — scored separately

- **Confidence** (0–1): `0.70·detections + 0.20·retrieval + 0.10·artifact prior − benign penalty`
- **Risk**: independent red-flag class. *Self-destruct + persistence ⇒ critical*, regardless of confidence.

## Escalation policy

| Condition | Decision |
|---|---|
| Critical risk (red flag) | **ESCALATE** — never auto-approve |
| Confidence ≥ 0.70, no red flags | **AUTO_REPORT** |
| Some behaviors or confidence ≥ 0.45 | **ESCALATE** to human with full trace |
| No behaviors, confidence < 0.45 | **ALLOW** |

## Quickstart

    pip install -r requirements.txt
    python run_demo.py
    python eval/run_eval.py
    python eval/calibrate.py
    streamlit run app.py

## Tool use / MCP

    python -m sentinelscan.tools.mcp_server

Tools: `scan_artifact`, `extract_indicators`, `classify_artifact`, `scan_secrets`.

## Detection modes

| Mode | Input | Catches |
|---|---|---|
| **Static** | A file's source text | What the code *can* do |
| **Live** | Running processes + network | What it's *doing* right now |

- Static analyzer on CyberRecon's QR-C2 module: **AUTO_REPORT at 0.83** with T1102, T1071.001, T1041, T1113, T1564.001
- Live monitor on CyberRecon running: **AUTO_REPORT at 0.75** in real time

## Verification & evaluation

### Gold set — 25 samples (21 malicious, 4 benign)

| Metric | Value |
|---|---|
| Behavior precision | 0.863 |
| Behavior recall | 0.955 |
| Malicious flag rate | **21 / 21** |
| **False-critical on benign** | **0** |
| Mean confidence, malicious | 0.714 |
| Mean confidence, benign | 0.000 |
| Escalation precision | 1.00 |

Reproduce: `python eval/run_eval.py` → `GATE: PASS`

### Threshold calibration (why 0.70?)

`eval/calibrate.py` sweeps the auto-report threshold against the labeled set:

| Threshold | Precision | Recall | False-positives |
|---|---|---|---|
| 0.30 | 1.00 | 0.95 | 0 |
| 0.50 | 1.00 | 0.86 | 0 |
| **0.70** | **1.00** | **0.71** | **0** |
| 0.75 | 1.00 | 0.67 | 0 |
| 0.80 | 1.00 | 0.52 | 0 |

At 0.70, precision holds at 1.00 with zero benign false-positives. Reproduce: `python eval/calibrate.py`.

### RAG store

25 hand-curated ATT&CK technique chunks. Pure-Python TF-IDF retrieval — deterministic,
offline, zero dependencies. We validated a full MITRE Enterprise STIX ingest (200+
techniques) but shipped the curated seed because keyword precision on our rule-driven
queries is higher with the smaller, focused corpus.

## Security & data care

- **No secrets in repo** — `.env` git-ignored
- **No PHI to shared models** — artifacts never leave the machine; Groq sees only
  behavior names and confidence
- **Secrets redacted before display**
- **Live monitor** only runs synthetic demo samples (safety whitelist)

## Observability

Every agent step, tool call and pause traced with the reason. Full JSON trace in the
Streamlit UI.

## Resilience

- **Retriever**: TF-IDF (pure Python) — no dependency
- **LLM**: Groq (`openai/gpt-oss-20b`) if `GROQ_API_KEY` is set; local rule-synthesizer otherwise
- **Fully offline** verdicts

## Is this really detecting or just a demo?

We built two independent verification paths:

1. **Gold set eval** — 25 labeled samples, `python eval/run_eval.py` prints `GATE: PASS` with precision 0.863 and **zero false-criticals on benign**
2. **Live monitor** — runs on your actual system. Launch any headless Chrome and watch `c2_qr_channel → T1102` fire with the real process ID. Kill the process and the alert clears.

The detection is real. The rules match actual byte patterns in file content and actual process/network state on the machine.

## What we'd build next

- Sandbox detonation with network isolation (Firecracker/gVisor)
- Full ATT&CK STIX ingest with tuned embedding
- Labeled corpus from MalwareBazaar for real evaluation
- Slack/PagerDuty escalation webhook
- Kernel-level monitoring via ETW (Windows) / eBPF (Linux)
