# SentinelScan — Agentic Malware Triage & Threat-Intel Copilot

**Track 03 · Trustworthy, Responsible & Secure AI** — Agentic AI Hackathon 2026

A SOC analyst drops in a suspicious file. Five agents classify it, scan it, ground
every claim in MITRE ATT&CK, score their own confidence **and risk separately**,
and either auto-file a report — or escalate to a human with the full reasoning trace.

**The demo villain is our own CyberRecon** — a working QR-based C2 framework that
bypasses browser isolation. We built the attack, and we built the AI that catches it.

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

## Limitations (honest)

- **Static regex detection.** Packed or obfuscated samples partially evade it — that's
  what the escalation band is for. Our own `evasion_*.py` samples demonstrate this live.
- **Live monitor is process-level polling** (psutil), not kernel EDR.
- **Gold set is 25 samples** — a demonstration set, not a validation corpus.
- **Scorer weights are hand-calibrated** — `eval/calibrate.py` documents the threshold
  choice, but the weights themselves weren't fit to data.
- **RAG store covers 25 ATT&CK techniques** — a subset of ATT&CK's 700+ sub-techniques.
- **LLM is presentation-only.** Verdict, confidence, risk, citations are deterministic.
- **No real containment.** ESCALATE produces a recommendation and trace.

## What we'd build next

- Sandbox detonation with network isolation (Firecracker/gVisor)
- Full ATT&CK STIX ingest with tuned embedding
- Labeled corpus from MalwareBazaar for real evaluation
- Slack/PagerDuty escalation webhook
- Kernel-level monitoring via ETW (Windows) / eBPF (Linux)