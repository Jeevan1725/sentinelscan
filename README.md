# SentinelScan

**Agentic AI for endpoint malware triage and threat-intelligence grounding.**

Track 03 — Trustworthy, Responsible & Secure AI
Agentic AI Bootcamp Hackathon 2026, Amritapuri

---

## Overview

SentinelScan is a multi-agent system that triages suspicious code artifacts. It reads a file or inspects a running system, classifies observed behaviors against MITRE ATT&CK, scores its own confidence and risk independently, and either auto-files an incident report or escalates to a human analyst with a complete reasoning trace.

The project was built for Track 03, which explicitly rewards building the safety layer itself: confidence scoring, guardrails, escalation, and auditability. Every architectural decision in SentinelScan favors **auditability over autonomy**, on the premise that a security verdict that cannot be explained cannot be trusted.

---

## Motivation: why endpoint detection for QR-based C2

To understand the design, one must understand the threat.

Browser isolation is a widely deployed security boundary. Web content is rendered in a remote sandbox; only pixels reach the endpoint. Network firewalls, DNS filters, and IDS see nothing because no network channel exists between the isolated content and the host.

The boundary has one gap: **pixels are not filtered.**

A QR code is a rendered image. An adversary can encode command-and-control instructions as QR codes, render them in a headless browser, and have an implant on the endpoint read them. Commands travel as visual content, never as network packets. Mandiant documented this technique in 2024.

Traditional network security has no countermeasure for this channel. Detection must occur **at the endpoint** — by reading the implant's code, observing its process behavior, and detecting the pattern of a QR-C2 loop. SentinelScan is designed for exactly that.

---

## Demonstration: attack and defense from one team

This submission contains two projects:

**CyberRecon** — a working QR-C2 framework implementing the Mandiant technique. It includes a Flask C2 server that encodes commands as QR images, a headless-Chrome decoder client, keylogging, screenshot capture, webcam capture, GPS lookup, persistence (registry, scheduled task, startup folder), and self-destruct. Source files are located in `demo_samples/cyberrecon_*.py`.

**SentinelScan** — the defensive agent this repository documents. It detects CyberRecon's behavior both statically (via source code analysis) and live (via process and network monitoring).

This pairing provides a stronger demonstration than defending against hypothetical threats: the defender is verified against a real, working implementation of the attack.

> **Safety note.** CyberRecon is included as source files only. It is never executed during any part of the demo. All command-and-control addresses are `127.0.0.1`. The samples are read as text and analyzed; no network activity is generated.

---

## Architecture

```
                    ┌──────────────────────────────────────────┐
   File or          │              ORCHESTRATOR                │
   live snapshot ──►│   SimpleOrchestrator (graph.py)          │
                    │   - shared PipelineState                 │
                    │   - Tracer logs every step with reason   │
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
                                                    │ ALLOW /      │
                                                    │ ESCALATE /   │
                                                    │ AUTO_REPORT  │
                                                    └──────────────┘
```

### Agents

| Agent | Module | Responsibility |
|---|---|---|
| Intake | `agents/intake.py` | Classifies the artifact type and sets the confidence prior. |
| Static Analyzer | `agents/analyzer_agent.py` | Executes 19 behavior rules through FastMCP tools. Extracts IOCs, redacts secrets. |
| RAG Retriever | `agents/retriever_agent.py` | Queries a TF-IDF index over 25 curated MITRE ATT&CK chunks. Every detection is cited to a retrieved technique with a similarity score. |
| Scorer | `agents/scorer.py` | Computes confidence (documented weighted sum) and risk (independent red-flag classification). |
| Router | `agents/router_agent.py` | Produces one of three outcomes: `ALLOW`, `ESCALATE`, `AUTO_REPORT`. |

### Confidence and risk are scored independently

Confidence and risk are distinct concerns and are computed separately.

```
confidence = 0.70 × detection_score
           + 0.20 × retrieval_score
           + 0.10 × artifact_prior
           − benign_penalty
```

Risk is derived from confidence bands **plus** an independent red-flag governor:

| Red flag | Effect |
|---|---|
| `self_destruct` combined with any persistence behavior | Forces CRITICAL regardless of confidence |
| Live secrets (AWS keys, API tokens) in the artifact | Forces CRITICAL regardless of confidence |

A file can score 0.95 confidence and still be refused auto-approval when a red flag fires. This is the central design principle: high confidence does not override risk.

### Routing policy

| Condition | Decision |
|---|---|
| Critical risk (red flag fired) | `ESCALATE` — never auto-approve |
| Confidence ≥ 0.70, no red flags | `AUTO_REPORT` — auto-file the incident |
| Behaviors detected, confidence < 0.70 | `ESCALATE` — human review with full trace |
| No behaviors, confidence < 0.45 | `ALLOW` |

Three outcomes rather than two allow the system to express uncertainty. In security, both false positives and false negatives carry operational cost; a system that can say "I am not certain" is more useful than one forced into a binary verdict.

---

## Detection modes

Two input sources feed the same pipeline, scorer, and router:

| Mode | Input | Use case |
|---|---|---|
| Static | Source text of an artifact | Determine what the code can do |
| Live | Running processes and network connections | Determine what the code is currently doing |

On CyberRecon's QR-C2 module, both modes independently reach the same verdict with correct ATT&CK citations.

---

## Repository layout

```
sentinelscan/
├── README.md
├── WRITEUP.md
├── DEMO_VIDEO_SCRIPT.md
├── requirements.txt
├── .env.example
├── .gitignore
│
├── run_demo.py                   CLI: static analysis of one file
├── watch_live.py                 CLI: live process and network monitor
├── app.py                        Streamlit web interface
│
├── sentinelscan/
│   ├── config.py                 Weights, thresholds, secret patterns
│   ├── tracer.py                 Structured event tracing
│   ├── llm.py                    LLM wrapper (Groq) with local fallback
│   ├── retriever.py              TF-IDF index; optional Chroma backend
│   ├── analyzer.py               19 behavioral rules
│   ├── report.py                 Markdown incident report builder
│   ├── graph.py                  Pipeline orchestrator
│   ├── live_signals.py           Process and network snapshotting
│   ├── agents/                   Five specialized agents
│   ├── tools/mcp_server.py       FastMCP tool server
│   └── data/attack_seed.json     25 curated ATT&CK technique chunks
│
├── demo_samples/                 25 labeled samples
│   ├── cyberrecon_*.py           5 files — the demonstration threat
│   ├── mal_*.py                  17 files — synthetic malware
│   ├── evasion_*.py              3 files — obfuscation samples
│   └── ben_*.py                  4 files — benign code
│
└── eval/
    ├── gold_set.jsonl            25 labeled evaluation cases
    ├── run_eval.py               Accuracy and safety metrics
    └── calibrate.py              Threshold sweep
```

---

## Installation

### Prerequisites

- Python 3.11 or newer
- Git
- Approximately 500 MB free disk space for the virtual environment

### Steps

**1. Clone the repository**

```bash
git clone https://github.com/Jeevan1725/sentinelscan.git
cd sentinelscan
```

**2. Create and activate a virtual environment**

Windows (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

macOS / Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

Dependencies: `streamlit`, `fastmcp`, `psutil`, `groq`, `python-dotenv`.

**4. (Optional) Configure LLM summaries**

SentinelScan runs fully offline by default. The optional LLM layer generates the analyst summary paragraph only; verdicts, confidence, risk, and citations are always deterministic.

To enable LLM summaries:

```bash
cp .env.example .env
```

Edit `.env`:

```
GROQ_API_KEY=<your key from https://console.groq.com/keys>
GROQ_MODEL=openai/gpt-oss-20b
```

**5. Verify the installation**

```bash
python run_demo.py demo_samples/cyberrecon_01_qr_c2.py
```

Expected output:

```
cyberrecon_01_qr_c2.py -> AUTO_REPORT (risk=high, confidence=0.827)

[screen_capture]    -> T1113 Screen Capture
[c2_http]           -> T1071.001 Application Layer Protocol: Web
[c2_qr_channel]     -> T1102 Web Service C2
[data_exfiltration] -> T1041 Exfiltration Over C2 Channel
[stealth_execution] -> T1564.001 Hide Artifacts
```

---

## Usage

### Static analysis (CLI)

Analyze a single artifact:

```bash
python run_demo.py demo_samples/cyberrecon_01_qr_c2.py
```

Analyze every sample in the demo set:

```bash
python run_demo.py
```

Each run produces an incident report containing the verdict, risk class, confidence breakdown, all detected behaviors with file/line evidence, and the ATT&CK citation for each behavior.

### Live monitoring (CLI)

Terminal 1:

```bash
python watch_live.py --interval 3
```

Terminal 2 (triggers a detection):

```powershell
& "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe" --headless --disable-gpu --remote-debugging-port=9222 about:blank
```

The monitor prints an alert within seconds:

```
======================================================================
  LIVE THREAT DETECTED
======================================================================
  VERDICT     : AUTO_REPORT
  RISK        : HIGH
  CONFIDENCE  : 0.806
  [c2_qr_channel] -> T1102 Web Service C2
    - pid 12345 chrome.exe --headless (QR decode loop candidate)
```

### Web interface

```bash
streamlit run app.py
```

The browser opens at `http://localhost:8501`. Two tabs are available:

- **Analyze a file** — select a sample or upload a file; the full agent trace and report are displayed.
- **Live monitor** — start/stop process and network monitoring; alerts stream in as they occur.

### MCP tool server

```bash
python -m sentinelscan.tools.mcp_server
```

Exposes four tools over MCP: `scan_artifact`, `extract_indicators`, `classify_artifact`, `scan_secrets`.

### Evaluation

```bash
python eval/run_eval.py     # Accuracy and safety metrics
python eval/calibrate.py    # Threshold calibration sweep
```

---

## Evaluation

### Dataset

The gold set contains 25 labeled samples:

| Category | Count |
|---|---|
| Malicious | 21 |
| Benign | 4 |

Malicious samples include real CyberRecon source files. Benign samples include standard Python and Flask applications.

### Results

| Metric | Value |
|---|---|
| Behavior precision | 0.863 |
| Behavior recall | 0.955 |
| Malicious flag rate | 21 / 21 |
| False-critical on benign | 0 |
| Mean confidence, malicious | 0.714 |
| Mean confidence, benign | 0.000 |
| Escalation precision | 1.00 |

The evaluation includes a hard safety gate: `false_critical_on_benign == 0`. If a benign sample is ever classified as critical, the gate fails. It does not.

### Threshold calibration

The auto-report threshold is not chosen arbitrarily. `eval/calibrate.py` sweeps thresholds against the labeled set:

| Threshold | Precision | Recall | Benign false positives |
|---|---|---|---|
| 0.30 | 1.00 | 0.95 | 0 |
| 0.50 | 1.00 | 0.86 | 0 |
| 0.70 | 1.00 | 0.71 | 0 |
| 0.75 | 1.00 | 0.67 | 0 |
| 0.80 | 1.00 | 0.52 | 0 |

At 0.70, precision holds at 1.00 with zero benign false positives. Below 0.70, only recall improves. Above 0.70, recall degrades without a precision gain.

---

## Design decisions

### Deterministic pipeline over LLM-driven orchestration

The five agents are orchestrated by a fixed Python pipeline, not by an LLM planner. This was deliberate. A probabilistic planner can produce inconsistent verdicts; a deterministic pipeline produces identical output for identical input. For a security tool, reproducibility is a requirement.

### TF-IDF retrieval over dense embeddings

Both retrieval paths were implemented and evaluated. A dense embedding approach (Chroma + MiniLM) was tested against the rule-driven queries used by the analyzer and returned low-similarity matches. TF-IDF performs better on this specific workload: short, keyword-dense queries against a small, focused corpus. The embedding path remains available; the shipped default is TF-IDF.

### LLM confined to summarization

The LLM (Groq `openai/gpt-oss-20b`) generates the analyst summary paragraph only. It does not influence the verdict, confidence, risk classification, or ATT&CK citations. This ensures the verdict remains auditable and reproducible even in the event of model failure.

### Red-flag governor independent of confidence

Certain behavior combinations (self-destruct with persistence, live secrets) force CRITICAL classification regardless of the numeric confidence. This is the mechanism by which the system declines to auto-approve high-confidence findings when the risk profile warrants escalation.

---

## Limitations

The following limitations are known and deliberate:

- **Static analysis is regex-based.** Obfuscated or packed artifacts partially evade detection. The escalation band is the designed response to this case; the `evasion_*.py` samples demonstrate it in practice.
- **Live monitoring is process-level polling**, not kernel-level endpoint detection. It is bypassable by renaming binaries.
- **The gold set contains 25 samples**, sufficient for demonstration but not for validation. Production evaluation would require a corpus at MalwareBazaar scale.
- **Scorer weights are hand-calibrated.** The threshold is data-driven; the underlying weights are not learned.
- **The RAG store covers 25 ATT&CK techniques**, a subset of the full ATT&CK corpus.
- **No automated containment.** ESCALATE produces a recommendation and full trace; it does not quarantine.
- **No authentication or multi-tenancy.** Single-user local deployment.

---

## Roadmap

- Sandbox detonation with network isolation (Firecracker or gVisor)
- Full ATT&CK STIX ingest with security-domain embeddings
- Labeled evaluation corpus sourced from MalwareBazaar
- Slack and PagerDuty escalation webhook
- Kernel-level monitoring via ETW (Windows) or eBPF (Linux)

---

## Track 03 alignment

| Track 03 requirement | Implementation |
|---|---|
| Confidence scoring | Four-component weighted sum, displayed in the UI |
| Guardrails | Red-flag governor; high confidence does not override safety |
| Audit logs | Structured JSON trace with reasons for every step |
| Resilience | TF-IDF fallback, LLM optional, offline verdicts |
| Explicit escalation | Three-way router: `ALLOW` / `ESCALATE` / `AUTO_REPORT` |
| Grounding | Every claim cited to a retrieved ATT&CK technique |
| Safety invariant | Zero false-critical on benign, enforced by the evaluation gate |

---

## License

MIT License.

Built for the Agentic AI Bootcamp Hackathon 2026 at Amritapuri.
