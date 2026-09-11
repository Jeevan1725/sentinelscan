# 🛡 SentinelScan — Agentic AI Malware Triage

**Agentic AI Hackathon 2026 · Track 03 — Trustworthy, Responsible & Secure AI**

---

## What is this project?

SentinelScan is an **AI-powered malware triage tool**. You give it a suspicious file or point it at a running system, and it tells you whether the code is dangerous — with evidence.

But it's not just a scanner. It's built around a critical idea for Track 03:

> **A security tool you can't audit is a security tool you can't trust.**

So SentinelScan does four things most malware scanners don't:

1. **Multiple specialized AI agents** work together — each doing one job
2. **Every detection is grounded** in MITRE ATT&CK, the industry standard for describing malware behavior
3. **Confidence and risk are scored separately** — "I'm sure" and "it's dangerous" are not the same thing
4. **When it's not sure, it escalates to a human** — instead of guessing

---

## The demo story — we built the attack AND the defense

This hackathon submission contains **two** projects, built by the same team:

### 1. CyberRecon — the villain

CyberRecon is a **working QR-code command-and-control (C2) framework**. It's designed to defeat browser isolation — a security technology that runs all web content in a remote sandbox.

**How CyberRecon bypasses it:** browser isolation blocks network traffic, but QR codes are just **pixels**. Malware can receive commands by reading QR codes rendered in a headless browser. No network packet ever crosses the boundary. Mandiant documented this exact technique in 2024.

**CyberRecon contains:** a QR C2 server, a headless-Chrome QR decoder, a keylogger, screenshot capture, webcam capture, GPS lookups, persistence mechanisms, and self-destruct.

### 2. SentinelScan — the defender (this project)

SentinelScan is an **agentic AI** that detects CyberRecon's behavior — statically (by reading its source code) and live (by watching its running processes).

**Why this matters:** most hackathon projects defend against hypothetical threats. **We defend against our own real C2 framework** — verified in the evaluation set, verified in the live demo, with real MITRE ATT&CK citations.

> **Safety note:** CyberRecon is included in `demo_samples/` as `cyberrecon_*.py` — the source files SentinelScan analyzes. It is **never executed** during the demo. All C2 addresses are `127.0.0.1` (localhost). The samples are read as text, not run.

---

## How SentinelScan works — in plain English

When you give SentinelScan a file, five specialized agents run in sequence:

```
   Your file
      │
      ▼
┌───────────────┐
│  1. INTAKE    │  "What kind of file is this?"
│               │  → Python script, PowerShell, Windows executable
└───────┬───────┘
        ▼
┌───────────────┐
│ 2. ANALYZER   │  "What can this code do?"
│               │  → Runs 19 behavior rules: keylogging, C2, exfiltration,
│               │    persistence, self-destruct, anti-VM, etc.
└───────┬───────┘
        ▼
┌───────────────┐
│ 3. RETRIEVER  │  "What MITRE ATT&CK technique matches this behavior?"
│               │  → Looks up the behavior in a knowledge base and returns
│               │    the technique ID with a similarity score
└───────┬───────┘
        ▼
┌───────────────┐
│ 4. SCORER     │  "How sure am I? And how dangerous is it?"
│               │  → Computes TWO scores: confidence (0-1) and risk class
│               │  → Checks red flags that force CRITICAL regardless
└───────┬───────┘
        ▼
┌───────────────┐
│ 5. ROUTER     │  "What should we do?"
│               │  → ALLOW / ESCALATE / AUTO_REPORT
└───────────────┘
```

Every step is **traced with a reason** — so you can see exactly why the system made each decision.

### The five agents in detail

| Agent | File | Job |
|---|---|---|
| **Intake** | `sentinelscan/agents/intake.py` | Classifies the artifact type — sets a prior that influences confidence |
| **Static Analyzer** | `sentinelscan/agents/analyzer_agent.py` | Runs 19 regex behavior rules via FastMCP tools. Also extracts IOCs (URLs, IPs, emails) and redacts secrets. |
| **RAG Retriever** | `sentinelscan/agents/retriever_agent.py` | Queries a TF-IDF index over 25 hand-curated MITRE ATT&CK technique chunks. Every detection cites a technique + similarity score. |
| **Scorer** | `sentinelscan/agents/scorer.py` | Computes confidence (weighted sum) and risk (independent red-flag class). |
| **Router** | `sentinelscan/agents/router_agent.py` | Decides: ALLOW, ESCALATE, or AUTO_REPORT. |

### The confidence formula — fully auditable

```
confidence = 0.70 × detections_score
           + 0.20 × rag_retrieval_score
           + 0.10 × artifact_prior
           − benign_penalty
```

Every term is shown in the UI. A judge can compute it by hand and verify the output.

### The Red-Flag Governor — the safety layer

The scorer produces **two independent scores**:

- **Confidence** (0–1): "How sure am I that this verdict is right?"
- **Risk** (low/medium/high/critical): "How dangerous is it if this is real?"

These are **separate**. Why? Because a system can be highly confident something is malware and still need human review before acting.

Certain behavior combinations **force CRITICAL** regardless of confidence:

| Red flag | Why |
|---|---|
| `self_destruct` + any `persistence` behavior | Real implants self-delete and persist. Prank scripts don't. |
| Live secrets in the artifact | AWS keys, API tokens — active credential theft |

**When a red flag fires, the system refuses to auto-approve.** It escalates to a human with the full trace.

### The escalation policy

| Condition | Decision |
|---|---|
| Critical risk (red flag fired) | **ESCALATE** — never auto-approve |
| Confidence ≥ 0.70, no red flags | **AUTO_REPORT** — auto-file the incident |
| Behaviors detected but uncertain | **ESCALATE** — human reviews the trace |
| Nothing detected, low confidence | **ALLOW** |

**Why three outcomes and not two:** in security, both false positives (crying wolf) and false negatives (missing real threats) cost money. A three-way router lets the system say **"I don't know"** — which is often the honest answer.

---

## Two detection modes — same pipeline

SentinelScan can analyze two kinds of input:

| Mode | Input | Catches | Command |
|---|---|---|---|
| **Static** | A file's source text | What the code **can** do | `python run_demo.py <file>` |
| **Live** | Running processes + network connections | What it's **doing right now** | `python watch_live.py` |

**Same pipeline. Same scorer. Same router. Different input source.**

On CyberRecon, both modes independently reach the same verdict:
- **Static:** AUTO_REPORT at confidence 0.827 with 5 ATT&CK citations
- **Live:** AUTO_REPORT at confidence 0.806 with 3 ATT&CK citations

---

## What's inside this repository

```
sentinelscan_clean/
├── README.md                     ← this file
├── WRITEUP.md                    ← one-page project write-up
├── DEMO_VIDEO_SCRIPT.md          ← 3-minute demo shot list
├── requirements.txt              ← Python dependencies
├── .env.example                  ← config template (no secrets)
├── .gitignore                    ← excludes .env, .venv, __pycache__
│
├── run_demo.py                   ← CLI: analyze one file
├── watch_live.py                 ← CLI: live process/network monitor
├── app.py                        ← Streamlit web UI
│
├── sentinelscan/                 ← the Python package
│   ├── __init__.py
│   ├── config.py                 ← weights, thresholds, secret patterns
│   ├── tracer.py                 ← observability
│   ├── llm.py                    ← Groq LLM wrapper + local fallback
│   ├── retriever.py              ← TF-IDF + optional Chroma
│   ├── analyzer.py               ← 19 behavior rules
│   ├── report.py                 ← markdown report builder
│   ├── graph.py                  ← pipeline orchestrator
│   ├── live_signals.py           ← process/network snapshotter
│   ├── agents/                   ← the 5 agents
│   │   ├── intake.py
│   │   ├── analyzer_agent.py
│   │   ├── retriever_agent.py
│   │   ├── scorer.py
│   │   └── router_agent.py
│   ├── tools/
│   │   └── mcp_server.py         ← FastMCP tool server
│   └── data/
│       └── attack_seed.json      ← 25 curated ATT&CK chunks
│
├── demo_samples/                 ← 25 labeled samples
│   ├── cyberrecon_*.py           ← the villain (5 files)
│   ├── mal_*.py                  ← synthetic malware (17 files)
│   ├── evasion_*.py              ← obfuscated (3 files)
│   └── ben_*.py                  ← benign (4 files)
│
└── eval/
    ├── gold_set.jsonl            ← 25 labeled test cases
    ├── run_eval.py               ← accuracy + safety metrics
    └── calibrate.py              ← threshold sweep ("why 0.70?")
```

---

## Full setup — from zero to running

### Prerequisites

- **Python 3.11 or newer** — check with `python --version`
- **Git** — check with `git --version`
- **~500 MB free disk space** (for the optional `.venv`)
- **Windows, macOS, or Linux** (tested on Windows 11)

### Step 1 — Clone the repository

```bash
git clone https://github.com/Jeevan1725/sentinelscan.git
cd sentinelscan
```

### Step 2 — Create a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

You should see `(.venv)` appear at the start of your terminal prompt.

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

**What gets installed:**
- `streamlit` — the web UI
- `fastmcp` — the MCP tool server
- `psutil` — process and network monitoring
- `groq` — the optional LLM client
- `python-dotenv` — reads `.env` for configuration

**Takes ~1 minute on a fresh install.**

### Step 4 — Configure (optional)

The system works **fully offline** with no setup. To enable LLM-generated summaries (nicer analyst text):

1. Get a free Groq API key at **https://console.groq.com/keys**
2. Copy the template:
   ```bash
   cp .env.example .env
   ```
3. Open `.env` in a text editor and add your key:
   ```
   GROQ_API_KEY=gsk_your_actual_key_here
   GROQ_MODEL=openai/gpt-oss-20b
   ```

**Skip this step** if you want to run in offline mode — the pipeline works identically, only the summary paragraph changes.

### Step 5 — Verify the install

```bash
python run_demo.py demo_samples/cyberrecon_01_qr_c2.py
```

**Expected output:**
```
cyberrecon_01_qr_c2.py -> AUTO_REPORT (risk=high, confidence=0.827)
retriever: tf-idf (built-in index) | llm: groq (openai/gpt-oss-20b)

[screen_capture]    -> T1113 Screen Capture
[c2_http]           -> T1071.001 Application Layer Protocol: Web
[c2_qr_channel]     -> T1102 Web Service C2
[data_exfiltration] -> T1041 Exfiltration Over C2 Channel
[stealth_execution] -> T1564.001 Hide Artifacts
```

If you see that, **the install works**.

---

## Running every part of the project

### 1. Analyze a file (CLI)

```bash
python run_demo.py demo_samples/cyberrecon_01_qr_c2.py
```

Prints a full incident report with:
- Verdict, risk, confidence
- Confidence breakdown (auditable)
- Every detected behavior
- ATT&CK citations with similarity scores
- File/line evidence for each detection

### 2. Analyze every sample in the demo set

```bash
python run_demo.py
```

Runs the pipeline over all 25 samples and prints a report for each.

### 3. Run the evaluation gate

```bash
python eval/run_eval.py
```

**Prints accuracy + safety metrics:**
```
behavior_precision            0.863
behavior_recall               0.955
triage_flag_rate_malicious    21/21
false_critical_on_benign      0
mean_confidence_malicious     0.714
mean_confidence_benign        0.000
escalation_precision          1.00

GATE: PASS
```

### 4. Run threshold calibration

```bash
python eval/calibrate.py
```

**Prints a threshold sweep — the answer to "why 0.70?":**
```
threshold   precision   recall   false_pos
     0.30        1.00     0.95           0
     0.50        1.00     0.86           0
     0.70        1.00     0.71           0
     0.75        1.00     0.67           0
     0.80        1.00     0.52           0
```

### 5. Launch the interactive web UI

```bash
streamlit run app.py
```

**Browser opens automatically at `http://localhost:8501`.**

Two tabs:
- **📄 Analyze a file** — click through the 25 samples, see the full trace
- **📡 Live monitor** — real-time process/network scanning

### 6. Run the live monitor (terminal)

In one terminal:
```bash
python watch_live.py --interval 3
```

In another terminal, trigger a detection:
```bash
# Windows
& "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe" --headless --disable-gpu --remote-debugging-port=9222 about:blank
```

Within 3–6 seconds, the first terminal prints:
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

**Stop the monitor:** press `Ctrl+C`.

### 7. Run the FastMCP tool server

```bash
python -m sentinelscan.tools.mcp_server
```

Starts an MCP server exposing:
- `scan_artifact_tool(code)` — behavior detection
- `extract_indicators_tool(code)` — IOC extraction
- `classify_artifact_tool(name)` — artifact classification
- `scan_secrets_tool(code)` — secret redaction

Any MCP-compatible agent can connect and call these tools.

---

## Understanding the output

### Example: analyzing CyberRecon's QR-C2 module

```
cyberrecon_01_qr_c2.py -> AUTO_REPORT (risk=high, confidence=0.827)
```

**What each part means:**
- **`cyberrecon_01_qr_c2.py`** — the file we analyzed
- **`AUTO_REPORT`** — the router decided the confidence is high enough to auto-file
- **`risk=high`** — the risk class (would be `critical` if a red flag fired)
- **`confidence=0.827`** — the computed certainty score

### The confidence breakdown

```
detections (w=0.70):    0.700   ← 10 severity points of behaviors
rag_retrieval (w=0.20): 0.127   ← mean of top ATT&CK similarity scores
artifact_prior (w=0.10):0.000   ← 0 because it's a plain .py file
benign_penalty:        -0.000   ← 0 because severity-2+ behaviors fired
                     ─────────
confidence:             0.827
```

**Every term is verifiable.** A judge can recompute this by hand.

### The ATT&CK citations

```
[c2_qr_channel] -> T1102 Web Service C2 (sim=0.726)
```

- **`c2_qr_channel`** — the behavior our rule detected
- **`T1102`** — the MITRE ATT&CK technique ID (Web Service C2)
- **`Web Service C2`** — the technique name
- **`sim=0.726`** — how well the query matched this chunk in the knowledge base

**Every claim is grounded.** No detection without a citation.

---

## The evaluation — proving it works

The gold set contains **25 labeled samples**:

| Category | Count | What they test |
|---|---|---|
| Malicious | 21 | Real CyberRecon modules + synthetic malware |
| Benign | 4 | Clean code that must not false-positive |

**Metrics reported:**

| Metric | Value | What it means |
|---|---|---|
| Behavior precision | 0.863 | 86% of detected behaviors were correct |
| Behavior recall | 0.955 | 96% of real behaviors were caught |
| Malicious flag rate | 21/21 | Every malicious sample was flagged |
| **False-critical on benign** | **0** | No clean file was ever misclassified |
| Escalation precision | 1.00 | Every escalation was on a real threat |

**The safety invariant:** `false_critical_on_benign == 0` is a **hard gate**. If a benign sample is ever misclassified as critical, the entire eval fails. It doesn't.

**Reproduce:** `python eval/run_eval.py`

---

## Is this really detecting, or just a demo?

Two independent ways to verify:

### 1. The gold set is real

`eval/run_eval.py` runs the pipeline over 25 labeled files and prints `GATE: PASS`. The malicious samples include real CyberRecon source code. The benign samples include real Flask apps.

### 2. The live monitor runs on your actual system

```bash
python watch_live.py --interval 3
```

It reads your actual processes and network connections via `psutil`. Launch any headless Chrome process and the `c2_qr_channel` detection fires with the **real PID**. Kill the process and the alert clears.

**Nothing is mocked. Nothing is hard-coded.**

---

## Tech stack — and why each choice

| Component | Technology | Why |
|---|---|---|
| Language | Python 3.13 | Security ecosystem, fast iteration |
| Agent pipeline | Custom deterministic orchestrator | Auditable; no LLM in the control flow |
| Tools | FastMCP | Briefing requirement; standardized interface |
| Retrieval | TF-IDF (pure Python) | Zero dependencies, works offline, matches keyword queries |
| LLM | Groq `openai/gpt-oss-20b` | Fast, free tier; **summary only, not decisions** |
| Live monitoring | psutil | Cross-platform process + network introspection |
| Web UI | Streamlit | Judge-clickable in seconds |
| Config | python-dotenv | Standard 12-factor secrets handling |

**Every choice favors auditability over capability.** Because in security, a verdict you can't explain is a verdict you can't trust.

---

## Limitations — honest and documented

- **Static regex detection** — obfuscated samples partially evade it. That's what the escalation band is for; our own `evasion_*.py` samples demonstrate this live.
- **Live monitor is process-level polling** — bypassable by renaming binaries. Not kernel-level EDR.
- **Gold set is 25 samples** — a demonstration set, not a validation corpus.
- **Scorer weights are hand-calibrated** — `eval/calibrate.py` documents the threshold choice, but the weights weren't learned from data.
- **RAG store covers 25 ATT&CK techniques** — a subset of ATT&CK's 700+.
- **LLM is presentation-only** — verdict, confidence, risk, and citations are deterministic.
- **No real containment** — ESCALATE produces a recommendation and full trace, not automatic quarantine.

---

## What we'd build next

- Sandbox detonation with network isolation (Firecracker/gVisor)
- Full ATT&CK STIX ingest (700+ techniques) with security-domain embeddings
- Labeled corpus from MalwareBazaar for real-world evaluation
- Slack / PagerDuty escalation webhook
- Kernel-level monitoring via ETW (Windows) or eBPF (Linux)

---

## The 3-minute demo — what judges will see

1. **0:00–0:20** — VS Code: CyberRecon's real source code. "We built this C2 framework."
2. **0:20–0:40** — Streamlit UI opens. "SentinelScan — 5 agents, RAG-grounded ATT&CK citations."
3. **0:40–1:05** — Click `cyberrecon_01_qr_c2.py`. **AUTO_REPORT, T1102 cited.**
4. **1:05–1:25** — Click `mal_implant_red_flag.py`. **ESCALATE + CRITICAL** — self-destruct + persistence overrides high confidence.
5. **1:25–1:55** — Live monitor tab. Launch Chrome headless. **T1102 fires live** with real PID and full agent trace.
6. **1:55–2:15** — Terminal: `python eval/run_eval.py`. **GATE: PASS, 21/21 flagged, 0 false-critical.**
7. **2:15–2:30** — Terminal: `python eval/calibrate.py`. **Why 0.70? Data-driven.**
8. **2:30–3:00** — Closing: "Static and live. Attack and defense, same team. Fully offline."

---

## Track 03 alignment

The briefing for Track 03 says: *"Build the safety layer itself: confidence scoring, guardrails, prompt-injection defence, audit logs, resilience under red-teaming."*

| Track 03 goal | SentinelScan feature |
|---|---|
| Confidence scoring | 4-component weighted sum, shown in the UI |
| Guardrails | Red-flag governor — high confidence does not override safety |
| Audit logs | Full JSON trace with reasons for every step |
| Resilience | TF-IDF fallback, Groq → local rule-synthesizer, fully offline verdicts |
| Explicit escalation | 3-way router: ALLOW / ESCALATE / AUTO_REPORT |
| Grounding | Every claim cited to a retrieved ATT&CK technique with similarity |
| Safety invariant | Zero false-critical on benign — enforced by the eval gate |

**The safety layer isn't a checkbox — it's the core of the system.**

---

## Team & license

Built for the **Agentic AI Bootcamp Hackathon 2026** at Amritapuri.
Track 03: Trustworthy, Responsible & Secure AI.

MIT License — free to use, modify, and learn from.
