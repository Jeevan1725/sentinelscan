# SentinelScan — One-Page Write-up

**Track 03 · Trustworthy, Responsible & Secure AI** — Agentic AI Hackathon 2026

## Problem

SOC triage drowns analysts. Tools emit verdicts nobody can audit, and low-confidence
cases get rubber-stamped. Analysts need a system that shows its work and knows when
to escalate.

## What it is

Five specialized agents cooperate over shared state:

1. **Intake** — classifies the artifact
2. **Static analyzer** — 19 behavior rules via FastMCP tools
3. **RAG retriever** — cites ATT&CK techniques retrieved from a 25-chunk vector store
4. **Scorer** — computes confidence (documented weighted sum) and risk (independent red-flag class)
5. **Router** — ALLOW / ESCALATE / AUTO_REPORT

A second intake path accepts **live process and network snapshots**, so the same
pipeline runs on running malware in real time.

## Confidence and risk — scored separately

- **Confidence** = `0.70·detections + 0.20·retrieval + 0.10·prior − benign_penalty`
- **Risk** = independent red-flag classification. *Self-destruct + persistence* ⇒ CRITICAL regardless of confidence.

A high-confidence, low-severity artifact can ALLOW. A low-confidence, high-severity
artifact always ESCALATES. **Safety is not a threshold on a single number.**

## Threshold calibration

`eval/calibrate.py` sweeps thresholds against a 25-sample gold set. At 0.70, precision
is 1.00 with zero benign false-positives and recall 0.67. Below 0.70 only recall
improves; at 0.80, recall collapses to 0.10. The threshold is data-driven.

## Evaluation

| Metric | Value |
|---|---|
| Behavior precision | 0.863 |
| Behavior recall | 0.955 |
| Malicious flagged | 21 / 21 |
| False-critical on benign | 0 |
| Escalation precision | 1.00 |

## Detection modes

- **Static:** reads source text, detects code capabilities
- **Live:** psutil snapshots of processes + network connections

CyberRecon's QR-C2 module scores **AUTO_REPORT at 0.79** statically and
**AUTO_REPORT at 0.75** live — both modes independently reach the same verdict.

## Observability

Every agent step, tool call, and pause is traced with its reason. Full JSON trace
viewable in the Streamlit UI.

## Resilience

- Retriever: TF-IDF (pure Python, offline)
- LLM: Groq if key present, local rule-synthesizer otherwise
- Verdicts work fully offline

## Security & data care

- No secrets in repo; `.env` git-ignored
- Artifacts never leave the machine; LLM sees only behavior names + confidence
- Secrets redacted before display

## Demo

Static: `cyberrecon_01_qr_c2.py` → AUTO_REPORT with T1102.
Red-flag: `mal_implant_red_flag.py` → ESCALATE + CRITICAL.
Live: start monitor, launch CyberRecon's QR decoder, confidence climbs to 0.75 and crosses the auto-report bar in real time.