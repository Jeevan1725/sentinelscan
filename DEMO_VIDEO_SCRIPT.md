# 3-Minute Demo Video Script

**Setup before recording:**
- Two terminals in `sentinelscan` with `.venv` activated
- One terminal in `cyberrecon (4)/cyberrecon` with its venv activated
- Browser open at `http://localhost:8501`

| Time | Shot | Say |
|---|---|---|
| 0:00–0:20 | VS Code → CyberRecon folder | "This is CyberRecon — a real QR-based C2 framework. It bypasses browser isolation because pixels aren't filtered. We built the attack. Now watch SentinelScan catch it." |
| 0:20–0:40 | Browser → Streamlit title | "SentinelScan: five agents, FastMCP tools, 25 ATT&CK techniques, and a confidence check that knows when to escalate." |
| 0:40–1:00 | UI: `cyberrecon_01_qr_c2.py` | "A real CyberRecon module. Detected as QR-C2, cited to T1102 — the Mandiant 2024 technique. T1071 for HTTP, T1041 for exfiltration. AUTO_REPORT at 0.83." |
| 1:00–1:20 | UI: `mal_implant_red_flag.py` | "Confidence 0.82 — above the auto-report bar. But self-destruct plus persistence is an **independent** red flag. CRITICAL. Never auto-approved." |
| 1:20–1:50 | Terminal 1: `python watch_live.py --interval 3`<br>Terminal 2: `python qr_decoder.py --c2 http://127.0.0.1:8443 --victim-id <id> --interval 5` | "Live monitor. No file — just running processes. Watch the confidence climb: 0.66, then **0.75 — above the auto-report bar**. T1102 cited live. CyberRecon caught in real time." |
| 1:50–2:10 | Terminal: `python eval/run_eval.py` | "25-sample gold set. Precision 0.86, recall 0.96. Every malicious sample flagged. Zero false-critical on benign. Gate: PASS." |
| 2:10–2:25 | Terminal: `python eval/calibrate.py` | "Why 0.70? We swept every threshold. At 0.70 precision is 1.00 with zero benign false-positives. Data-driven." |
| 2:25–2:40 | Ctrl+C CyberRecon | "Attack stopped. Fully offline verdicts." |
| 2:40–3:00 | Closing slide | "Static and live detection. Separate confidence and risk. A red-flag governor that refuses to auto-approve a real implant. Same team built both sides. That's trustworthy AI." |