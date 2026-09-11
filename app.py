"""SentinelScan UI - streamlit run app.py
Two modes:
  - Analyze file   : drop a file, run the 5-agent pipeline
  - Live monitor   : watch processes/network, alerts stream in
"""
import sys
import time
import json
from pathlib import Path
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinelscan import analyze_artifact, analyze_live_signals
from sentinelscan.live_signals import snapshot

st.set_page_config(page_title="SentinelScan", page_icon="🛡", layout="wide")

st.title("🛡 SentinelScan — Agentic Malware Triage")
st.caption("Multi-agent pipeline · FastMCP tools · RAG-grounded ATT&CK citations · "
           "confidence + risk scored separately · human escalation · Track 03")

tab_file, tab_live = st.tabs(["📄 Analyze a file", "📡 Live monitor"])

# ─────────────────────────────────────────────────────────────────────────────
# TAB 1 — Static analysis
# ─────────────────────────────────────────────────────────────────────────────
with tab_file:
    samples = sorted(Path("demo_samples").glob("*"))
    choice = st.sidebar.selectbox("Demo sample",
                                  ["<upload or paste>"] + [s.name for s in samples])
    uploaded = st.sidebar.file_uploader("Or drop a file",
                                        type=["py", "ps1", "txt", "sh"])
    pasted = st.sidebar.text_area("...or paste code", height=120)

    code, name = None, None
    if uploaded:
        code, name = uploaded.read().decode("utf-8", "ignore"), uploaded.name
    elif pasted.strip():
        code, name = pasted, "pasted_snippet.py"
    elif choice != "<upload or paste>":
        code, name = (Path("demo_samples") / choice).read_text(), choice

    if not code:
        st.info("Upload a file, paste code, or choose a demo sample from the sidebar.")
    else:
        with st.spinner("Agents working..."):
            state = analyze_artifact(code, name=name)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Verdict", state.decision)
        c2.metric("Risk", state.risk.upper())
        c3.metric("Confidence", f"{state.confidence:.2f}")
        c4.metric("LLM layer", "Groq" if "groq" in state.llm_name
                  else "Local (sovereign)")
        st.progress(state.confidence, text="auto-report threshold: 0.70")

        colL, colR = st.columns(2)
        with colL:
            st.subheader("Agent trace")
            st.caption("Every step, tool call and pause — with the reason.")
            st.json([{"step": e.step, "agent": e.agent, "action": e.action,
                      "detail": e.detail, "reason": e.reason}
                     for e in state._trace_events])
        with colR:
            st.subheader("Confidence breakdown")
            st.table({"component": list(state.confidence_breakdown),
                      "contribution": list(state.confidence_breakdown.values())})
            if state.red_flags:
                for rf in state.red_flags:
                    st.error(f"🚩 RED FLAG: {rf}")

        st.subheader("Detections — ATT&CK citations")
        for b, det in state.detections.items():
            with st.expander(f"{b} ({det['hits']} hits)"):
                for m in state.attack_mappings.get(b, [])[:2]:
                    st.markdown(f"- **{m['technique_id']} {m['technique_name']}** "
                                f"(sim={m['score']})")
                for ev in det["evidence"][:4]:
                    st.code(f"L{ev['line']}: {ev['snippet']}", language="python")

        st.subheader("Report")
        st.markdown(state.report_md)
        if state.decision == "ESCALATE":
            st.error(f"ESCALATED — {state.decision_reason}")
        else:
            st.success(f"AUTO-REPORTED — {state.decision_reason}")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 2 — Live monitor (auto-refreshing, with agent traces)
# ─────────────────────────────────────────────────────────────────────────────
with tab_live:
    st.markdown("### 📡 Live process / network monitor")
    st.caption("Watches running processes and network connections. Runs the same "
               "5-agent pipeline on live signals.")

    # ---- Session state ----
    if "live_alerts" not in st.session_state:
        st.session_state.live_alerts = []
    if "live_last_sig" not in st.session_state:
        st.session_state.live_last_sig = None
    if "live_autorun" not in st.session_state:
        st.session_state.live_autorun = False

    # ---- Controls ----
    colA, colB = st.columns([1, 1])
    interval = colA.slider("Poll interval (s)", 2, 10, 3, key="live_interval")
    max_alerts = colB.slider("Alerts shown", 5, 50, 20, key="live_max")

    btn_col1, btn_col2, btn_col3 = st.columns(3)

    if btn_col1.button("▶ Start", type="primary",
                       use_container_width=True,
                       disabled=st.session_state.live_autorun):
        st.session_state.live_autorun = True
        st.rerun()

    if btn_col2.button("⏹ Stop", use_container_width=True,
                       disabled=not st.session_state.live_autorun):
        st.session_state.live_autorun = False
        st.rerun()

    if btn_col3.button("🗑 Clear", use_container_width=True):
        st.session_state.live_alerts = []
        st.session_state.live_last_sig = None
        st.rerun()

    # ---- Status ----
    if st.session_state.live_autorun:
        st.success(f"🟢 Monitoring — polling every {interval}s · "
                   f"{len(st.session_state.live_alerts)} alert(s) captured")
    else:
        st.info("⚪ Stopped. Click ▶ Start to begin monitoring.")

    # ---- One polling cycle ----
    if st.session_state.live_autorun:
        detections = snapshot()
        signature = tuple(sorted(detections.keys()))

        if signature and signature != st.session_state.live_last_sig:
            state = analyze_live_signals(detections)
            st.session_state.live_alerts.append({
                "ts": time.strftime("%H:%M:%S"),
                "verdict": state.decision,
                "risk": state.risk,
                "confidence": state.confidence,
                "reason": state.decision_reason,
                "red_flags": state.red_flags,
                "detections": state.detections,
                "attack_mappings": state.attack_mappings,
                "trace": [{"step": e.step, "agent": e.agent, "action": e.action,
                           "detail": e.detail, "reason": e.reason}
                          for e in state._trace_events],
            })
            st.session_state.live_last_sig = signature
        elif not signature:
            st.session_state.live_last_sig = None

    # ---- Render alerts ----
    alerts = st.session_state.live_alerts
    if not alerts:
        st.info("No alerts yet. Waiting for suspicious activity...")
    else:
        st.markdown(f"**{len(alerts)} alert(s)** — newest first")
        for alert in reversed(alerts[-max_alerts:]):
            verdict = alert["verdict"]
            color = {"ALLOW": "green",
                     "ESCALATE": "orange",
                     "AUTO_REPORT": "red"}.get(verdict, "gray")
            with st.expander(
                f"**{alert['ts']}** — :{color}[**{verdict}**] "
                f"· risk={alert['risk'].upper()} "
                f"· confidence={alert['confidence']:.3f}",
                expanded=(alert is alerts[-1]),
            ):
                st.write(f"**Reason:** {alert['reason']}")
                if alert["red_flags"]:
                    for rf in alert["red_flags"]:
                        st.error(f"🚩 {rf}")

                # ---- Detections with citations ----
                st.markdown("**Detections — ATT&CK citations**")
                for behavior, data in alert["detections"].items():
                    maps = alert["attack_mappings"].get(behavior, [])
                    cite = (f"**{maps[0]['technique_id']} "
                            f"{maps[0]['technique_name']}** (sim={maps[0]['score']})"
                            if maps else "n/a")
                    st.markdown(f"- `{behavior}` → {cite}")
                    for ev in data["evidence"][:2]:
                        st.caption(f"  · {ev['snippet'][:120]}")

                # ---- Agent trace ----
                with st.expander("🔍 Agent trace (observability)"):
                    st.caption("Every step, tool call and pause — with the reason.")
                    st.json(alert.get("trace", []))

    # ---- Auto-refresh: loop while running ----
    if st.session_state.live_autorun:
        time.sleep(interval)
        st.rerun()