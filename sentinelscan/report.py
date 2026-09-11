def build_report(state):
    L = []
    L.append(f"# Incident Report: `{state.artifact_name}`")
    L.append("")
    L.append(f"**Verdict:** {state.decision}  |  **Risk:** {state.risk.upper()}  |  "
             f"**Confidence:** {state.confidence}  |  **LLM layer:** {state.llm_name}")
    L.append("")
    L.append(f"**Routing reason:** {state.decision_reason}")
    L.append("")
    L.append("## Analyst summary")
    L.append(state.summary)
    L.append("")
    L.append("## Confidence breakdown (auditable)")
    for k, v in state.confidence_breakdown.items():
        L.append(f"- {k}: {v}")
    if state.red_flags:
        L.append("")
        L.append("## Red flags (independent risk signal)")
        for rf in state.red_flags:
            L.append(f"- RED FLAG: {rf}")
    L.append("")
    L.append("## Behavior detections (each claim cited to ATT&CK)")
    for b, det in state.detections.items():
        L.append("")
        L.append(f"### {b} ({det['hits']} hits)")
        for m in state.attack_mappings.get(b, [])[:2]:
            L.append(f"- maps to **{m['technique_id']} {m['technique_name']}** "
                     f"(retrieval sim={m['score']})")
        for ev in det["evidence"][:3]:
            L.append(f"  - L{ev['line']}: `{ev['snippet']}`")
    if state.iocs:
        L.append("")
        L.append("## IOCs")
        for i in state.iocs[:10]:
            L.append(f"- {i['type']}: `{i['value']}`")
    if state.secrets:
        L.append("")
        L.append(f"## Secrets: {len(state.secrets)} found - redacted, never transmitted.")
    L.append("")
    L.append("## Recommendations")
    if state.decision == "ESCALATE":
        L.append("- Human analyst review required. Full reasoning trace attached.")
    joined = " ".join(state.detections)
    if "persistence" in joined:
        L.append("- Check autostart locations on affected hosts.")
    if "keylogging" in state.detections or "credential_harvesting" in state.detections:
        L.append("- Force credential rotation for affected users.")
    if state.detections:
        L.append("- Isolate host; collect memory and timeline artifacts.")
    else:
        L.append("- No action; sample consistent with benign software.")
    return "\n".join(L)
