from .. import config
from ..llm import get_llm


def run(state, tracer):
    llm = get_llm()
    state.llm_name = llm.name
    state.summary = llm.summarize(state)

    if state.risk == "critical":
        state.decision, state.decision_reason = "ESCALATE", (
            "Critical risk class (red flag or confidence>=0.90) - "
            "never auto-approve; immediate human analyst review.")
    elif state.confidence >= config.AUTO_REPORT_THRESHOLD and not state.red_flags:
        state.decision, state.decision_reason = "AUTO_REPORT", (
            f"Confidence {state.confidence} >= {config.AUTO_REPORT_THRESHOLD} "
            "and no red flags.")
    elif state.detections or state.confidence >= 0.45:
        state.decision, state.decision_reason = "ESCALATE", (
            f"Uncertain band (confidence {state.confidence}, "
            f"{len(state.detections)} behavior cluster(s)) - route to human "
            "analyst with the full reasoning trace.")
    else:
        state.decision, state.decision_reason = "ALLOW", (
            f"No malicious behaviors detected and confidence {state.confidence} "
            "< 0.45 - consistent with benign software; allow and monitor.")

    tracer.log("router-agent", "route",
               detail=f"decision={state.decision} llm={state.llm_name}",
               reason=state.decision_reason)
    return state
