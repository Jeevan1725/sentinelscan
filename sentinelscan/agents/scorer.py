from .. import config
from ..analyzer import benign_indicators


def run(state, tracer):
    sev = config.SEVERITY
    det_raw = sum(sev.get(b, 1) * min(d["hits"], 3) for b, d in state.detections.items())
    det_score = min(1.0, det_raw / config.DET_DENOMINATOR)

    if state.attack_mappings:
        best_scores = [max((m["score"] for m in v), default=0.0)
                       for v in state.attack_mappings.values()]
        retrieval_score = sum(best_scores) / len(best_scores)
    else:
        retrieval_score = 0.0

    prior = {"dropper_candidate": 1.0, "windows_executable": 0.7,
             "powershell_script": 0.5}.get(state.artifact_type, 0.0)

    penalty = config.BENIGN_PENALTY if (state.detections and benign_indicators(state.detections)) else 0.0

    confidence = (config.W_DETECTIONS * det_score
                  + config.W_RETRIEVAL * retrieval_score
                  + config.W_PRIOR * prior) - penalty
    state.confidence = round(max(0.0, min(1.0, confidence)), 3)
    state.confidence_breakdown = {
        "detections (w=0.70)": round(config.W_DETECTIONS * det_score, 3),
        "rag_retrieval (w=0.20)": round(config.W_RETRIEVAL * retrieval_score, 3),
        "artifact_prior (w=0.10)": round(config.W_PRIOR * prior, 3),
        "benign_penalty": -penalty,
    }

    red_flags = []
    d = state.detections
    if config.CRITICAL_BEHAVIOR in d and any(c in d for c in config.CRITICAL_COMPANIONS):
        red_flags.append("self-destruct combined with persistence = real implant")
    if state.secrets:
        red_flags.append("live secrets present in artifact")
    state.red_flags = red_flags

    if red_flags or state.confidence >= 0.90:
        state.risk = "critical"
    elif state.confidence >= config.AUTO_REPORT_THRESHOLD:
        state.risk = "high"
    elif state.confidence >= 0.45:
        state.risk = "medium"
    else:
        state.risk = "low"

    tracer.log("scorer-agent", "score",
               detail=f"confidence={state.confidence} risk={state.risk} "
                      f"breakdown={state.confidence_breakdown}",
               reason="Confidence is a documented weighted sum - auditable, not a vibe.")
    if red_flags:
        tracer.log("scorer-agent", "red_flag",
                   detail="; ".join(red_flags),
                   reason="Red flags override numeric confidence (safety governor).")
    return state
