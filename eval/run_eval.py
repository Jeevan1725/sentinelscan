"""SentinelScan gold-set evaluation."""
import json
import sys
import statistics
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinelscan import analyze_artifact

ROOT = Path(__file__).resolve().parents[1]


def main():
    rows, tp = [], {"fp": 0, "fn": 0, "tp": 0}
    benign_critical, conf_mal, conf_ben = 0, [], []
    n_flagged_mal = n_mal = n_escalated_right = n_escalated = 0

    for line in (ROOT / "eval/gold_set.jsonl").read_text().splitlines():
        if not line.strip():
            continue
        g = json.loads(line)
        st = analyze_artifact(ROOT / g["file"])
        det = set(st.detections)
        exp = set(g["expected_behaviors"])
        tp["tp"] += len(det & exp)
        tp["fp"] += len(det - exp)
        tp["fn"] += len(exp - det)
        flagged = st.decision in ("AUTO_REPORT", "ESCALATE")
        if g["label"] == "malicious":
            n_mal += 1
            conf_mal.append(st.confidence)
            if flagged:
                n_flagged_mal += 1
        else:
            conf_ben.append(st.confidence)
            if st.risk == "critical":
                benign_critical += 1
        if st.decision == "ESCALATE":
            n_escalated += 1
            if g["label"] == "malicious":
                n_escalated_right += 1
        rows.append({"file": g["file"], "label": g["label"], "risk": st.risk,
                     "confidence": st.confidence, "decision": st.decision,
                     "detected": sorted(det)})

    prec = tp["tp"] / max(1, tp["tp"] + tp["fp"])
    rec = tp["tp"] / max(1, tp["tp"] + tp["fn"])
    results = {
        "behavior_precision": round(prec, 3),
        "behavior_recall": round(rec, 3),
        "triage_flag_rate_malicious": f"{n_flagged_mal}/{n_mal}",
        "false_critical_on_benign": benign_critical,
        "mean_confidence_malicious": round(statistics.mean(conf_mal), 3) if conf_mal else 0.0,
        "mean_confidence_benign": round(statistics.mean(conf_ben), 3) if conf_ben else 0.0,
        "escalation_precision": round(n_escalated_right / max(1, n_escalated), 3),
        "samples": rows,
    }
    print(json.dumps(results, indent=2))
    (ROOT / "eval/results.json").write_text(json.dumps(results, indent=2))
    ok = benign_critical == 0 and prec >= 0.6 and n_flagged_mal == n_mal
    print("")
    print("GATE:", "PASS" if ok else "NEEDS TUNING")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
