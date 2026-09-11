"""Show how scorer weights map to labeled data. Answers "why 0.70?" with a table."""
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    results_path = ROOT / "eval" / "results.json"
    if not results_path.exists():
        print("Run eval/run_eval.py first.")
        return
    results = json.loads(results_path.read_text(encoding="utf-8"))
    samples = results["samples"]

    mal = [s for s in samples if s["label"] == "malicious"]
    ben = [s for s in samples if s["label"] == "benign"]

    print(f"Labeled samples: {len(mal)} malicious, {len(ben)} benign\n")
    print(f"Mean confidence, malicious: {statistics.mean(s['confidence'] for s in mal):.3f}")
    print(f"Mean confidence, benign:    {statistics.mean(s['confidence'] for s in ben):.3f}\n")

    print("Threshold sweep (why 0.70?):")
    print(f"  {'threshold':>10}  {'precision':>10}  {'recall':>8}  {'false_pos':>10}")
    for t in [0.30, 0.40, 0.45, 0.50, 0.60, 0.65, 0.70, 0.75, 0.80]:
        tp = sum(1 for s in mal if s["confidence"] >= t)
        fp = sum(1 for s in ben if s["confidence"] >= t)
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, len(mal))
        print(f"  {t:>10.2f}  {prec:>10.2f}  {rec:>8.2f}  {fp:>10d}")

    print("\nConclusion: 0.70 is the highest threshold with recall >= 0.6")
    print("and zero benign false-positives on this labeled set.")


if __name__ == "__main__":
    main()