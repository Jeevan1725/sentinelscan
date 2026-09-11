"""SentinelScan CLI demo.
Usage: python run_demo.py [sample_file]
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinelscan import analyze_artifact


def show(state):
    print("=" * 70)
    print(f"  {state.artifact_name}  ->  {state.decision} (risk={state.risk}, "
          f"confidence={state.confidence})")
    print("=" * 70)
    print(f"  retriever: {state.retriever_backend} | llm: {state.llm_name}")
    for k, v in state.confidence_breakdown.items():
        print(f"    {k}: {v}")
    for b in state.detections:
        maps = state.attack_mappings.get(b, [])
        cite = f"{maps[0]['technique_id']} {maps[0]['technique_name']}" if maps else "n/a"
        print(f"  [{b}] -> {cite}")
    print(state.report_md[:900])
    print()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        show(analyze_artifact(sys.argv[1]))
    else:
        for f in sorted(Path("demo_samples").glob("*")):
            show(analyze_artifact(f))
