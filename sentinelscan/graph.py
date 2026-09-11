from dataclasses import dataclass, field
from pathlib import Path
from .tracer import Tracer
from .retriever import get_retriever
from .agents import intake, analyzer_agent, retriever_agent, scorer, router_agent
from . import report as report_mod


@dataclass
class PipelineState:
    artifact_name: str
    code: str
    artifact_type: str = "unknown"
    detections: dict = field(default_factory=dict)
    iocs: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    attack_mappings: dict = field(default_factory=dict)
    confidence: float = 0.0
    confidence_breakdown: dict = field(default_factory=dict)
    risk: str = "low"
    red_flags: list = field(default_factory=list)
    decision: str = "ESCALATE"
    decision_reason: str = ""
    summary: str = ""
    llm_name: str = ""
    report_md: str = ""
    retriever_backend: str = ""


class SimpleOrchestrator:
    """Deterministic multi-agent pipeline: intake -> analyzer -> retriever
    -> scorer -> router, with shared state and a tracer logging every handoff."""

    def __init__(self):
        self.retriever, self.retriever_backend = get_retriever()

    def run(self, state):
        t = Tracer()
        state.retriever_backend = self.retriever_backend
        t.log("orchestrator", "start",
              detail=f"artifact={state.artifact_name}",
              reason="New triage request received.")
        intake.run(state, t)
        analyzer_agent.run(state, t)
        retriever_agent.run(state, t, self.retriever)
        scorer.run(state, t)
        router_agent.run(state, t)
        state.report_md = report_mod.build_report(state)
        t.log("orchestrator", "done",
              detail=f"decision={state.decision} confidence={state.confidence}",
              reason="Pipeline complete; report assembled from agent outputs only.")
        self._tracer = t
        state._trace_events = t.events
        return state


def try_langgraph_pipeline():
    try:
        from langgraph.graph import StateGraph, END
    except Exception:
        return None
    from typing import TypedDict

    class S(TypedDict, total=False):
        st: PipelineState

    orch = SimpleOrchestrator()

    def node(fn):
        def _n(s):
            fn(s["st"], orch._tracer)
            return {"st": s["st"]}
        return _n

    g = StateGraph(S)
    g.add_node("intake", node(intake.run))
    g.add_node("analyzer", node(analyzer_agent.run))
    g.add_node("retriever",
               lambda s: (retriever_agent.run(s["st"], orch._tracer, orch.retriever),
                          {"st": s["st"]})[1])
    g.add_node("scorer", node(scorer.run))
    g.add_node("router", node(router_agent.run))
    g.set_entry_point("intake")
    g.add_edge("intake", "analyzer")
    g.add_edge("analyzer", "retriever")
    g.add_edge("retriever", "scorer")
    g.add_edge("scorer", "router")
    g.add_edge("router", END)
    return g.compile()


def analyze_artifact(path_or_code, name=None):
    p = Path(str(path_or_code))
    if p.exists():
        code = p.read_text(encoding="utf-8", errors="ignore")
        name = name or p.name
    else:
        code, name = str(path_or_code), name or "pasted_code"
    state = PipelineState(artifact_name=name, code=code)
    return SimpleOrchestrator().run(state)
def analyze_live_signals(detections, host="localhost"):
    """
    Run the existing pipeline on a live-process snapshot instead of a file.
    Reuses analyzer_agent, retriever, scorer, router - only the intake differs.
    """
    from .agents import analyzer_agent, retriever_agent, scorer, router_agent
    from .tracer import Tracer

    t = Tracer()
    state = PipelineState(artifact_name=f"<live:{host}>", code="")
    state.detections = detections
    state.artifact_type = "live_process"
    state.iocs = []
    state.secrets = []

    t.log("orchestrator", "start",
          detail=f"live monitor: host={host}",
          reason="Live system snapshot received.")

    # Skip intake-agent (already classified as live). Run analyzer's downstream steps.
    retriever, retriever_backend = get_retriever()
    state.retriever_backend = retriever_backend

    # Analyzer tool call is bypassed - detections were built from live signals.
    t.log("static-analyzer-agent", "tool_call",
           detail=f"live snapshot -> {len(detections)} behaviors",
           reason="Live process/network scan; not hard-coded.")

    retriever_agent.run(state, t, retriever)
    scorer.run(state, t)
    router_agent.run(state, t)

    t.log("orchestrator", "done",
          detail=f"decision={state.decision} confidence={state.confidence}",
          reason="Live pipeline complete.")
    state._trace_events = t.events
    return state