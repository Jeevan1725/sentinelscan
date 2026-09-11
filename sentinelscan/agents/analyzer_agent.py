from .. import analyzer
from ..tools import mcp_server as tools


def run(state, tracer):
    state.detections = tools.scan_artifact(state.code)["behaviors"]
    state.iocs = tools.extract_indicators(state.code)["iocs"]
    state.secrets = tools.scan_secrets(state.code)["secrets"]

    n_rules = sum(d["hits"] for d in state.detections.values())
    tracer.log("static-analyzer-agent", "tool_call",
               detail=f"scan_artifact -> {len(state.detections)} behaviors, "
                      f"{n_rules} rule hits",
               reason="Called via FastMCP tool; analysis is not hard-coded in the agent.")
    tracer.log("static-analyzer-agent", "tool_call",
               detail=f"extract_indicators -> {len(state.iocs)} IOCs; "
                      f"scan_secrets -> {len(state.secrets)} secrets (redacted)",
               reason="Security & data care: secrets never surface unredacted.")
    return state
