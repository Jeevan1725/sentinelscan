from .. import analyzer


def run(state, tracer):
    state.artifact_type = analyzer.classify_artifact(state.artifact_name, state.code)
    tracer.log("intake-agent", "classify",
               detail=f"{state.artifact_name} -> {state.artifact_type}",
               reason="Artifact type sets the prior and routes which tool set applies.")
    return state
