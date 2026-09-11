BEHAVIOR_QUERIES = {
    "keylogging": "keylogger keystroke capture on_press input capture credentials",
    "credential_harvesting": "credential theft password token api key harvesting",
    "screen_capture": "screen capture screenshot surveillance",
    "webcam_capture": "webcam video capture camera surveillance",
    "clipboard_theft": "clipboard data collection",
    "c2_http": "command and control http beacon web endpoints",
    "c2_qr_channel": "qr code visual channel browser isolation c2 web service",
    "data_exfiltration": "exfiltration base64 encoded data over c2",
    "persistence_registry": "registry run key autostart persistence",
    "persistence_scheduled_task": "scheduled task persistence",
    "persistence_startup_folder": "startup folder persistence autostart",
    "self_destruct": "self deletion data destruction anti-forensics",
    "anti_forensics": "clear event logs indicator removal anti-forensics",
    "anti_vm": "virtualization sandbox debugger evasion",
    "stealth_execution": "hidden window headless no console hide artifacts",
    "code_execution": "python command interpreter subprocess execution",
    "tool_download": "download tools ingress tool transfer downloader",
    "reverse_shell": "reverse shell socket connect interactive shell remote access",
    "decoy_social_engineering": "decoy document user execution social engineering",
    "beaconing": "c2 beacon command control callback channel polling heartbeat",
}


def run(state, tracer, retriever):
    state.attack_mappings = {}
    for behavior in state.detections:
        q = BEHAVIOR_QUERIES.get(behavior, behavior.replace("_", " "))
        res = retriever.search(q, k=3)
        state.attack_mappings[behavior] = res
        best = res[0] if res else None
        tracer.log("retriever-agent", "retrieve",
                   detail=f"{behavior} -> {best['technique_id'] if best else 'no match'} "
                          f"(sim={best['score'] if best else 0})",
                   reason="Every claim must trace to a retrieved ATT&CK chunk (RAG grounding).")
    return state
