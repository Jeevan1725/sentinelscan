# SentinelScan configuration. Every weight documented: the scorer must be auditable.

W_DETECTIONS = 0.70
W_RETRIEVAL = 0.20
W_PRIOR = 0.10
DET_DENOMINATOR = 14.0
AUTO_REPORT_THRESHOLD = 0.70
BENIGN_PENALTY = 0.20

SEVERITY = {
    "c2_qr_channel": 3, "c2_http": 3, "keylogging": 3, "credential_harvesting": 3,
    "persistence_registry": 3, "persistence_scheduled_task": 3,
    "persistence_startup_folder": 3, "self_destruct": 3, "tool_download": 3,
    "data_exfiltration": 2, "screen_capture": 2, "webcam_capture": 2,
    "clipboard_theft": 2, "anti_forensics": 2, "anti_vm": 2, "stealth_execution": 2,
    "code_execution": 2, "decoy_social_engineering": 1, "reverse_shell": 3,
}

CRITICAL_BEHAVIOR = "self_destruct"
CRITICAL_COMPANIONS = ["persistence_registry", "persistence_scheduled_task",
                       "persistence_startup_folder"]

SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "private_key_block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "generic_api_token": r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*[\'\"][A-Za-z0-9_\-]{20,}[\'\"]",
}

TOP_K_TECHNIQUES = 3
