import re
from . import config

RULES = {
    "keylogging": [
        ("keyboard hook library", r"pynput|keyboard\.Listener|on_press"),
        ("keystroke buffering", r"key\.char|word_buffer|keystroke|\[ENTER\]|flush.*key"),
    ],
    "credential_harvesting": [
        ("credential keywords", r"password|passwd|credential|api[_-]?key|secret|token"),
        ("financial/pii patterns", r"cvv|ssn|credit_card|private_key|otp|2fa"),
    ],
    "screen_capture": [
        ("screen capture api", r"pyautogui\.screenshot|ImageGrab|mss|screenshot\("),
    ],
    "webcam_capture": [
        ("camera capture api", r"cv2\.VideoCapture|webcam|camera_index|VideoCapture\("),
    ],
    "clipboard_theft": [
        ("clipboard access", r"pyperclip|clipboard_steal|clipboard_get|paste buffer"),
    ],
    "c2_http": [
        ("c2 endpoints", r"/register|/exfil|/qr/|command_queue|/command/"),
        ("beaconing requests", r"requests\.(get|post)\(.*c2|session\.(get|post)"),
    ],
    "c2_qr_channel": [
        ("qr encoding of commands", r"qrcode|QRCode|encode_command_to_qr"),
        ("qr decoding loop", r"QRCodeDetector|detectAndDecode|capture_qr_screenshot"),
    ],
    "data_exfiltration": [
        ("base64 exfil encoding", r"base64\.b64encode|b64encode\("),
        ("exfil buffers", r"exfil|send.*screenshot|data.*exfiltrat"),
    ],
    "persistence_registry": [
        ("registry run key", r"winreg|CurrentVersion\\Run|SetValueEx"),
    ],
    "persistence_scheduled_task": [
        ("scheduled task creation", r"schtasks|scheduled_task|/sc.*minute"),
    ],
    "persistence_startup_folder": [
        ("startup folder copy", r"Start Menu.*Startup|startup_folder|Programs\\Startup"),
    ],
    "self_destruct": [
        ("self delete logic", r"self_destruct|os\._exit|goto loop|del .*exe_path"),
        ("wipe on exit", r"self.delete|SELF-DESTRUCT|cleanup.*traces"),
    ],
    "anti_forensics": [
        ("event log clearing", r"wevtutil|clear_event_logs|wipe_temp|cl.*log"),
    ],
    "anti_vm": [
        ("vm/debugger checks", r"IsDebuggerPresent|check_vm|vbox|vmware|hyper-v|VM_MAC|parallels"),
    ],
    "stealth_execution": [
        ("hidden window flags", r"CREATE_NO_WINDOW|hide_console|ShowWindow.*0"),
        ("headless execution", r"--headless|noconsole|windowed.*pyinstaller"),
    ],
    "code_execution": [
        ("process spawning", r"subprocess\.(run|Popen)|os\.system\("),
        ("dynamic eval", r"\beval\(|\bexec\("),
    ],
    "tool_download": [
        ("downloader", r"urllib\.request|urlretrieve|wget |DownloadString|Invoke-WebRequest|IEX|Invoke-Expression|chromedriver"),
    ],
    "decoy_social_engineering": [
        ("decoy document", r"decoy|Invoice|os\.startfile|lure"),
    ],
    "reverse_shell": [
        ("raw socket connect", r"socket\.socket|socket\.AF_INET|\.connect\("),
        ("stdout/stdin redirection", r"os\.dup2|fileno\(\)"),
        ("interactive shell spawn", r'\["/bin/sh"|cmd\.exe|/bin/bash.*-i'),
    ],
}

IOC_PATTERNS = {
    "url": r"https?://[\w\-.]+(?:/[\w\-./]*)?",
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "email": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
}


def scan_secrets(code):
    hits = []
    for name, pat in config.SECRET_PATTERNS.items():
        for m in re.finditer(pat, code):
            hits.append({"type": name, "redacted": True,
                         "preview": m.group(0)[:6] + "***REDACTED***"})
    return hits


def extract_iocs(code):
    iocs = []
    for kind, pat in IOC_PATTERNS.items():
        for m in re.finditer(pat, code):
            val = m.group(0)
            if kind == "ip" and val.startswith(("127.", "0.", "192.168.", "10.")):
                continue
            iocs.append({"type": kind, "value": val})
    seen, out = set(), []
    for i in iocs:
        if i["value"] not in seen:
            seen.add(i["value"])
            out.append(i)
    return out


def detect_behaviors(code):
    lines = code.splitlines()
    detections = {}
    for behavior, rules in RULES.items():
        evidence = []
        for rule_name, pat in rules:
            for ln, line in enumerate(lines, 1):
                if re.search(pat, line, re.IGNORECASE):
                    evidence.append({"rule": rule_name, "line": ln,
                                     "snippet": line.strip()[:140]})
        if evidence:
            detections[behavior] = {"hits": len(evidence), "evidence": evidence[:6]}
    return detections


def classify_artifact(name, code):
    n = name.lower()
    if n.endswith(".ps1"):
        return "powershell_script"
    if n.endswith((".exe", ".dll", ".scr")):
        return "windows_executable"
    if n.endswith((".sh", ".bash")):
        return "shell_script"
    if "dropper" in n or "sfx" in n or "payload" in n:
        return "dropper_candidate"
    if n.endswith(".py"):
        return "python_script"
    return "unknown"


def benign_indicators(detections):
    sev = config.SEVERITY
    return not any(sev.get(b, 0) >= 2 for b in detections)
