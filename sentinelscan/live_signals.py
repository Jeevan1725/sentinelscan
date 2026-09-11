"""
Live signal extraction from running system state.

Produces the same behavior strings the static analyzer produces,
so the existing scorer/retriever/router work unchanged.

Detection modes:
  - Process scan:      headless browsers, keylog libs, exe-in-temp, child processes
  - Network scan:      suspicious ports, beaconing, sustained polling, cadence
"""
import psutil
import time as _time
from collections import defaultdict

KEYLOG_HINTS = ["pynput", "keylog", "keyboard"]
SUSPICIOUS_PORTS = {4444, 8443, 8080, 9001, 1337, 5555}
BEACON_MIN = 4
POLL_MIN = 3

# --- Polling cadence tracker (module-level, survives across snapshots) ---
_poll_history = {}   # host -> [timestamps]


def _detect_polling_cadence(host, now=None):
    """
    Detect machine-driven polling: same host contacted at regular intervals
    with low variance. Returns a dict if cadence detected, else None.
    """
    now = now or _time.time()
    hist = _poll_history.setdefault(host, [])
    hist.append(now)
    _poll_history[host] = hist[-10:]  # keep last 10

    if len(hist) < 4:
        return None
    intervals = [hist[i + 1] - hist[i] for i in range(len(hist) - 1)]
    if len(intervals) < 3:
        return None
    avg = sum(intervals) / len(intervals)
    variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
    # Regular intervals + low variance = machine polling
    if variance < 1.0 and 2 <= avg <= 15:
        return {"interval_avg": round(avg, 2), "samples": len(hist)}
    return None


def snapshot():
    """
    Take a snapshot of processes + network connections.
    Returns a behavior dict shaped like analyzer.detect_behaviors() output.
    """
    behaviors = {}
    evidence = defaultdict(list)

    # --- Process scan ---
    for p in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
        try:
            info = p.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        cmd = " ".join(info.get("cmdline") or []).lower()
        name = (info.get("name") or "").lower()
        exe = (info.get("exe") or "").lower()

        # Headless browser / QR decode loop candidate
        if ("chrome" in name or "chromium" in name) and "--headless" in cmd:
            behaviors["c2_qr_channel"] = behaviors.get("c2_qr_channel", 0) + 1
            evidence["c2_qr_channel"].append(
                f"pid {info['pid']} {name} --headless (QR decode loop candidate)")

        # Keylogger library loaded
        if "python" in name and any(h in cmd for h in KEYLOG_HINTS):
            behaviors["keylogging"] = behaviors.get("keylogging", 0) + 1
            evidence["keylogging"].append(
                f"pid {info['pid']} python process with keylog library in cmdline")

        # Executable running from temp folder
        if exe.endswith(".exe") and ("\\temp\\" in exe or "/tmp/" in exe):
            behaviors["stealth_execution"] = behaviors.get("stealth_execution", 0) + 1
            evidence["stealth_execution"].append(
                f"pid {info['pid']} {name} running from temp: {exe[:80]}")

        # [NEW] Child process detection: python spawning a headless browser
        if "python" in name:
            try:
                parent = psutil.Process(info["pid"])
                for child in parent.children(recursive=False):
                    child_name = (child.name() or "").lower()
                    if ("chrome" in child_name or "chromium" in child_name):
                        behaviors["c2_qr_channel"] = behaviors.get("c2_qr_channel", 0) + 1
                        evidence["c2_qr_channel"].append(
                            f"pid {info['pid']} python spawned child: {child.name()}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    # --- Network scan ---
    per_host = defaultdict(int)
    per_host_pids = defaultdict(set)
    for c in psutil.net_connections(kind="inet"):
        if c.status == "ESTABLISHED" and c.raddr:
            host = f"{c.raddr.ip}:{c.raddr.port}"
            per_host[host] += 1
            if c.pid:
                per_host_pids[host].add(c.pid)
            if c.raddr.port in SUSPICIOUS_PORTS:
                behaviors["c2_http"] = behaviors.get("c2_http", 0) + 1
                evidence["c2_http"].append(
                    f"connection to {host} (suspicious port {c.raddr.port})")

    for host, count in per_host.items():
        # Classic beaconing (many connections in one snapshot)
        if count >= BEACON_MIN:
            behaviors["beaconing"] = behaviors.get("beaconing", 0) + 1
            evidence["beaconing"].append(
                f"{count} connections to {host} (pids: {sorted(per_host_pids[host])})")

        # [NEW] Sustained polling to a C2-like port within one snapshot
        port = host.rsplit(":", 1)[-1]
        if count >= POLL_MIN and port in ("8443", "4444", "1337", "9001", "8080"):
            behaviors["c2_qr_channel"] = behaviors.get("c2_qr_channel", 0) + 1
            evidence["c2_qr_channel"].append(
                f"sustained polling to {host} ({count} connections)")

        # [NEW] Polling cadence detection (regular intervals across snapshots)
        cadence = _detect_polling_cadence(host)
        if cadence:
            behaviors["beaconing"] = behaviors.get("beaconing", 0) + 1
            evidence["beaconing"].append(
                f"{host}: {cadence['samples']} polls at ~{cadence['interval_avg']}s "
                f"intervals (machine cadence detected)")

    # --- Shape like analyzer.detect_behaviors output ---
    detections = {}
    for behavior, hits in behaviors.items():
        detections[behavior] = {
            "hits": hits,
            "evidence": [{"rule": "live_monitor", "line": 0, "snippet": e}
                         for e in evidence[behavior][:6]],
        }
    return detections