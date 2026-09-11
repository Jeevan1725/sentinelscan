"""
SentinelScan live process/network monitor - colored terminal UI.
Usage:  python watch_live.py [--interval N] [--quiet]
Stop:   Ctrl+C
"""
import argparse
import os
import sys
import time
from pathlib import Path

# --- Windows ANSI enable ---
if os.name == "nt":
    os.system("")  # enables VT100 on Windows 10+
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinelscan import analyze_live_signals
from sentinelscan.live_signals import snapshot


# --- ANSI colors ---
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
GREY = "\033[90m"


def verdict_color(v):
    return {
        "ALLOW": GREEN,
        "ESCALATE": YELLOW,
        "AUTO_REPORT": RED,
    }.get(v, CYAN)


def risk_color(r):
    return {
        "low": GREEN,
        "medium": YELLOW,
        "high": RED,
        "critical": RED + BOLD,
    }.get(r.lower(), CYAN)


def bar(value, width=10, fill="█", empty="░"):
    n = max(0, min(width, int(round(value * width))))
    return fill * n + empty * (width - n)


def hr(w=70, char="─"):
    return char * w


def box_top(w=70):
    return f"╔{hr(w, '═')}╗"


def box_bot(w=70):
    return f"╚{hr(w, '═')}╝"


def box_line(content, w=70):
    # Pad to width, accounting for ANSI escape codes (approximate)
    import re
    stripped = re.sub(r"\033\[[0-9;]*m", "", content)
    pad = max(0, w - len(stripped))
    return f"║ {content}{' ' * (pad - 1)}║"


def box_sep(w=70):
    return f"╠{hr(w, '═')}╣"


def render_alert(state, ts):
    W = 70
    out = []
    out.append("")
    out.append(box_top(W))
    header = f"{BOLD}{RED}  LIVE THREAT DETECTED{RESET}"
    ts_text = f"{GREY}{ts}{RESET}"
    # Right-align timestamp roughly
    pad = W - 26
    out.append(box_line(f"{header}{' ' * max(1, pad)}{ts_text}", W))
    out.append(box_sep(W))

    vc = verdict_color(state.decision)
    rc = risk_color(state.risk)
    conf = state.confidence
    conf_color = GREEN if conf >= 0.7 else (YELLOW if conf >= 0.45 else RED)

    out.append(box_line(
        f"{BOLD}VERDICT{RESET}        {vc}{BOLD}{state.decision:<14}{RESET}", W))
    out.append(box_line(
        f"{BOLD}RISK{RESET}           {rc}{BOLD}{state.risk.upper():<14}{RESET}", W))
    out.append(box_line(
        f"{BOLD}CONFIDENCE{RESET}     {conf_color}{bar(conf, 10)}{RESET}  "
        f"{conf_color}{conf:.3f}{RESET}  {GREY}(threshold 0.70){RESET}", W))

    if state.red_flags:
        out.append(box_sep(W))
        out.append(box_line(f"{RED}{BOLD}⚠  RED FLAGS{RESET}", W))
        for rf in state.red_flags:
            out.append(box_line(f"   {RED}•{RESET} {rf}", W))

    out.append(box_sep(W))
    out.append(box_line(f"{BOLD}DETECTED BEHAVIORS{RESET}", W))
    if not state.detections:
        out.append(box_line(f"   {GREY}(none){RESET}", W))
    for behavior, d in state.detections.items():
        maps = state.attack_mappings.get(behavior, [])
        cite = f"[{CYAN}{maps[0]['technique_id']}{RESET}] {maps[0]['technique_name']}" \
            if maps else f"{GREY}[n/a]{RESET}"
        label = behavior.replace("_", " ")
        out.append(box_line(f"   {BLUE}•{RESET} {BOLD}{label:<26}{RESET} {cite}", W))
        for ev in d["evidence"][:2]:
            snippet = ev["snippet"]
            if len(snippet) > 58:
                snippet = snippet[:55] + "..."
            out.append(box_line(f"       {GREY}{snippet}{RESET}", W))

    out.append(box_sep(W))
    footer = f"{GREY}{state.decision_reason}{RESET}"
    if len(state.decision_reason) > 66:
        # wrap into 2 lines
        out.append(box_line(f"{GREY}{state.decision_reason[:66]}{RESET}", W))
        out.append(box_line(f"{GREY}{state.decision_reason[66:132]}{RESET}", W))
    else:
        out.append(box_line(footer, W))

    out.append(box_bot(W))
    out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=3)
    ap.add_argument("--quiet", action="store_true",
                    help="suppress 'clean' heartbeat lines")
    args = ap.parse_args()

    print(f"\n{BOLD}{CYAN}🛡  SentinelScan — Live Monitor{RESET}")
    print(f"{GREY}   scanning every {args.interval}s · Ctrl+C to stop{RESET}\n")

    last_signature = None
    while True:
        try:
            detections = snapshot()
            signature = tuple(sorted(detections.keys()))

            if signature and signature != last_signature:
                state = analyze_live_signals(detections)
                print(render_alert(state, time.strftime("%H:%M:%S")))
                last_signature = signature

            elif not signature:
                last_signature = None
                if not args.quiet:
                    print(f"{GREY}[{time.strftime('%H:%M:%S')}] clean · "
                          f"no suspicious behaviors{RESET}")

            time.sleep(args.interval)

        except KeyboardInterrupt:
            print(f"\n{GREY}stopped.{RESET}")
            return
        except Exception as e:
            print(f"{RED}[error]{RESET} {e}")
            time.sleep(args.interval)


if __name__ == "__main__":
    main()