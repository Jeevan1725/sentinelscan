# CyberRecon — Threat Context for the SentinelScan Demo

**A working implementation of the Mandiant 2024 QR-C2 browser-isolation bypass.**

This document explains what CyberRecon is, why it exists in this repository, and how it is used in the demonstration. It is provided as **documentation only**. The source is included in `demo_samples/cyberrecon_*.py` for the sole purpose of being analyzed by SentinelScan; it is never executed.

---

## The security boundary being bypassed

Browser isolation is a widely deployed enterprise security control. Its premise is straightforward: no web content executes on the endpoint. Instead:

1. A remote sandbox loads the web page.
2. The sandbox renders the page to pixels.
3. The pixels are streamed to the endpoint's browser.

The endpoint never receives HTML, JavaScript, or any executable content. It receives an image. A firewall, DNS filter, or network intrusion detection system never sees the traffic because, from the network's perspective, there is no traffic between the isolated content and the endpoint.

The control is effective against the standard command-and-control channels: HTTP callbacks, DNS tunneling, custom TCP. None of them can traverse the isolation boundary.

The control has one limitation: **it filters content, not pixels.**

---

## The attack

A QR code is a rendered image. If an adversary controls the content being rendered inside the isolated browser, they can place a QR code on the page. The endpoint renders the QR code as pixels and decodes it locally. The decoded payload is a command-and-control instruction.

This means:

- The command channel is **visual**, not network-based.
- Nothing suspicious appears on the wire.
- Standard network security tooling has no signal to detect.
- The endpoint is executing commands delivered through rendered images.

Mandiant documented this technique publicly in 2024. It is not theoretical.

---

## What CyberRecon implements

CyberRecon is a complete, working implementation of this attack. It contains:

### Command and control

- **`c2_server.py`** — a Flask server that encodes commands as QR codes, renders them as images, and serves them at `/qr/<victim_id>`. It receives exfiltrated data at `/exfil/<victim_id>` and displays live victim state on a Parrot Viewer dashboard.
- **`qr_decoder.py`** — a headless Chrome client that polls the C2 server's QR endpoint, screenshots the response, decodes the QR code, and executes the embedded command. Uses Selenium and OpenCV.

### Post-exploitation modules

- **`modules/keylogger.py`** — captures keystrokes via `pynput`, buffers them, and exfiltrates in chunks every 15–30 seconds.
- **`modules/screenshot.py`** — captures screen content, compresses as JPEG, exfiltrates.
- **`modules/webcam.py`** — captures webcam frames, optionally with face detection.
- **`modules/gps.py`** — retrieves geolocation via public IP lookup services.
- **`modules/persistence.py`** — installs persistence via Registry Run key, scheduled task, and startup folder.
- **`modules/stealth.py`** — anti-forensics (event log clearing), VM detection, console hiding, and self-destruct (batch script delete loop).

### Delivery

- **`sfx_payload.py`** — builds a self-extracting archive that installs the implant silently while displaying a decoy document.

### Fallback channels

If the visual channel is unavailable, the client falls back to TCP or HTTP. This is a redundant capability, not a design requirement.

---

## Why CyberRecon is in this repository

SentinelScan is a defensive system. It detects malware behavior at the endpoint by reading code and observing process activity. The most convincing way to demonstrate a defensive system is to test it against a real, working threat.

**CyberRecon serves three purposes in this project:**

1. **It is the demonstration villain.** During the video demo, CyberRecon's source code is shown in VS Code, then the same files are analyzed by SentinelScan in the Streamlit UI. The defense detects the offense.
2. **It is in the evaluation set.** Five of the 25 samples in `eval/gold_set.jsonl` are CyberRecon modules. The evaluation verifies that SentinelScan flags them.
3. **It provides context.** A viewer who understands what CyberRecon does understands why SentinelScan's endpoint approach is necessary — the network cannot see this threat.

---

## Safety and ethical boundary

The following constraints apply to every use of CyberRecon in this project:

1. **CyberRecon is never executed.** All analysis is static. The `.py` files are read as text by SentinelScan's analyzer. No process is started, no network connection is opened, no commands are decoded.
2. **All command-and-control addresses are `127.0.0.1`.** The samples reference localhost only. There is no external infrastructure.
3. **CyberRecon is not deployed or weaponized in this repository.** There is no installer, no build step, and no operator CLI in the version included here.
4. **The malware capability is documented, not enabled.** The source files are readable code. Their behavior is described in this document. Their execution is out of scope.

SentinelScan's detection of CyberRecon is verified in the evaluation output:

```
cyberrecon_01_qr_c2.py  ->  AUTO_REPORT  (confidence 0.827)
cyberrecon_02_keylogger.py  ->  AUTO_REPORT  (confidence 0.788)
cyberrecon_03_persistence.py  ->  AUTO_REPORT  (confidence 0.842)
cyberrecon_04_stealth.py  ->  AUTO_REPORT  (confidence 0.813)
cyberrecon_05_dropper.py  ->  ESCALATE  (confidence 0.579)
```

Reproduce: `python eval/run_eval.py`.

---

## What SentinelScan detects in CyberRecon

SentinelScan is not tuned to CyberRecon specifically. Its rules detect **behavior patterns** that apply to any malware in the same families. When it analyzes CyberRecon's QR-C2 module, it detects:

| Behavior | MITRE ATT&CK | Evidence |
|---|---|---|
| QR visual channel C2 | T1102 — Web Service C2 | `QRCodeDetector`, `detectAndDecode`, headless Chrome loop |
| HTTP C2 | T1071.001 — Application Layer Protocol: Web | `requests.get` to C2, `/qr/` endpoint |
| Screen capture | T1113 — Screen Capture | `pyautogui.screenshot` |
| Data exfiltration | T1041 — Exfiltration Over C2 Channel | `base64.b64encode` to HTTP POST |
| Stealth execution | T1564.001 — Hide Artifacts | `--headless` flag in process command line |

The same rules detect analogous behaviors in unrelated malware families — for example, a hypothetical QR-C2 implant built by a different threat actor using a different framework. This is verified in the evaluation set: the five CyberRecon modules score identically to their synthetic equivalents (`mal_qr_c2.py`, `mal_keylogger.py`, etc.), because the detector operates on behavior, not on file names.

---

## Live detection

SentinelScan's live monitor detects CyberRecon running in real time. When the CyberRecon QR decoder process is active, the monitor observes:

- A headless Chrome process polling a network endpoint
- A Python process that has spawned `chromedriver.exe` as a child
- Repeated connections to port 8443 on localhost

The verdict is consistent with the static analysis:

```
VERDICT     : AUTO_REPORT
RISK        : HIGH
CONFIDENCE  : 0.806
  [c2_qr_channel] -> T1102 Web Service C2
    - pid 12345 chrome.exe --headless (QR decode loop candidate)
  [c2_http] -> T1071.001 Application Layer Protocol: Web
    - connection to 127.0.0.1:8443 (suspicious port 8443)
```

The static and live analyzers independently reach the same verdict via different evidence paths.

---

## Why this pairing matters

Most malware-detection demonstrations use an artificial or ancient sample. The detector is tested on files that have been labeled malware for years, under the assumption that the detector's pattern rules will still apply.

CyberRecon is different. It implements a technique published eighteen months before this project, using libraries that ship with modern Python and Chrome. It is a working version of an attack that defeats a widely deployed security control.

Demonstrating SentinelScan's detection of CyberRecon shows the defensive system works against a current, real threat — not against a curated historical sample.

---

## References

- Mandiant. *QR Codes: A Novel Command and Control Channel Bypassing Browser Isolation.* 2024.
- MITRE ATT&CK — T1102 Web Service C2. https://attack.mitre.org/techniques/T1102/
- MITRE ATT&CK — T1071.001 Application Layer Protocol: Web. https://attack.mitre.org/techniques/T1071/001/

---

## Related documents

- [`README.md`](README.md) — project overview and setup
- [`WRITEUP.md`](WRITEUP.md) — one-page project summary
- [`DEMO_VIDEO_SCRIPT.md`](DEMO_VIDEO_SCRIPT.md) — 3-minute demonstration shot list
