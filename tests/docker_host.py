"""Read-only smoke check: Direct host access, login and socket ownership."""
import json
import time
from http.cookies import SimpleCookie
from urllib.request import Request, urlopen

base = "http://127.0.0.1:18089"
request = Request(base + "/api/login", data=json.dumps({
    "username": "admin", "password": "ci-compose-smoke",
}).encode(), headers={"Content-Type": "application/json"})
with urlopen(request, timeout=10) as response:
    assert json.load(response)["success"]
    cookie = SimpleCookie(response.headers["Set-Cookie"])
    session = cookie["firewall_ui_session"].value

for attempt in range(15):
    request = Request(base + "/api/ports", headers={
        "Cookie": "firewall_ui_session=" + session,
    })
    with urlopen(request, timeout=10) as response:
        body = json.load(response)
    assert body["success"], body.get("msg")
    ports = body["obj"]["ports"]
    if any(port["port"] == 18889 and port["protocol"] == "tcp"
           and port["listening"] and port["processes"] for port in ports):
        print("Direct access and host listener ownership verified")
        break
    time.sleep(1)
else:
    raise AssertionError("Host test listener/process missing from Compose panel")
