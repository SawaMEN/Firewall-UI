"""Read-only smoke check: Direct host access, login and socket ownership."""
import json
import os
import time
import ssl
from http.cookies import SimpleCookie
from urllib.request import Request, urlopen

https = os.environ.get("FIREWALL_UI_TEST_HTTPS") == "1"
base = ("https" if https else "http") + "://127.0.0.1:18089"
# The smoke fixture deliberately uses a self-signed certificate.
context = ssl._create_unverified_context() if https else None
request = Request(base + "/api/login", data=json.dumps({
    "username": os.environ.get("FIREWALL_UI_USERNAME", "admin"),
    "password": os.environ.get("FIREWALL_UI_PASSWORD", "ci-compose-smoke"),
}).encode(), headers={"Content-Type": "application/json"})
with urlopen(request, timeout=10, context=context) as response:
    assert json.load(response)["success"]
    cookie = SimpleCookie(response.headers["Set-Cookie"])
    session_cookie = next(iter(cookie.values()))
    session = session_cookie.key + "=" + session_cookie.value

for attempt in range(15):
    request = Request(base + "/api/ports", headers={
        "Cookie": session,
    })
    with urlopen(request, timeout=10, context=context) as response:
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
