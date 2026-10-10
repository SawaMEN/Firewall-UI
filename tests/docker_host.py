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
    login = json.load(response)
    assert login["success"]
    csrf = login["obj"]["csrf"]
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

request = Request(base + "/panel/api/server/firewall/status", headers={"Cookie": session})
with urlopen(request, timeout=20, context=context) as response:
    firewall = json.load(response)
assert firewall["success"], firewall.get("msg")
assert firewall["obj"]["backend"] == "ufw", firewall
print("Container uses the actual host UFW, without a conflicting nftables hook")

if os.environ.get("FIREWALL_UI_TEST_UPDATES") == "1":
    request = Request(base + "/api/update/status", headers={"Cookie": session})
    with urlopen(request, timeout=30, context=context) as response:
        update = json.load(response)
    assert update["success"], update.get("msg")
    assert update["obj"]["docker"] and not update["obj"].get("manualInstall", False), update
    assert not update["obj"].get("automatic", False), update
    print("Docker update endpoint is configured and the host update service is available")
