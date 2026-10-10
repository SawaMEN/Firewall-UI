"""Read-only smoke check: Docker DNS, login and host socket ownership."""
import json
import time
from http.cookies import SimpleCookie
from urllib.request import Request, urlopen

base = "http://firewall-ui.internal:8088"
request = Request(base + "/api/login", data=json.dumps({
    "username": "admin", "password": "ci-proxy-smoke",
}).encode(), headers={"Content-Type": "application/json"})
with urlopen(request, timeout=10) as response:
    assert json.load(response)["success"]
    cookie = SimpleCookie(response.headers["Set-Cookie"])
    assert cookie["firewall_ui_session"]["secure"]
    session = cookie["firewall_ui_session"].value

# The browser uses HTTPS at the reverse proxy; the smoke check deliberately
# sends the session directly over the isolated CI Docker network.
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
        print("Docker DNS, Secure Cookie and host listener ownership verified")
        break
    time.sleep(1)
else:
    raise AssertionError("Host test listener/process missing from proxy-mode panel")
