"""Exercise the real native service and firewall in isolated distro containers."""
import json
import os
import subprocess
import sys
import time
from http.cookies import SimpleCookie
from urllib.request import Request, urlopen

base = "http://127.0.0.1:18089"
cookie = ""
csrf = ""


def api(path, data=None):
    headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(base + path, data=None if data is None else json.dumps(data).encode(), headers=headers)
    with urlopen(request, timeout=40) as response:
        result = json.load(response)
        assert result["success"], result
        return result.get("obj"), response.headers


def mutate(path, data):
    result, _ = api(path, data)
    pending = result.get("rollback") if isinstance(result, dict) else None
    if pending:
        api("/api/firewall/rollback/confirm", {"token": pending["token"]})
    return result


login, headers = api("/api/login", {"username": "admin", "password": os.environ.get("FIREWALL_UI_PASSWORD", "1")})
session = next(iter(SimpleCookie(headers["Set-Cookie"]).values()))
cookie = session.key + "=" + session.value
csrf = login["csrf"]
api("/api/session")
status, _ = api("/api/firewall/status")
expected = os.environ["FIREWALL_UI_TEST_BACKEND"]
assert status["backend"] == expected, status
for attempt in range(15):
    ports, _ = api("/api/ports")
    if any(p["port"] == 18889 and p["listening"] and p["processes"] for p in ports["ports"]):
        break
    time.sleep(1)
else:
    raise AssertionError("Listener or its process was not detected")

if sys.argv[1] == "mutate":
    mutate("/api/firewall/enabled", {"enabled": True})
    if expected == "ufw":
        subprocess.run(["ufw", "allow", "20092/tcp", "comment", "compatibility-foreign"], check=True)
    else:
        subprocess.run(["firewall-cmd", "--add-port=20092/tcp"], check=True)
        subprocess.run(["firewall-cmd", "--permanent", "--add-port=20092/tcp"], check=True)
    mutate("/api/firewall/rules/add", {"port": 20091, "protocol": "tcp", "label": "compatibility-owned"})
    mutate("/api/firewall/rules/add", {"port": 20094, "protocol": "udp"})
    mutate("/api/firewall/rules/delete", {"port": 20094, "protocol": "udp"})
    mutate("/api/firewall/port", {"port": 20093, "protocol": "tcp", "closed": True})
    mutate("/api/firewall/ping", {"enabled": False})
    assert open("/proc/sys/net/ipv4/icmp_echo_ignore_all").read().strip() == "1"

status, _ = api("/api/firewall/status")
assert status["enabled"], status
assert any(r["port"] == 20091 and r["protocol"] == "tcp" for r in status["manualRules"]), status
assert not any(r["port"] == 20094 for r in status["manualRules"]), status
advanced, _ = api("/api/firewall/advanced")
assert any(r["portStart"] == 20093 and r["action"] == "deny" for r in advanced), advanced
print("Native authentication, sockets, rules and persistent settings verified")
