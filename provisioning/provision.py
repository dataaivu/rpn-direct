#!/usr/bin/env python3
"""RPN Direct provisioning API (stdlib-only, TLS).

A friend's RPN.exe POSTs its WireGuard *public* key + a shared access code.
We allocate a stable 10.99.0.x /32, add the peer to the wgd0 hub, install the
policy route that sends that node's internet traffic into wgd0 -> the Pi exit,
and return the hub's public key + endpoint so the client can finish its config.

Source of truth for allocations is peers.json; apply-routes.sh re-applies the
live state from it on boot. The client's PRIVATE key never reaches this server.
"""
import json, os, re, ssl, subprocess, fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE   = "/opt/rpn-provision"
CONF   = os.path.join(BASE, "config.json")     # {"access_code": "..."} — NOT in repo
PEERS  = os.path.join(BASE, "peers.json")
LOCK   = os.path.join(BASE, "provision.lock")

WG_IF       = "wgd0"
WG_CONF     = "/etc/wireguard/wgd0.conf"
TABLE       = "5101"                  # policy-routing table: default dev wgd0 (-> Pi)
SUBNET      = "10.99.0."
POOL_START  = 103                     # .1 hub, .2 Pi, .101 Friend are reserved
POOL_END    = 250
HUB_PUBKEY  = "UvEK1hM6jkX1D0ngwkYdB/QlURB4nekJj/Rq01w/Glg="
ENDPOINT    = "65.20.80.3:51820"
DNS         = "1.1.1.1"
KEEPALIVE   = 25

CERT = "/etc/letsencrypt/live/magicstreamer.duckdns.org/fullchain.pem"
KEY  = "/etc/letsencrypt/live/magicstreamer.duckdns.org/privkey.pem"

ACCESS_CODE = json.load(open(CONF))["access_code"]
# 44-char base64 Curve25519 public key
PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")


def load_peers():
    return json.load(open(PEERS)) if os.path.exists(PEERS) else {}


def save_peers(p):
    tmp = PEERS + ".tmp"
    json.dump(p, open(tmp, "w"), indent=2)
    os.replace(tmp, PEERS)


def alloc_ip(peers):
    used = {v["ip"] for v in peers.values()}
    for n in range(POOL_START, POOL_END + 1):
        ip = SUBNET + str(n)
        if ip not in used:
            return ip
    raise RuntimeError("address pool exhausted")


def apply_peer(pubkey, ip):
    # 1) live hub peer
    subprocess.run(["wg", "set", WG_IF, "peer", pubkey, "allowed-ips", ip + "/32"], check=True)
    # 2) persist to wgd0.conf if not already there
    conf = open(WG_CONF).read()
    if pubkey not in conf:
        with open(WG_CONF, "a") as f:
            f.write(f"\n[Peer]\n# rpn-node {ip}\nPublicKey = {pubkey}\nAllowedIPs = {ip}/32\n")
    # 3) exit policy route: traffic FROM this node -> table 5101 -> wgd0 -> Pi
    subprocess.run(["ip", "route", "replace", "default", "dev", WG_IF, "table", TABLE], check=True)
    rules = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True).stdout
    if f"from {ip} lookup {TABLE}" not in rules:
        subprocess.run(["ip", "rule", "add", "from", ip, "lookup", TABLE], check=True)


def remove_peer(pubkey):
    """Drop a stale peer (live + persisted) when a device rotates its key.

    Without this, a reinstalled device that regenerates its keypair would leave
    its old public key behind holding the SAME /32 — two peers claiming one IP,
    which breaks routing. We re-key in place: same IP, old pubkey removed.
    """
    # 1) live hub
    subprocess.run(["wg", "set", WG_IF, "peer", pubkey, "remove"], check=False)
    # 2) persisted conf: drop the [Peer] stanza whose PublicKey matches
    try:
        lines = open(WG_CONF).read().splitlines()
    except FileNotFoundError:
        return
    out, block, drop = [], [], False

    def flush():
        nonlocal block, drop
        if not drop:
            out.extend(block)
        block, drop = [], False

    for ln in lines:
        if ln.strip() == "[Peer]":
            flush()
            block = [ln]
        elif block:
            block.append(ln)
            if ln.strip().startswith("PublicKey") and pubkey in ln:
                drop = True
        else:
            out.append(ln)
    flush()
    tmp = WG_CONF + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(out).rstrip("\n") + "\n")
    os.replace(tmp, WG_CONF)


def find_by_device(peers, device_id):
    if not device_id:
        return None
    for pk, v in peers.items():
        if v.get("device_id") == device_id:
            return pk
    return None


def provision(pubkey, name, device_id):
    with open(LOCK, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        peers = load_peers()
        old_pk = find_by_device(peers, device_id)
        if old_pk is not None:
            # Known device — ALWAYS the same IP, even if the keypair was regenerated.
            ip = peers[old_pk]["ip"]
            if old_pk != pubkey:
                del peers[old_pk]
                peers[pubkey] = {"ip": ip, "name": name, "device_id": device_id}
                save_peers(peers)
                remove_peer(old_pk)              # strip the stale key holding this /32
            else:
                peers[pubkey]["name"] = name     # same device, same key — keep name fresh
                save_peers(peers)
        elif pubkey in peers:                    # legacy client (no device_id): key on pubkey
            ip = peers[pubkey]["ip"]
            if device_id:
                peers[pubkey]["device_id"] = device_id
                save_peers(peers)
        else:                                    # brand-new device
            ip = alloc_ip(peers)
            peers[pubkey] = {"ip": ip, "name": name, "device_id": device_id}
            save_peers(peers)
        apply_peer(pubkey, ip)
    return {
        "assigned_ip": ip + "/32",
        "hub_pubkey": HUB_PUBKEY,
        "endpoint": ENDPOINT,
        "dns": DNS,
        "keepalive": KEEPALIVE,
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, {"status": "ok"}) if self.path == "/health" else self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/provision":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n))
        except Exception:
            return self._send(400, {"error": "bad json"})
        if data.get("code") != ACCESS_CODE:
            return self._send(403, {"error": "bad access code"})
        pubkey = (data.get("pubkey") or "").strip()
        if not PUBKEY_RE.match(pubkey):
            return self._send(400, {"error": "bad pubkey"})
        name = (data.get("name") or "node")[:48]
        device_id = (data.get("device_id") or "").strip()[:64]
        try:
            self._send(200, provision(pubkey, name, device_id))
        except Exception as e:
            self._send(500, {"error": str(e)})

    def log_message(self, *a):
        pass


def main():
    httpd = ThreadingHTTPServer(("0.0.0.0", 8446), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("rpn-provision listening on https://0.0.0.0:8446 (/provision, /health)")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
