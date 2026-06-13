#!/usr/bin/env bash
# Re-apply the RPN Direct exit policy routes + hub peers from peers.json.
# Runs at boot (rpn-exit-routes.service) so provisioned nodes survive a reboot
# even if something rewrites the live wgd0 state.
set -e
TABLE=5101
WG_IF=wgd0
PEERS=/opt/rpn-provision/peers.json

# table 5101 default -> wgd0 (-> Pi exit)
ip route replace default dev "$WG_IF" table "$TABLE"

# NAT node traffic to the hub's own tunnel IP (10.99.0.1) on the way to the Pi.
# Without this, the Pi receives packets sourced 10.99.0.10x and has no return route
# for them (its hub-peer AllowedIPs only covers .1), so node internet egress is
# black-holed. SNAT-to-hub lets every current/future node reuse the .1 path the Pi
# already serves. Scoped to wgd0; does not touch Headscale or the enp1s0 path.
iptables -t nat -C POSTROUTING -s 10.99.0.0/24 -o "$WG_IF" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o "$WG_IF" -j MASQUERADE

# Allow the node->Pi egress hairpin (in wgd0 -> out wgd0). The RPN_FORWARD chain
# otherwise DROPs all node-sourced forwarded traffic (only the hub .1 is allowed),
# which black-holes every node's internet. This ACCEPT must sit BEFORE that DROP.
if iptables -L RPN_FORWARD -n >/dev/null 2>&1; then
  iptables -C RPN_FORWARD -s 10.99.0.0/24 -i "$WG_IF" -o "$WG_IF" -j ACCEPT 2>/dev/null \
    || iptables -I RPN_FORWARD 1 -s 10.99.0.0/24 -i "$WG_IF" -o "$WG_IF" -j ACCEPT
fi

# pre-existing Friend-Germany node
ip rule show | grep -q "from 10.99.0.101 lookup $TABLE" || ip rule add from 10.99.0.101 lookup "$TABLE"

# provisioned nodes
if [ -f "$PEERS" ]; then
  python3 - "$PEERS" "$TABLE" <<'PY'
import json, subprocess, sys
peers = json.load(open(sys.argv[1])); table = sys.argv[2]
rules = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True).stdout
for pk, v in peers.items():
    ip = v["ip"]
    subprocess.run(["wg", "set", "wgd0", "peer", pk, "allowed-ips", ip + "/32"], check=False)
    if f"from {ip} lookup {table}" not in rules:
        subprocess.run(["ip", "rule", "add", "from", ip, "lookup", table], check=False)
PY
fi
echo "rpn exit routes applied"
