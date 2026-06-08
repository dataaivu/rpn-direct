#!/usr/bin/env bash
# RPN Direct — Phase 1: isolated plain-WireGuard hub interface on the VPS.
#
# SAFETY: fully additive and isolated from the existing Headscale stack.
#   - New interface  : wgd0            (Headscale uses its own embedded WG)
#   - New UDP port    : 51820          (Headscale/DERP is on 3478 — untouched)
#   - New subnet      : 10.99.0.0/24   (Headscale uses 100.64.0.0/10 — no overlap)
#   - NAT rule scoped : -s 10.99.0.0/24 only
#   - ip_forward      : already 1 on this host — left as-is
# Re-runnable: keys are generated once and reused.
#
# Phase 1 exit = the VPS's own IP (Vultr). The Pi residential exit is wired in later.
set -euo pipefail
export PATH=$PATH:/usr/sbin:/usr/bin

WGIF=wgd0
WGPORT=51820
WGNET=10.99.0.0/24
SRVADDR=10.99.0.1/24
CLIENTADDR=10.99.0.101/32
UPLINK=enp1s0
PUBIP=65.20.80.3

# 1. WireGuard userspace tools
if ! command -v wg >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq wireguard-tools
fi

mkdir -p /etc/wireguard
cd /etc/wireguard
umask 077

# 2. Keys (generate once, reuse on re-run)
[ -f "srv_${WGIF}.key" ]  || wg genkey > "srv_${WGIF}.key"
wg pubkey < "srv_${WGIF}.key" > "srv_${WGIF}.pub"
[ -f "cli1_${WGIF}.key" ] || wg genkey > "cli1_${WGIF}.key"
wg pubkey < "cli1_${WGIF}.key" > "cli1_${WGIF}.pub"

SRV_PRIV=$(cat "srv_${WGIF}.key")
SRV_PUB=$(cat "srv_${WGIF}.pub")
CLI_PRIV=$(cat "cli1_${WGIF}.key")
CLI_PUB=$(cat "cli1_${WGIF}.pub")

# 3. Server interface config
cat > "/etc/wireguard/${WGIF}.conf" <<EOF
[Interface]
Address = ${SRVADDR}
ListenPort = ${WGPORT}
PrivateKey = ${SRV_PRIV}
PostUp = iptables -I FORWARD 1 -i ${WGIF} -j ACCEPT; iptables -I FORWARD 1 -o ${WGIF} -j ACCEPT; iptables -t nat -A POSTROUTING -s ${WGNET} -o ${UPLINK} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WGIF} -j ACCEPT; iptables -D FORWARD -o ${WGIF} -j ACCEPT; iptables -t nat -D POSTROUTING -s ${WGNET} -o ${UPLINK} -j MASQUERADE

[Peer]
# cli1 — Fire TV Cube test device
PublicKey = ${CLI_PUB}
AllowedIPs = ${CLIENTADDR}
EOF

# 4. Firewall — open only the new port
ufw allow "${WGPORT}/udp" >/dev/null

# 5. Bring up + persist
systemctl enable "wg-quick@${WGIF}" >/dev/null 2>&1 || true
wg-quick down "${WGIF}" 2>/dev/null || true
wg-quick up "${WGIF}"

# 6. Emit the client config (captured by the operator; never committed to the repo)
echo "===CLIENT_CONFIG_BEGIN==="
cat <<EOF
[Interface]
PrivateKey = ${CLI_PRIV}
Address = ${CLIENTADDR}
DNS = 1.1.1.1

[Peer]
PublicKey = ${SRV_PUB}
Endpoint = ${PUBIP}:${WGPORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
echo "===CLIENT_CONFIG_END==="

# 7. Verify isolation
echo "===VERIFY==="
echo -n "headscale_health="; curl -s -o /dev/null -w "%{http_code}\n" https://magicstreamer.duckdns.org/health
echo -n "wgd0_up="; (wg show "${WGIF}" >/dev/null 2>&1 && echo yes) || echo no
wg show "${WGIF}"
