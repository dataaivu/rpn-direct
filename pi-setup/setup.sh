#!/bin/bash
# RPN Direct — Pi zero-touch first-boot setup.
# Bake this script into the SD card image. It runs once on first boot,
# registers the Pi with the coordinator, sets up WireGuard, and starts the agent.
#
# Prerequisites (already installed in the base image):
#   wireguard-tools, curl, python3, systemd
#
# Usage: sudo bash setup.sh [--coordinator URL] [--fleet-token TOKEN]
#        Or set env vars COORDINATOR and FLEET_TOKEN before running.

set -euo pipefail

COORDINATOR="${COORDINATOR:-http://65.20.80.3:8089}"
FLEET_TOKEN="${FLEET_TOKEN:-REPLACE_IN_IMAGE}"
WG_IFACE="wgd0"
WG_PORT=51821
AGENT_DIR="/opt/rpn-agent"
WG_DIR="/etc/wireguard"

# Parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --coordinator) COORDINATOR="$2"; shift 2 ;;
        --fleet-token) FLEET_TOKEN="$2"; shift 2 ;;
        *) shift ;;
    esac
done

log() { echo "[rpn-setup] $*"; }

# ── 1. Hardware identity ──────────────────────────────────────────────────────
SERIAL=$(grep -m1 Serial /proc/cpuinfo 2>/dev/null | awk '{print $3}' | tr -d ' ')
if [[ -z "$SERIAL" || "$SERIAL" == "0000000000000000" ]]; then
    # Fallback: use first non-loopback MAC (stable across reboots)
    SERIAL=$(cat /sys/class/net/*/address 2>/dev/null | grep -v "00:00:00:00:00:00" | grep -v "^lo$" | head -1 | tr -d ':')
fi
if [[ -z "$SERIAL" ]]; then
    SERIAL="pi-$(hostname)-$(date +%s)"
fi
log "Pi serial: $SERIAL"

# ── 2. WireGuard keypair ──────────────────────────────────────────────────────
mkdir -p "$WG_DIR"
if [[ ! -f "$WG_DIR/$WG_IFACE.key" ]]; then
    wg genkey | tee "$WG_DIR/$WG_IFACE.key" | wg pubkey > "$WG_DIR/$WG_IFACE.pub"
    chmod 600 "$WG_DIR/$WG_IFACE.key"
    log "WireGuard keypair generated"
else
    log "WireGuard keypair already exists"
fi
PUBKEY=$(cat "$WG_DIR/$WG_IFACE.pub")
PRIVKEY=$(cat "$WG_DIR/$WG_IFACE.key")
log "pubkey: $PUBKEY"

# ── 3. Register with coordinator ──────────────────────────────────────────────
LOCATION=$(curl -sf --max-time 5 https://ipinfo.io/city 2>/dev/null || echo "unknown")
RESPONSE=$(curl -sf --max-time 15 -X POST "$COORDINATOR/pi/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"fleet_token\": \"$FLEET_TOKEN\",
        \"serial\":      \"$SERIAL\",
        \"pubkey\":      \"$PUBKEY\",
        \"name\":        \"pi-$SERIAL\",
        \"location\":    \"$LOCATION\"
    }")

VPN_IP=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['vpn_ip'])" 2>/dev/null)
if [[ -z "$VPN_IP" ]]; then
    log "ERROR: registration failed. Response: $RESPONSE"
    exit 1
fi
log "registered: vpn_ip=$VPN_IP"

# Save Pi ID for the agent
echo "$SERIAL" > "$WG_DIR/pi-id"

# ── 4. WireGuard interface config ─────────────────────────────────────────────
# Detect the default outbound interface (eth0 or wlan0)
OUTIF=$(ip route show default | awk '/default/ {print $5; exit}')
log "outbound interface: $OUTIF"

cat > "$WG_DIR/$WG_IFACE.conf" << EOF
[Interface]
PrivateKey = $PRIVKEY
Address = $VPN_IP
ListenPort = $WG_PORT

# Route customer traffic out to local ISP (residential exit)
PostUp   = iptables -t nat -A POSTROUTING -o $OUTIF -j MASQUERADE
PostUp   = iptables -A FORWARD -i $WG_IFACE -j ACCEPT
PostUp   = iptables -A FORWARD -o $WG_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $OUTIF -j MASQUERADE
PostDown = iptables -D FORWARD -i $WG_IFACE -j ACCEPT
PostDown = iptables -D FORWARD -o $WG_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
chmod 600 "$WG_DIR/$WG_IFACE.conf"
log "WireGuard config written"

# ── 5. System tuning ──────────────────────────────────────────────────────────
# IP forwarding (required for routing customer traffic)
grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf && \
    sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf || \
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# Increase WireGuard UDP buffer sizes for higher throughput
cat >> /etc/sysctl.conf << 'EOF'
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.netdev_max_backlog=5000
EOF
sysctl -p >/dev/null 2>&1

# ── 6. Start WireGuard ────────────────────────────────────────────────────────
systemctl enable wg-quick@$WG_IFACE
systemctl restart wg-quick@$WG_IFACE
log "WireGuard started"

# ── 7. Install agent ──────────────────────────────────────────────────────────
mkdir -p "$AGENT_DIR"

# Download latest agent binary (built by GitHub Actions)
AGENT_URL="https://github.com/dataaivu/rpn-direct/releases/latest/download/rpn-agent-linux-arm7"
curl -sfL "$AGENT_URL" -o "$AGENT_DIR/rpn-agent" && chmod +x "$AGENT_DIR/rpn-agent" || \
    log "WARNING: could not download agent — deploy manually to $AGENT_DIR/rpn-agent"

# Systemd unit
cat > /etc/systemd/system/rpn-agent.service << EOF
[Unit]
Description=RPN Direct Pi agent
After=network.target wg-quick@$WG_IFACE.service
Wants=wg-quick@$WG_IFACE.service

[Service]
Type=simple
ExecStart=$AGENT_DIR/rpn-agent \
    -coordinator $COORDINATOR \
    -wg-iface    $WG_IFACE \
    -stun        65.20.80.3:3479 \
    -pi-id       $SERIAL
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable rpn-agent
systemctl start rpn-agent
log "agent started"

# ── 8. Done ───────────────────────────────────────────────────────────────────
log ""
log "Setup complete!"
log "  Pi ID:     $SERIAL"
log "  VPN IP:    $VPN_IP"
log "  WG port:   $WG_PORT"
log "  Outbound:  $OUTIF"
log ""
log "The Pi will appear in the coordinator fleet within 30 seconds."
log "Customers will be assigned to it automatically."
