# RPN Direct Coordinator

Own-stack NAT-traversal control plane (no Tailscale / Headscale). See
[ARCHITECTURE.md](ARCHITECTURE.md) for the full design and rationale.

The coordinator **introduces peers and triggers hole-punching; it is not in the
data path** once a direct WG connection is up. It only relays as a last resort
(symmetric-CGNAT on both ends).

## Status

| Piece | State |
|------|-------|
| Control channel (WSS), registration, stable IP assignment | ✅ |
| Persistent IP state (survives restarts) | ✅ |
| Peer roster broadcast | ✅ |
| Candidate exchange + synchronized `punch` (simultaneous-open) | ✅ |
| **Relay-first**: relay sent immediately on connect, punch upgrades to direct | ✅ |
| STUN (RFC 5389) server-reflexive candidate discovery | ✅ |
| Dual STUN ports (RFC 5780 NAT-type classification) | ✅ |
| TURN relay (pion/turn) with HMAC-SHA1 time-limited credentials | ✅ |
| TLS (WSS) via `-tls-cert`/`-tls-key` | ✅ flags ready |
| Rate limiting (10 hello/min per IP) | ✅ |
| Pi exit agent: STUN self-discovery + reports candidates | ✅ |
| Pi exit agent: exponential backoff + healthz | ✅ |
| **Compiled / tested** | ⛔ **not yet** — CI builds on push |
| Android client ICE agent (`wireguard-go` + pion/ice) | ⬜ next milestone |
| Provisioning (access codes, enable/disable/expiry) | ⬜ |

## Ports (all on VPS 65.20.80.3)

| Port | Proto | Purpose |
|------|-------|---------|
| 8089 | TCP | WSS control channel |
| 3479 | UDP | STUN primary (RFC 5389) |
| 3481 | UDP | STUN secondary (RFC 5780 dual-port NAT classification) |
| 3480 | UDP | TURN relay (last-resort; WG-encrypted payload) |

## Build / run

```sh
cd coordinator
go mod tidy
go build -o rpn-coord ./...

# dev mode (any access code, open TURN relay):
./rpn-coord -http :8089 -stun :3479 -stun2 :3481 \
    -stun-public  65.20.80.3:3479 \
    -stun2-public 65.20.80.3:3481 \
    -relay-public 65.20.80.3:3480

# production (access codes + HMAC TURN credentials):
./rpn-coord -codes "ABC123:family-sharma,DEF456:family-rao" \
    -turn-secret "$(openssl rand -hex 32)" \
    -state-file /opt/rpn-coord/state.json
```

## Deploy

Push to master — GitHub Actions builds and deploys to the VPS automatically.
Set `RPN_TURN_SECRET` in GitHub repo secrets before first deploy.

```sh
# First-time VPS setup (one-time):
mkdir -p /opt/rpn-coord
cp rpn-coord.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable rpn-coord

# Open ports in UFW:
ufw allow 8089/tcp comment 'rpn-coord WSS'
ufw allow 3479/udp comment 'rpn-coord STUN'
ufw allow 3481/udp comment 'rpn-coord STUN2 (RFC 5780)'
ufw allow 3480/udp comment 'rpn-coord TURN relay'
```

## How "VPS only for linking, not data" works

```
Pi (India, Airtel CGNAT)
  └─ kernel wgd0 keepalive ──▶ VPS hub (wgd0, port 51820)
                                   │
                    coordinator reads Pi's live endpoint via
                    `wg show wgd0 dump` → /exit/info API
                                   │
Android client ──▶ GET /exit/info ─┘
  └─ configures WireGuard endpoint = Pi's ip:port
  └─ DATA PATH: Android ──────────────────▶ Pi (direct)
                                           └─▶ Airtel → internet
```

VPS is used only for:
1. WSS control signaling (tiny)
2. `/exit/info` HTTP endpoint (tiny)
3. STUN (tiny)
4. TURN relay only if both ends are symmetric-CGNAT (fallback; ideally never used)

## Direct-path strategy (ordered by preference)

1. **Static IP on Pi exit** — Airtel/Jio add-on (~₹500/mo). Exit has a public
   candidate → Android connects directly with zero punching. Recommended for 4K.
2. **`/exit/info` with keepalive** — Pi's keepalive holds the CGNAT port mapping
   open; coordinator reads and serves it. Android dials Pi directly. Works today
   without hole-punching (confirmed: `direct 122.164.83.185:11855`).
3. **Synchronized punch** — simultaneous-open via the coordinator's `punch` message.
   Works for full-cone and port-restricted-cone NAT.
4. **TURN relay** — last resort; symmetric-CGNAT on both ends.
