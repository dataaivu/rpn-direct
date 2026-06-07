# RPN Direct

A fully-owned residential VPN built on plain **WireGuard hub-and-spoke** — no Tailscale,
no Headscale. Routes customer traffic out through a residential exit node (India / Airtel)
for a genuine local IP, sidestepping CGNAT by relaying through a public VPS hub.

See **[CLAUDE.md](CLAUDE.md)** for project context and **[SPEC.md](SPEC.md)** for the design.

## Layout
| Dir | Purpose |
|-----|---------|
| `server/` | VPS hub — WireGuard interface, routing, firewall |
| `pi-exit/` | Raspberry Pi exit node — persistent tunnel + masquerade |
| `android/` | Customer client — `VpnService` + WireGuard |
| `provisioning/` | Create / enable / disable customers; issue access codes |
| `docs/` | Design notes |

## Status
Scaffold only. First milestone: 3-node proof-of-concept (VPS + Pi + one phone) using an
off-the-shelf WireGuard app to validate routing **before** building the custom client.

> Secrets never live in this repo. Keep keys/tokens in env vars or local files outside the tree.
