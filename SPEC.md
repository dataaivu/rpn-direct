# RPN Direct — Technical Spec

## 1. Topology: WireGuard hub-and-spoke

The VPS is the **hub**. Two kinds of spokes connect to it: the **exit node** (Pi) and
**customers**. Customer traffic is policy-routed through the Pi's tunnel.

```
            wg0 (hub) on VPS  10.99.0.0/24
            ┌───────────────────────────────────────┐
 customer──▶│ 10.99.0.101  ... 10.99.0.0/24 ... peers │
 customer──▶│ 10.99.0.102                              │
   Pi ─────▶│ 10.99.0.2  (exit; persistent keepalive)  │
            └───────────────────────────────────────┘
                    │ routing/NAT on VPS
                    ▼
          customer pkts → forwarded into Pi peer → Pi NATs to Airtel → internet
```

### Addressing (proposal)
- Hub subnet: `10.99.0.0/24`
- VPS hub address: `10.99.0.1`
- Pi exit: `10.99.0.2` (fixed)
- Customers: `10.99.0.101+` (one /32 per customer, issued at provisioning)

## 2. Components

### a) VPS hub (`server/`)
- WireGuard interface `wg0`, listening on a UDP port (e.g. 51820).
- Peers: the Pi + every customer.
- Routing: customer packets destined for the internet are forwarded to the Pi peer (not
  NAT'd out the VPS's own uplink). Options to evaluate:
  - per-customer `AllowedIPs = 0.0.0.0/0` pointing default route at Pi, with fwmark/policy
    routing on the VPS, **or**
  - a small routing table that sends customer source IPs into the Pi tunnel.
- `verify`: a customer must only be able to reach the internet-via-Pi, not other customers
  (firewall isolation between /32s).

### b) Pi exit (`pi-exit/`)
- WireGuard peer of the VPS, with `PersistentKeepalive = 25` so the outbound tunnel stays up
  through CGNAT.
- `AllowedIPs` on the VPS side = `10.99.0.2/32`; the Pi accepts forwarded customer traffic and
  **NATs it out `eth0`/`wlan0`** to Airtel (`iptables MASQUERADE`).
- IP forwarding + masquerade enabled. This is what makes the customer's public IP = the Pi's
  Airtel IP.

### c) Android client (`android/`)
- Embeds `wireguard-go` (MIT) or uses the official `wireguard-android` `GoBackend` /
  `tunnel` library (also permissive) — evaluate which is less work.
- `VpnService` brings up the tun; config = the customer's wg keypair + the VPS endpoint +
  `AllowedIPs = 0.0.0.0/0` + DNS.
- **Lifecycle is the risk** (see CLAUDE.md): foreground service, VPN-permission dialog,
  reconnect after disconnect, sleep/wake. Mirror the hard-won fixes from the other app.
- First-run: customer enters an **access code**; client calls the provisioning API and
  receives its wg config.

### d) Provisioning API (`provisioning/`)
- Backend (small service on the VPS or alongside) that:
  - `create customer` → generate wg keypair, assign a /32, add peer to VPS `wg0`, return config.
  - `enable/disable customer` → add/remove the peer (or firewall rule) on the VPS. This is the
    remote on/off switch (equivalent to the ACL lever in the Headscale design).
  - `trial` → store an expiry; a disabled/expired customer's peer is removed.
- Access code = the credential the customer types into the app to fetch their config.
- Admin surface: CLI first; a small GUI later (mirror the Headplane experience you liked).

## 3. CGNAT handling — the whole point
Nobody ever dials the CGNAT'd Pi. The Pi dials **out** to the public VPS and holds the tunnel
open with keepalive. Customers dial the public VPS. The VPS is the only publicly-reachable
party. CGNAT on either end never has to accept an inbound connection. Solved structurally.

## 4. Open questions to resolve early
1. VPS routing mechanism for "customer → Pi → internet" (policy routing vs. per-peer default
   route). Prototype both on the existing VPS without disturbing the Headscale stack (use a
   second wg interface + separate port).
2. Android wg library choice: raw `wireguard-go` vs `wireguard-android` tunnel lib.
3. Where the provisioning API runs and how access codes map to configs.
4. Bandwidth/cost model: all relayed traffic crosses the VPS — measure on the 3-node PoC.

## 5. Proof-of-concept (first milestone)
One VPS interface + the Pi + one phone:
- [ ] Stand up a second `wg` interface on the VPS (new port, `10.99.0.0/24`), no impact on
      Headscale.
- [ ] Connect the Pi as exit peer with keepalive + masquerade.
- [ ] Hand-craft one customer config; connect a phone using any WireGuard app first
      (validate routing before building the custom client).
- [ ] Confirm the phone's public IP = the Pi's Airtel IP, and measure latency/throughput.
- [ ] Only then: build the minimal `VpnService` client.

Validate the network design with an off-the-shelf WireGuard app **before** writing any Android
code — de-risks the hard part cheaply.
