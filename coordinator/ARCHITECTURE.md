# RPN Direct — NAT-Traversal Coordinator (own-stack, no Tailscale)

Goal: replicate the **"VPS only coordinates, data goes direct"** model in plain
WireGuard — a self-hosted control plane that introduces peers, helps them punch
through NAT to a **direct** path, and **relays** only when the NAT physics make a
direct path impossible. No tailscale.com, no Headscale, no Tailscale client.

This is a magicsock-class subsystem. We do **not** reinvent STUN/ICE from the RFCs;
we stand on the systems that already solved each piece and glue them to WireGuard.

## Sources we draw from
| Piece | Source of inspiration | What we take |
|------|----------------------|--------------|
| Candidate gathering, connectivity checks, simultaneous-open, relay fallback | **IETF ICE/STUN/TURN** via **pion** (`pion/ice`, `pion/stun`, `pion/turn`) | The whole NAT-traversal state machine — battle-tested, pure Go. |
| Binding traversal to WireGuard on one socket | **Tailscale magicsock / disco / DERP** | One UDP socket multiplexes disco probes *and* WG packets, so the punched mapping is the one WG uses. |
| The data plane | **WireGuard (userspace `wireguard-go`)** | Userspace WG lets us own the UDP socket; kernel WG can't share the punched mapping cleanly. |

## Why userspace WireGuard (not kernel `wg`)
A NAT mapping is per-source-port. If a separate STUN/ICE socket punches the hole,
kernel WG's *own* socket (different port) won't inherit that mapping — so the punch
is wasted. Tailscale solves this by making one socket (`magicsock`) do both. We do the
same: `wireguard-go` hands us a `conn.Bind`, and our bind is an ICE-aware socket that
sends/receives WG packets on the exact port ICE validated. This is the single most
important design decision and the reason a naive kernel-WG + `wg set endpoint` approach
fails on symmetric NAT.

## Roles (maps onto RPN Direct)
- **exit**  — the residential box (Pi / PC) in India. Advertises itself as the egress;
  NATs forwarded traffic out Airtel. One per location.
- **client** — a customer device (phone / Fire TV / the Android app). Wants its default
  route to egress via an `exit`.
- **coordinator** — the VPS. Public, always-on. **Control plane + relay-of-last-resort.**
  Never in the data path once a direct path is established.

## Topology
```
        coordinator (VPS, public)  — signaling (WSS) + STUN + TURN relay
        ┌───────────────────────────────────────────────┐
        │  control channel (who exists, candidates, punch)│
        └───────────────────────────────────────────────┘
            ▲                                   ▲
            │ control                           │ control
        client (DE, CGNAT)                  exit (IN, Airtel CGNAT/static)
            └──────────── DIRECT WG data path ─────────────┘   ← the goal
                  (relay via coordinator only if punch fails)
```

## Connection lifecycle
1. **Register** — peer opens WSS to coordinator, sends `hello{accessCode, pubKey, role}`.
   Coordinator authenticates the access code, assigns a stable VPN IP (`10.99.0.0/24`),
   returns `welcome{selfIP, stunEndpoint, relayEndpoint}` and the current peer list.
2. **Gather candidates** — each peer gathers ICE candidates:
   - *host*  : its LAN addresses,
   - *srflx* : its public mapping, learned from the coordinator's STUN endpoint
     (server-reflexive — also classifies NAT behaviour, RFC 5780),
   - *relay* : a TURN allocation on the coordinator (fallback).
   Peer reports them with `endpoints{candidates}`.
3. **Introduce** — coordinator pushes each peer the others' candidates (`peers`).
4. **Punch** — when a client wants an exit, coordinator sends `punch{peer, candidates, at}`
   to **both** simultaneously (synchronized clock from the coordinator). pion/ice runs
   connectivity checks; first valid pair wins.
5. **Bind to WG** — the winning candidate pair *is* the socket `wireguard-go` uses.
   Endpoint steering happens inside the bind, transparently — no `wg set` race.
6. **Relay fallback** — if no pair validates (symmetric ↔ symmetric CGNAT), peers use the
   TURN relay on the coordinator. WG traffic is already encrypted; the relay just forwards
   by allocation. **This is the only case the VPS carries data — and the only case with a
   bandwidth cost.**
7. **Maintain** — keepalive; re-gather + re-punch on endpoint change (roaming, new IP).

## The escape hatch that beats the physics
Symmetric-CGNAT on **both** ends cannot be punched — true for us, Tailscale, and NetBird
alike; all fall back to relay. The cheap way out is **a public/static IP on the exit**
(Airtel/Jio add-on). Then the exit publishes a *host/public* candidate that always wins,
the client connects directly with zero punching, and the relay is never used. The
coordinator code treats this as the trivial happy path: an exit with a public candidate
is just immediately reachable. **Recommended for the 4K use case** — it removes the one
expensive branch entirely.

## Maximizing direct connections — the agent's real job

This is where "Tailscale is good at direct" actually lives. It's a toolbox, not one trick.
The agent runs all of it; each technique lifts the share of connections that go direct
(and therefore cost zero bandwidth):

1. **Relay-first, upgrade-in-background.** Connect via the relay *instantly* so the product
   always works on tap one, then silently upgrade to a direct path the moment one validates.
   The user never waits on punching, and a relay-bound pair still works (just costs bandwidth).
2. **STUN server-reflexive discovery.** Learn the public ip:port mapping. (have: STUN-lite;
   upgrade to RFC 5389 + 5780 NAT-type classification via pion.)
3. **Synchronized simultaneous-open.** Both ends fire at the coordinator's `at` instant so each
   NAT sees an outbound first and admits the other's packet. (have: the `punch` message.)
4. **Local port-mapping — UPnP-IGD / NAT-PMP / PCP.** Ask the local router to open a port. If
   the exit is behind only its *own* home router (not deep carrier CGNAT), this yields a real
   forwarded port → direct, no punching needed. Many "CGNAT" homes are actually just one NAT.
5. **Symmetric-NAT port prediction (birthday paradox).** When one side has endpoint-dependent
   (symmetric) mapping, spray/guess ports to find the hole. Punches many symmetric NATs that
   naive STUN cannot — this is a big part of Tailscale's success rate.
6. **IPv6-first.** If both ends have native IPv6, connect over v6 (no NAT at all); prefer it.
   The coordinator just republishes the exit's rotating v6 endpoint — trivial, no punching.
7. **Continuous path discovery / roaming.** Keep probing; re-punch on network change; upgrade
   relay→direct whenever a path opens.

**Honest boundary:** double-symmetric-CGNAT with no IPv6 and no port-mappable router cannot be
punched by *any* of these — Tailscale included — and that pair relays. This toolbox lifts the
*direct* rate toward Tailscale's majority; it does not repeal the worst case. Which bucket the
real India↔Germany lines fall in is the one thing only a live `tailscale ping` test reveals.

## Components / build plan
| # | Component | Status | Notes |
|---|-----------|--------|-------|
| 1 | `coordinator` (this dir) — signaling hub + STUN responder | **scaffolding now** | Standard Go (WSS + UDP). Low risk. |
| 2 | TURN relay (pion/turn) embedded in coordinator | next | Allocation per peer-pair; only used on fallback. |
| 3 | `agent` — `wireguard-go` + pion/ice bind, on exit & client | next, **needs compile/test loop** | The hard part; build against live VPS+Pi. |
| 4 | Provisioning (access codes, enable/disable/expiry) | after PoC | Can fold into coordinator or sit beside it. |
| 5 | Android: swap baked config for agent + access-code fetch | after agent proven on desktop | Reuses the `VpnService` lifecycle fixes from the working app. |

## Wire protocol (control channel, JSON over WSS)
See `protocol.go`. Summary:
- C→S `hello`     `{accessCode, pubKey, role, name}`
- S→C `welcome`   `{selfIP, networkID, stunEndpoint, relayEndpoint}`
- S→C `peers`     `{peers:[{pubKey, role, vpnIP, candidates[], directOK}]}` (pushed on change)
- C→S `endpoints` `{candidates:[{type, addr}]}`
- C→S `connect`   `{peerPubKey}`
- S→C `punch`     `{peerPubKey, candidates[], atUnixMs}`
- C→S `result`    `{peerPubKey, ok, via:"direct"|"relay", addr}`
- S→C `relay`     `{peerPubKey, relaySession}`
- bidi `ping`/`pong` keepalive

## Isolation guarantee
Like `server/setup-wgd0.sh`, this is **additive and isolated** from the live Headscale
product: separate process, separate UDP ports, separate `10.99.0.0/24` subnet. Nothing
here touches the working MagicStreamer/RPN stack.

## Open risks (honest)
- ICE↔`wireguard-go` bind is fiddly; budget real iteration on live NATs (component 3).
- NAT-type detection (RFC 5780) needs the coordinator reachable on **two ports/IPs** to
  classify mapping vs filtering behaviour — provision that on the VPS.
- Relay bandwidth: if many customer pairs are symmetric-both-ends, the VPS pays. Push the
  static-IP-on-exit path to keep relay usage near zero.
</content>
</invoke>
