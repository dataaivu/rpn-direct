# core — shared ICE + userspace-WireGuard engine

The globally-robust NAT-traversal engine for RPN Direct. One Go package, two consumers:

- **Android** — `gomobile bind` turns `core/mobile` into an `.aar` the app links against.
- **Pi agent** — imports `core` natively (ARM binary).

Both ends run the *same* engine so their ICE agents interoperate.

## How it works

```
        coordinator /ws (signaling: candidates + ICE creds + punch timing)
                              │
   ┌──────────────────────────┴──────────────────────────┐
   ▼                                                       ▼
customer                                                  Pi exit
 pion/ice  ── connectivity checks ──▶ best path ◀── connectivity checks ── pion/ice
   │  host → srflx(STUN) → relay(TURN)        host → srflx(STUN) → relay(TURN)
   ▼                                                       ▼
 iceBind (conn.Bind)                                   iceBind
   │  wraps the chosen *ice.Conn                           │
   ▼                                                       ▼
 wireguard-go device  ◀══ encrypted WG over the ICE path ══▶ wireguard-go device
```

pion/ice picks **direct** when the pair is punchable and **TURN-relay** when it
isn't (symmetric×symmetric). `iceBind` makes wireguard-go tunnel over whatever
conn ICE selects — WG never knows or cares which path won.

## Files
- `protocol.go`  — JSON wire types, byte-compatible with `coordinator/protocol.go` (+ ufrag/pwd).
- `signaling.go` — WSS control-channel client.
- `icebind.go`   — adapts a pion `*ice.Conn` into a wireguard-go `conn.Bind`. The heart.
- `engine.go`    — orchestration; exports `Start/Stop/Status`.
- `keys.go`      — Curve25519 pubkey derivation.
- `mobile/`      — gomobile-bound primitive-only wrapper.

## Build the Android .aar locally
```
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile init
gomobile bind -target=android/arm64,android/arm -o rpncore.aar ./mobile
```
CI does this in `.github/workflows/core.yml`.

## Status / TODO
- [x] Single client↔exit ICE session, direct + TURN fallback.
- [ ] **Multi-peer on the Pi** — one ICE conn per customer needs a demuxing bind
      (map peer → `*ice.Conn`) or one device per customer. Current `iceBind` is
      single-conn. This is the next iteration before the Pi can serve many users.
- [ ] Pi agent: call `core` instead of kernel `wg set` (keep iptables MASQUERADE
      to Airtel on the userspace tun).
- [ ] Coordinator: relay `ufrag`/`pwd` in PeerInfo + Punch (protocol fields added;
      handler wiring pending).
- [ ] Trickle ICE (currently gathers fully before signaling).

Not yet compiled end-to-end — iterated via CI (`go vet` + gomobile + gradle).
