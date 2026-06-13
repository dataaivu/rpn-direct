# RPN Direct Coordinator

Own-stack NAT-traversal control plane (no Tailscale / Headscale). See
[ARCHITECTURE.md](ARCHITECTURE.md) for the full design and rationale.

The coordinator **introduces peers and triggers hole-punching; it is not in the data
path** once a direct path is up. It only relays as a last resort (symmetric-CGNAT on
both ends).

## Status — milestone 1 (signaling hub + STUN-lite)

| Piece | State |
|------|-------|
| Control channel (WSS), registration, stable IP assignment | ✅ scaffolded |
| Peer roster broadcast | ✅ |
| Candidate exchange + synchronized `punch` (simultaneous-open) | ✅ |
| Direct-fail → relay-instruction signaling | ✅ |
| STUN-lite server-reflexive discovery | ✅ (own minimal frame; RFC 5389 next) |
| **Compiled / tested** | ⛔ **not yet** — no Go toolchain on the dev box; CI (`.github/workflows/coordinator.yml`) builds + vets on push |
| TURN relay (pion/turn) actually forwarding | ⬜ milestone 2 |
| `agent` — `wireguard-go` + pion/ice data plane | ⬜ milestone 3 (needs live VPS+Pi test loop) |
| Provisioning (access codes, enable/disable/expiry) | ⬜ milestone 4 |

## Build / run

```sh
cd coordinator
go mod tidy
go build -o rpn-coord ./...

# dev mode (any access code accepted):
./rpn-coord -http :8089 -stun :3479 \
    -stun-public  65.20.80.3:3479 \
    -relay-public 65.20.80.3:3478

# production: configure access codes
./rpn-coord -codes "ABC123:family-sharma,DEF456:family-rao" ...
```

Isolated from the live Headscale stack: distinct process, ports (`8089/tcp`, `3479/udp`),
and the `10.99.0.0/24` subnet — nothing here touches the working MagicStreamer/RPN product.

## Next: get a real test loop

The hard part (milestone 3) must be built against real NATs, not blind. Options, in order
of preference:
1. **Build on the VPS** (`65.20.80.3`) where Go installs cleanly — run the coordinator there,
   run the agent on the Pi and a laptop, watch a path come up.
2. **Local Go** on the dev box + the Pi as the second peer.
3. CI only validates *compilation*, not traversal — it can't punch NAT.
</content>
