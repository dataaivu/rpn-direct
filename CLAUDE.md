# RPN Direct — own-stack residential VPN (no Tailscale/Headscale)

## What this project is
A **from-scratch, fully-owned** alternative to the current RPN app. Same product goal —
route a customer's traffic out through a **residential exit node** (India / Airtel) so they
get a genuine local IP — but built on **plain WireGuard in a hub-and-spoke topology**, with
our own client, our own server, and our own provisioning. **No Tailscale client, no Headscale,
no DERP, no coordination protocol.**

This is a *separate* project from the existing Tailscale-fork app. That app still lives at
`C:\Users\Mayreen\ts-android` (repo `dataaivu/rpn`) and is not touched here.

## Why hub-and-spoke (the core design decision)
You **cannot** reliably punch a direct hole through CGNAT-on-both-ends (customer behind
residential NAT, Pi behind Airtel CGNAT). Every VPN solves the hard case the same way: a
**publicly-reachable relay**. We already have one — the Vultr VPS. So instead of a mesh +
NAT traversal (what Tailscale spent years on), we use a simple hub:

```
Pi (India, CGNAT) ── persistent OUTBOUND wg tunnel ──▶ VPS (public IP) ◀── wg ── Customer
                                                          │
                                          VPS routes customer traffic into
                                          the Pi's tunnel → Airtel → internet
```

- Pi dials **out** to the VPS → its CGNAT is irrelevant (outbound is always allowed).
- Customers dial the **public VPS** → no hole-punching needed (VPS has a real IP).
- CGNAT is sidestepped **by design**, not by clever traversal.

Trade-off accepted: all traffic relays through the VPS (bandwidth cost, single hop). We give
up direct-path latency optimization — but with double-CGNAT, direct often wasn't possible
anyway.

## Known infrastructure (do NOT put secrets in this repo)
- **VPS hub:** `65.20.80.3` (`magicstreamer.duckdns.org`), Vultr. Currently also runs the
  Headscale/Headplane stack for the *other* app — be careful not to disrupt it.
- **Admin GUI:** a custom fork of wg-portal v2.3.0 (`wg-portal:owner`) manages the `wgd0` hub via
  a web GUI (apex `:8443`, Google-OIDC gated) — adds a protected **owner** role + GUI-managed
  admin, plus daily 15-day-retention backups. Patch, scripts and full notes in `server/wg-portal/`
  and `server/wg-portal.md`; credentials live off-repo on the dev machine.
- **Exit node:** Raspberry Pi, India, Airtel residential (~CGNAT). The genuine local IP is the
  whole product value.
- Secrets (SSH, tokens, keys) live **outside** this repo on the dev machine. Never commit them.

## The hard part (don't underestimate)
The difficulty is NOT WireGuard — `wireguard-go` (MIT) is embeddable and the crypto/tunnel is
solved. The difficulty is the **Android VPN lifecycle**: `VpnService`, foreground service,
the VPN permission dialog, and reconnect/sleep-wake handling. The other RPN app already fought
and won exactly these battles (a backend deadlock on disconnect, a stuck "Disconnecting…"
state). Expect to re-solve them here. Study those lessons before writing the client.

## Scope
- IN: WireGuard hub config (VPS), Pi persistent-tunnel setup, minimal Android client
  (`VpnService` + wireguard-go), a provisioning API (create customer → issue wg keys/config →
  enable/disable).
- OUT: the existing Tailscale-fork app; multi-platform clients (Android first; iOS/desktop later).

## Conventions
- Read `SPEC.md` for the full technical design before implementing.
- Windows dev box, PowerShell default. Mind UTF-8 BOM when writing build files (use editor tools,
  not `Set-Content -Encoding utf8`).
- Keep credentials in env vars / local files, never in the repo. See `.gitignore`.
