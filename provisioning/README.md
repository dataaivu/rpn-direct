# Provisioning

Creates and controls customers. The **access code** a customer types into the app maps to
their WireGuard config here. This module is also the **remote on/off switch** — the direct-stack
equivalent of the ACL lever in the Headscale design.

Operations (see ../SPEC.md §2d):
- `create customer` → generate wg keypair, assign a `/32`, add peer to the VPS hub, return config.
- `enable / disable customer` → add/remove the VPS peer (or a firewall rule). Propagates immediately.
- `trial` → store expiry; expired/disabled customers lose their peer.

TODO:
- [ ] Decide where it runs (on the VPS alongside `wg-direct`).
- [ ] Data store for customers ↔ keys ↔ /32 ↔ expiry ↔ enabled.
- [ ] CLI first; small admin GUI later (mirror the Headplane experience).
- [ ] Access-code issuance + redemption endpoint for the app.
