# Provisioning

Creates and controls customers. The **access code** a customer types into the app maps to
their WireGuard config here. This module is also the **remote on/off switch** — the direct-stack
equivalent of the ACL lever in the Headscale design.

Operations (see ../SPEC.md §2d):
- `create customer` → generate wg keypair, assign a `/32`, add peer to the VPS hub, return config.
- `enable / disable customer` → add/remove the VPS peer (or a firewall rule). Propagates immediately.
- `trial` → store expiry; expired/disabled customers lose their peer.

Admin GUI: **DONE** — manual provisioning is now point-and-click via **wg-portal v2** on the
VPS (see `../server/wg-portal.md`). Creating a peer = create customer; peer expiry = trial;
the peer's `disabled` toggle = the on/off lever. An automated provisioning API (below) is still
future work for the in-app access-code flow.

TODO:
- [ ] Decide where it runs (on the VPS alongside `wg-direct`).
- [ ] Data store for customers ↔ keys ↔ /32 ↔ expiry ↔ enabled.
- [x] Small admin GUI for manual management — wg-portal v2 (see `../server/wg-portal.md`).
- [ ] Access-code issuance + redemption endpoint for the app (programmatic, beyond the GUI).
