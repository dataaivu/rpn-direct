# VPS Hub

WireGuard hub on the public VPS (`magicstreamer.duckdns.org`). All spokes connect here.

**Caution:** this VPS already runs the Headscale/Headplane stack for the *other* RPN app.
Use a **separate `wg` interface and UDP port** and a distinct subnet (`10.99.0.0/24`) so the
PoC cannot disrupt the existing service.

TODO (see ../SPEC.md §2a, §4):
- [ ] Second `wg` interface `wg-direct` on a new port, subnet `10.99.0.0/24`, hub `10.99.0.1`.
- [ ] Add the Pi as exit peer (`10.99.0.2/32`).
- [ ] Routing: forward customer traffic into the Pi peer (policy routing vs per-peer default).
- [ ] Firewall: isolate customers from each other; allow only internet-via-Pi.
