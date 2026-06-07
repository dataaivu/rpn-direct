# Android Client

Minimal customer app: a `VpnService` that brings up a WireGuard tunnel to the VPS hub with
`AllowedIPs = 0.0.0.0/0`. First run asks for an **access code**, fetches the customer's wg
config from the provisioning API, then connects.

**The hard part is lifecycle, not WireGuard** (see ../CLAUDE.md). Before writing code, review
the reconnect/deadlock/“Disconnecting…” lessons from the other RPN app (`C:\Users\Mayreen\ts-android`)
— the same `VpnService` + foreground-service + permission + sleep/wake issues apply here.

TODO (see ../SPEC.md §2c, §5):
- [ ] Validate the network design with an **off-the-shelf** WireGuard app first.
- [ ] Choose wg library: raw `wireguard-go` vs `wireguard-android` tunnel lib.
- [ ] `VpnService` + foreground notification + VPN-permission flow.
- [ ] Access-code entry → provisioning fetch → connect.
- [ ] Reconnect-after-disconnect correctness (mirror the other app's ordered-teardown fix).
