# Pi Exit Node

Raspberry Pi on Airtel residential (India). Behind CGNAT — so it dials **outbound** to the
VPS hub and holds the tunnel open with `PersistentKeepalive = 25`. It NATs forwarded customer
traffic out to Airtel, making the customer's public IP the Pi's local Airtel IP (the product).

TODO (see ../SPEC.md §2b):
- [ ] WireGuard peer config: VPS endpoint, `10.99.0.2/32`, keepalive 25.
- [ ] `net.ipv4.ip_forward = 1`.
- [ ] `iptables -t nat -A POSTROUTING -o <uplink> -j MASQUERADE` for customer subnet.
- [ ] Survive reboots (systemd / wg-quick) and ISP reconnects.
