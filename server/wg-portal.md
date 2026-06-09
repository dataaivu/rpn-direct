# wg-portal — admin GUI for the `wgd0` hub

The WireGuard hub (`wgd0`, see `setup-wgd0.sh`) is managed through a web GUI:
**[wg-portal](https://github.com/h44z/wg-portal) v2** running in Docker on the VPS. This is the
"small admin GUI" that `SPEC.md §2d` / `provisioning/README.md` planned (mirrors the Headplane
experience of the other app).

> **No secrets in this repo.** Login credentials, the Google OAuth client, and the access URL
> live outside the repo (on the dev machine + in the VPS config). See `.gitignore` and CLAUDE.md.

## Architecture

```
browser ──HTTPS──▶ nginx (apex:8443, reuses apex Let's Encrypt cert)
                      │  proxy_pass
                      ▼
            wg-portal container (127.0.0.1:8888)
                      │  manages /etc/wireguard/wgd0.conf  (mounted)
                      ▼
                  wgd0 interface (live)
```

- **Hosting:** apex hostname `magicstreamer.duckdns.org` on a dedicated TLS port (**8443**).
  A subdomain was rejected — DuckDNS does not serve subdomains reliably (Let's Encrypt
  validation and public resolution both flaky), and wg-portal forbids a path component in
  `external_url`, so a sub-path under the apex isn't an option either.
- **Container:** image `wgportal/wg-portal:v2`, restart policy `unless-stopped`.
  Config `/opt/wg-portal/config/config.yaml`; data (peers/users) in
  `/opt/wg-portal/data/sqlite.db`; mounts `/etc/wireguard`.
- **Isolation from the other app:** wholly separate from the Headscale/Headplane stack on the
  same VPS — different container, port, and the `wgd0` interface only.

## Authentication

Two methods (both enabled):
1. **Google OIDC** — reuses the *same* Google OAuth client the Headplane GUI uses. Locked to a
   single operator Google account via `registration_enabled: false` + a pre-created admin user
   + an `admin_mapping` regex on the email claim. Requires one Google Cloud Console step:
   add the redirect URI `<external_url>/api/v0/auth/login/google/callback`.
2. **Local admin** (break-glass) — username/password stored in `config.yaml`.

## How the GUI maps to the provisioning model (`SPEC.md §2d`)

| Provisioning operation | wg-portal action                                  |
|------------------------|---------------------------------------------------|
| create customer        | create a peer on `wgd0`, assign a `/32` (10.99.0.101+) |
| trial                  | set the peer's expiry date                        |
| enable / disable       | toggle the peer's `disabled` flag (the on/off lever) |
| exit node              | the fixed Pi peer `10.99.0.2`                     |

## Known gap

Customer-to-customer **isolation is not yet enforced** — `wgd0`'s PostUp does a blanket
`FORWARD ACCEPT`, so peers on `10.99.0.0/24` can reach each other (violates `SPEC.md §2a/§4`).
wg-portal does not handle this; it needs iptables rules on the VPS. TODO.
