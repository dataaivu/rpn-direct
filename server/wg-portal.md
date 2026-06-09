# wg-portal — admin GUI for the `wgd0` hub (custom fork)

The WireGuard hub (`wgd0`, see `setup-wgd0.sh`) is managed through a web GUI:
a **custom fork of [wg-portal](https://github.com/h44z/wg-portal) v2.3.0** running in Docker on
the VPS (image tag `wg-portal:owner`). This is the "small admin GUI" that `SPEC.md §2d` /
`provisioning/README.md` planned (mirrors the Headplane experience of the other app), extended
with a protected **Owner** role and **GUI-managed admin**.

> **No secrets in this repo.** Login credentials, the Google OAuth client id/secret, and the
> admin password live outside the repo (on the dev machine + in the VPS config). See `.gitignore`.

## Architecture

```
browser ──HTTPS──▶ nginx (apex:8443, reuses apex Let's Encrypt cert)
                      │  proxy_pass
                      ▼
            wg-portal container (host net, --cap-add NET_ADMIN, 127.0.0.1:8888)
                      │  manages /etc/wireguard/wgd0.conf  (mounted)
                      ▼
                  wgd0 interface (live)
```

- **Hosting:** apex hostname `magicstreamer.duckdns.org` on a dedicated TLS port (**8443**).
  A subdomain was rejected — DuckDNS does not serve subdomains reliably (Let's Encrypt
  validation and public resolution both flaky), and wg-portal forbids a path component in
  `external_url`, so a sub-path under the apex isn't an option either.
- **Container:** image `wg-portal:owner`, `--network host`, `--cap-add NET_ADMIN` (required to
  manage `wgd0` — without it the container panics `device list error: operation not permitted`),
  restart policy `unless-stopped`. Config `/opt/wg-portal/config/config.yaml`; data (peers/users)
  in `/opt/wg-portal/data/sqlite.db`; mounts `/etc/wireguard`. The prior stock container is kept
  stopped as `wg-portal-old` for rollback.
- **Isolation from the other app:** wholly separate from the Headscale/Headplane stack on the
  same VPS — different container, port, and the `wgd0` interface only.

## The fork patch (`wg-portal/patch.py`)

`wg-portal/patch.py` applies idempotent edits to a clean `git clone --branch v2.3.0` of upstream:

1. **Protected Owner role.** Config key `auth.owners: [ ... ]` (a list of owner identifiers /
   emails). Backend guards in `internal/app/users/user_manager.go` (`isOwner`,
   `actorIsOwnerOrSystem`, checks in `validateModifications` + `validateDeletion`) so a
   **non-owner admin cannot delete, disable, lock, or demote an owner**, and owners are forced
   `IsAdmin=true` (also re-asserted on every OIDC login in `internal/app/auth/auth.go`). An
   `IsOwner` computed flag is exposed in the v0 user DTO and shown as an "Owner" badge in
   `frontend/src/views/UserView.vue`.
2. **GUI-managed admin.** `getOauthFieldMapping` in `internal/app/auth/oauth_common.go` defaulted
   the `is_admin` claim mapping to `"admin_flag"`, which makes `adminInfoAvailable=true` and lets
   OIDC overwrite the admin flag on every login. The patch defaults it to `""`, so when no
   `field_map.is_admin`/`admin_mapping` is configured, OIDC never touches the admin flag and the
   **GUI Admin checkbox is authoritative and persists across logins**.

### Build & deploy

Building must happen where there is RAM/CPU headroom (the VPS is 1 vCPU / ~1 GB; add temporary
swap first, or build on a bigger host). The Vite frontend compile is the heavy step.

```sh
git clone --depth 1 --branch v2.3.0 https://github.com/h44z/wg-portal.git wg-portal-build
cp wg-portal/patch.py wg-portal-build/ && (cd wg-portal-build && python3 patch.py)
cd wg-portal-build && DOCKER_BUILDKIT=1 docker build --build-arg BUILD_VERSION=v2.3.0-owner -t wg-portal:owner .
# deploy (preserves data; same mounts/caps as the old container):
docker stop wg-portal && docker rename wg-portal wg-portal-old
docker run -d --name wg-portal --network host --restart unless-stopped --cap-add NET_ADMIN \
  -v /etc/wireguard:/etc/wireguard -v /opt/wg-portal/data:/app/data -v /opt/wg-portal/config:/app/config \
  wg-portal:owner
```

## Authentication & roles

- **Sign in with Google** — reuses the *same* Google OAuth client the Headplane GUI uses;
  `registration_enabled: false`, so a user must be **pre-created** with `Identifier = their exact
  Gmail` (the OIDC `email` claim is the match key). Google Cloud Console must list the redirect
  URI `<external_url>/api/v0/auth/login/google/callback`.
- **Local admin** (break-glass) — username/password in `config.yaml`.
- **Roles:** `auth.owners` = protected owners (always admin, unremovable by non-owners);
  everyone else is a normal user or a GUI-toggled admin.

Note: per-user API routes encode the identifier with a custom base64url variant
(`=`→`-`, `/`→`_`, `+`→`.`, see `internal/app/api/v0/handlers/encoding.go`).

## Daily backups (`wg-portal/wgportal-backup.sh`)

A systemd timer runs `wgportal-backup.sh` daily at 03:30 → a tar.gz of the sqlite DB + config +
`wgd0` keys/conf in `/opt/backups/wg-portal/`, with **15-day retention**. Restore any archive
with `wgportal-restore.sh <archive>` (stops the container, snapshots current state, restores,
restarts). Both scripts live in `wg-portal/` here.

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
