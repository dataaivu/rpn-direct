#!/usr/bin/env bash
# Daily backup of wg-portal (sqlite DB + config) and the wgd0 WireGuard interface.
# Retains backups for 15 days. Restore with wgportal-restore.sh.
set -euo pipefail

BACKUP_DIR=/opt/backups/wg-portal
DATA_DB=/opt/wg-portal/data/sqlite.db
CONFIG_DIR=/opt/wg-portal/config
WG_DIR=/etc/wireguard
RETENTION_DAYS=15

TS=$(date +%Y%m%d-%H%M%S)
mkdir -p "$BACKUP_DIR"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Consistent sqlite snapshot (handles WAL); fall back to copy.
if command -v sqlite3 >/dev/null 2>&1; then
  sqlite3 "$DATA_DB" ".backup '$TMP/sqlite.db'"
else
  cp -a "$DATA_DB" "$TMP/sqlite.db"
fi

# wg-portal config (includes OIDC + owners) and the live WireGuard interface + keys.
cp -a "$CONFIG_DIR" "$TMP/config"
mkdir -p "$TMP/wireguard"
cp -a "$WG_DIR"/wgd0.conf "$TMP/wireguard/" 2>/dev/null || true
cp -a "$WG_DIR"/srv_wgd0.* "$WG_DIR"/cli1_wgd0.* "$TMP/wireguard/" 2>/dev/null || true

ARCHIVE="$BACKUP_DIR/wgportal-$TS.tar.gz"
tar -czf "$ARCHIVE" -C "$TMP" .
chmod 600 "$ARCHIVE"
echo "$(date -Is) backup created: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

# Retention: delete backups older than RETENTION_DAYS days.
find "$BACKUP_DIR" -maxdepth 1 -name 'wgportal-*.tar.gz' -mtime +"$RETENTION_DAYS" -print -delete
echo "$(date -Is) retention applied (kept last ${RETENTION_DAYS} days)"
