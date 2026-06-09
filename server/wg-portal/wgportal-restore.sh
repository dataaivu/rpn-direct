#!/usr/bin/env bash
# Restore a wg-portal backup produced by wgportal-backup.sh.
# Usage: wgportal-restore.sh /opt/backups/wg-portal/wgportal-YYYYMMDD-HHMMSS.tar.gz
set -euo pipefail

ARCHIVE="${1:-}"
if [ -z "$ARCHIVE" ] || [ ! -f "$ARCHIVE" ]; then
  echo "usage: $0 <archive.tar.gz>"
  echo "available backups:"; ls -1 /opt/backups/wg-portal/wgportal-*.tar.gz 2>/dev/null || true
  exit 1
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
tar -xzf "$ARCHIVE" -C "$TMP"

echo "Stopping wg-portal container..."
docker stop wg-portal >/dev/null

# Safety snapshot of current state before overwriting.
SB="/opt/backups/wg-portal/pre-restore-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$SB"
cp -a /opt/wg-portal/data/sqlite.db "$SB/" 2>/dev/null || true
cp -a /opt/wg-portal/config "$SB/" 2>/dev/null || true

echo "Restoring files..."
cp -a "$TMP/sqlite.db" /opt/wg-portal/data/sqlite.db
cp -a "$TMP/config/." /opt/wg-portal/config/
[ -d "$TMP/wireguard" ] && cp -a "$TMP/wireguard/." /etc/wireguard/ || true

echo "Starting wg-portal container..."
docker start wg-portal >/dev/null
echo "Restore complete from: $ARCHIVE"
echo "Previous state saved at: $SB"
