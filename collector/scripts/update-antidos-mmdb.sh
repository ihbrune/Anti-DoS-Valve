#!/usr/bin/env bash
# =============================================================================
# update-antidos-mmdb.sh
# Automated update script for DB-IP Lite binary MMDB databases (ASN and Country)
# Suitable for daily execution via cron (/etc/cron.daily/ or /etc/cron.d/)
# =============================================================================

set -euo pipefail

TARGET_DIR="${1:-/var/lib/antidos}"
USER_OWNER="${2:-antidos}"
GROUP_OWNER="${3:-antidos}"

# Ensure target directory exists
if [[ ! -d "$TARGET_DIR" ]]; then
    mkdir -p "$TARGET_DIR"
fi

TMP_DIR="$(mktemp -d /tmp/antidos-mmdb-XXXXXX 2>/dev/null || mktemp -d -t 'antidos-mmdb')"
trap 'rm -rf "$TMP_DIR"' EXIT

# Determine current YYYY-MM and previous month as fallback
CURRENT_YM="$(date +%Y-%m)"
PREV_YM="$(date -d '1 month ago' +%Y-%m 2>/dev/null || date -v-1m +%Y-%m 2>/dev/null || true)"

download_and_extract() {
    local TYPE="$1"       # "asn" or "country"
    local OUT_NAME="$2"   # "dbip-asn-lite.mmdb" or "dbip-country-lite.mmdb"
    local SUCCESS=0

    # Try current month first, fallback to previous month if early in the month
    for YM in "$CURRENT_YM" "$PREV_YM"; do
        if [[ -z "$YM" ]]; then continue; fi
        local URL="https://download.db-ip.com/free/dbip-${TYPE}-lite-${YM}.mmdb.gz"
        echo "[$(date -Iseconds)] Trying download: $URL"
        if curl -fsSL -A "AntiDoS-Collector-Updater/1.0" -o "$TMP_DIR/${TYPE}.mmdb.gz" "$URL"; then
            echo "[$(date -Iseconds)] Download succeeded for $TYPE ($YM). Extracting..."
            gzip -d -f "$TMP_DIR/${TYPE}.mmdb.gz"
            if [[ -s "$TMP_DIR/${TYPE}.mmdb" ]]; then
                # Atomically replace target file
                mv -f "$TMP_DIR/${TYPE}.mmdb" "$TARGET_DIR/${OUT_NAME}"
                SUCCESS=1
                echo "[$(date -Iseconds)] Successfully installed $OUT_NAME in $TARGET_DIR"
                break
            fi
        fi
    done

    if [[ "$SUCCESS" -ne 1 ]]; then
        echo "[$(date -Iseconds)] WARNING: Failed to download or update $TYPE database." >&2
        return 1
    fi
}

echo "[$(date -Iseconds)] Starting Anti-DoS MMDB database update in $TARGET_DIR"
download_and_extract "asn" "dbip-asn-lite.mmdb" || true
download_and_extract "country" "dbip-country-lite.mmdb" || true

# Set ownership and permissions if running as root
if [[ $(id -u) -eq 0 ]] && id "$USER_OWNER" &>/dev/null; then
    chown "$USER_OWNER:$GROUP_OWNER" "$TARGET_DIR"/dbip-*.mmdb 2>/dev/null || true
fi
chmod 644 "$TARGET_DIR"/dbip-*.mmdb 2>/dev/null || true

echo "[$(date -Iseconds)] Anti-DoS MMDB database update completed."

# Reload / restart collector service if systemd service is active
if command -v systemctl &>/dev/null && systemctl is-active --quiet antidos-collector; then
    echo "[$(date -Iseconds)] Restarting antidos-collector to load updated MMDB databases..."
    systemctl restart antidos-collector
fi
