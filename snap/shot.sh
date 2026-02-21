#!/bin/bash
set -euo pipefail

############################################
# CONFIGURATION
############################################

BASE_TIME="03:02"   # UTC time (HH:MM)
TARGET_FILE="/disk/boot/menu/aaa.vhd"
TARGET_FILE2="/disk/boot/menu/aaa.efi"
SOURCE_FILE="/disk/boot/menu/windows_snapshot.vhd"

rm -f "$TARGET_FILE"
rm -f "$TARGET_FILE2"

############################################
# DERIVED VALUES (UTC, PURE EPOCH MATH)
############################################

IFS=":" read -r BASE_HOUR BASE_MIN <<< "$BASE_TIME"

BASE_SECONDS=$((10#$BASE_HOUR * 3600 + 10#$BASE_MIN * 60))

NOW_EPOCH=$(date -u +%s)

SECONDS_IN_DAY=86400
SECONDS_SINCE_MIDNIGHT=$((NOW_EPOCH % SECONDS_IN_DAY))

############################################
# Compute sleep duration until next BASE_TIME
############################################

if [ "$SECONDS_SINCE_MIDNIGHT" -lt "$BASE_SECONDS" ]; then
    SLEEP_SECONDS=$((BASE_SECONDS - SECONDS_SINCE_MIDNIGHT))
else
    SLEEP_SECONDS=$((SECONDS_IN_DAY - SECONDS_SINCE_MIDNIGHT + BASE_SECONDS))
fi

echo "Sleeping $SLEEP_SECONDS seconds until next $BASE_TIME UTC..."
sleep "$SLEEP_SECONDS"

############################################
# Perform action
############################################

echo "$BASE_TIME UTC reached. Updating boot entry..."

ln "$SOURCE_FILE" "$TARGET_FILE"

echo "Rebooting system..."
reboot
