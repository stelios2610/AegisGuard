#!/bin/bash
# FGUARD UTC - IPSec tunnel watchdog
# Initiates the IPSec child SA if tunnel is not ESTABLISHED.
# Run via cron every 2 minutes.
#
# Set CHILD_NAME to match the children{} block name in swanctl conf:
CHILD_NAME="tavros"   # or "Keratsini" on fitsolutions side
LOG="/var/log/fguard-ipsec-watchdog.log"

STATUS=$(swanctl --list-sas 2>/dev/null | grep -c ESTABLISHED)
if [ "$STATUS" -eq 0 ]; then
    swanctl --initiate --child "$CHILD_NAME" 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S'): Tunnel not ESTABLISHED, triggered initiate" >> "$LOG"
fi
