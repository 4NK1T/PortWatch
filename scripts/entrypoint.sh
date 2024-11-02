#!/bin/bash

SCAN_INTERVAL=${SCAN_INTERVAL:-3600}
DATA_DIR="/data"

# Ensure data directory exists
mkdir -p "$DATA_DIR"

# Main loop
while true; do
    echo "[$(date)] Starting scan cycle"
    
    # Run the nmap scan
    /app/nmap_scan.sh
    
    # Convert results to SQLite
    for xml in "$DATA_DIR"/*.xml; do
        if [ -f "$xml" ]; then
            python3 /app/nmap_to_sqlite.py "$xml"
        fi
    done
    
    # Clean up old XML files (keep last 5)
    find "$DATA_DIR" -name "*.xml" -type f | sort -r | tail -n +6 | xargs -r rm
    
    echo "[$(date)] Scan cycle completed. Sleeping for $SCAN_INTERVAL seconds"
    sleep "$SCAN_INTERVAL"
done