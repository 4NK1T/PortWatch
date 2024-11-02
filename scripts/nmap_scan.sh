#!/bin/bash

SCAN_DIR="/data"
IPS_FILE="$SCAN_DIR/targets.txt"
LOG_FILE="$SCAN_DIR/scan.log"

function log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

function run_scan() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local xml_file="$SCAN_DIR/nmap_${timestamp}.xml"
    local db_file="$SCAN_DIR/nmap_results.db"

    log "Starting nmap scan..."
    
    if nmap -p- -sCV -T3 --max-retries 2 \
         --min-rate 7500 -sS \
         --initial-rtt-timeout 200ms \
         -oX "$xml_file" \
         -iL "$IPS_FILE"; then
        
        log "Scan completed successfully. XML file created at: $xml_file"
        
        # Run the SQLite conversion with proper error handling
        if python3 /app/nmap_to_sqlite.py "$xml_file"; then
            log "Successfully converted to SQLite database"
        else
            log "Error: Failed to convert XML to SQLite"
            return 1
        fi
        
        # Cleanup old XML files (keep last 5)
        find "$SCAN_DIR" -name "nmap_*.xml" -type f | sort -r | tail -n +6 | xargs -r rm
        
        log "Scan cycle completed"
    else
        log "Nmap scan failed with error code $?"
        return 1
    fi
}

# Main execution
if [ ! -f "$IPS_FILE" ]; then
    log "No targets file found at $IPS_FILE"
    exit 1
fi

run_scan