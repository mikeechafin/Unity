#!/bin/bash
# set_dbsnmp.sh
# Version: 2026-01-16 v2.0
# Purpose: Unlock and reset dbsnmp password on all VMs in the list
# Changes:
#   - Use /etc/oratab as primary source for ORACLE_HOME (most reliable)
#   - Fallback to inventory.xml if oratab is empty
#   - Handle multiple ORACLE_SID (use the first running one)
#   - Better error checking & logging
#   - Added hostname in output for easier debugging

set -euo pipefail

SSH_CMD="/bin/ssh -T -o StrictHostKeyChecking=no -o PreferredAuthentications=publickey"
USER="oracle"
HOST_LIST="$1"

if [[ ! -f "$HOST_LIST" ]]; then
    echo "Error: Host list file not found: $HOST_LIST"
    exit 1
fi

echo "Starting dbsnmp reset/unlock on hosts from: $HOST_LIST"
echo "Using user: $USER"
echo "----------------------------------------"
echo

mapfile -t NODES < "$HOST_LIST"

for NODE in "${NODES[@]}"; do
    NODE=$(echo "$NODE" | tr -d '[:space:]')  # trim whitespace
    [[ -z "$NODE" ]] && continue

    echo "Processing: $NODE"
    echo "----------------------------------------"

    $SSH_CMD "$USER@$NODE" << 'EOF'
        # ==================== Remote script starts here ====================

        set -euo pipefail
        HOSTNAME=$(hostname -f)

        echo "Running on: $HOSTNAME"

        # 1. Try to get ORACLE_HOME from /etc/oratab (most reliable)
        if [[ -f /etc/oratab ]]; then
            # Get first non-comment line with valid ORACLE_HOME
            ORACLE_HOME=$(awk -F: '!/^(#|$)/ && $2 != "" {print $2; exit}' /etc/oratab 2>/dev/null)
        fi

        # 2. Fallback: parse inventory.xml for any database home (OraDB* or OraHome*)
        if [[ -z "$ORACLE_HOME" && -f /etc/oraInst.loc ]]; then
            INVENTORY_LOC=$(grep '^inventory_loc=' /etc/oraInst.loc | cut -d= -f2)
            if [[ -n "$INVENTORY_LOC" && -f "$INVENTORY_LOC/ContentsXML/inventory.xml" ]]; then
                # Look for any home that looks like a DB home (OraDB*, OraHome*, etc.)
                ORACLE_HOME=$(grep -E 'Ora(DB|Home|GiHome)' "$INVENTORY_LOC/ContentsXML/inventory.xml" \
                              | head -1 | grep -oP 'LOC="\K[^"]+' | head -1 2>/dev/null)
            fi
        fi

        if [[ -z "$ORACLE_HOME" ]]; then
            echo "ERROR: Could not determine ORACLE_HOME on $HOSTNAME"
            echo "       - /etc/oratab has no valid entry"
            echo "       - No suitable home found in inventory.xml"
            exit 1
        fi

        echo "Found ORACLE_HOME: $ORACLE_HOME"

        # Verify sqlplus exists
        SQLPLUS="$ORACLE_HOME/bin/sqlplus"
        if [[ ! -x "$SQLPLUS" ]]; then
            echo "ERROR: sqlplus not executable at $SQLPLUS"
            exit 1
        fi

        # Find running ORACLE_SID (first pmon process)
        ORACLE_SID=$(ps -eo args | grep -i '^ora_pmon_' | grep -v grep | awk '{print $1}' | sed 's/ora_pmon_//' | head -1)

        if [[ -z "$ORACLE_SID" ]]; then
            echo "WARNING: No running database instance (pmon) found on $HOSTNAME"
            echo "         Skipping this host."
            exit 0
        fi

        echo "Found running instance: $ORACLE_SID"

        export ORACLE_HOME
        export ORACLE_SID

        PASS="We1come$"

        echo "Resetting dbsnmp password and unlocking account..."
        echo

        # Run both commands
        {
            echo "ALTER USER dbsnmp IDENTIFIED BY \"$PASS\";"
            echo "ALTER USER dbsnmp ACCOUNT UNLOCK;"
            echo "EXIT;"
        } | "$SQLPLUS" -S / as sysdba

        # Check if sqlplus succeeded
        if [[ $? -eq 0 ]]; then
            echo "SUCCESS: dbsnmp password reset and account unlocked on $HOSTNAME (SID: $ORACLE_SID)"
        else
            echo "ERROR: sqlplus failed on $HOSTNAME"
        fi

        echo "----------------------------------------"
EOF

    echo
done

echo "All hosts processed."
echo "Done."
