import paramiko
from maa_libraries import get_db_connection, encrypt_decrypt, is_hypervisor  # Import existing helpers from maa_libraries.py

def configure_snmp_entries(hostname, operation, config_content=''):
    """
    Configures SNMP entries on ILOMs or cells/DB servers.
    
    - hostname: The target hostname (e.g., ilom like scaqal05adm01-c.us.oracle.com, cell like scaqal05celadm01.us.oracle.com).
    - operation: 'setup' (add from config_content), 'clean' (drop maa-linked), 'cleanall' (drop all non-protected), 'check' (list current).
    - config_content: Optional multi-line string for setup (format: IP:port:ver:level:idType:secName per line).
    
    Skips if hypervisor (no agents expected). Uses root user, key-first auth, fallback to encrypted default 'We1come$'.
    Updates maamd.SNMP_SUBSCRIPTIONS (linked to agent ports in AGENT_HOME_INFO) and SNMP_USERS.
    Respects max 15 alerts per ILOM, PROTECTED_ENTRIES for users.
    """
    # Skip if hypervisor (no OEM agents/ILOM SNMP for hypervisors per context)
    if is_hypervisor(hostname):
        print(f"Skipping SNMP config on hypervisor {hostname}")
        return {'success': False, 'message': 'Hypervisor skipped'}

    # Get creds (root for ILOMs/cells/DB, encrypted from access_credentials)
    conn = get_db_connection()  # maamd user for DB ops
    cursor = conn.cursor()
    cred_query = "SELECT username, password FROM access_credentials WHERE component_name = :host OR component_name = 'default'"
    cursor.execute(cred_query, {'host': hostname})
    user, enc_pass = cursor.fetchone() or ('root', encrypt_decrypt('We1come$', decrypt=True))
    cursor.close()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, username=user, password=enc_pass, key_filename='/home/maatest/.ssh/id_rsa', timeout=10)
        
        # Detect SRVTYPE/CLITOOL (cellcli for cells/storage servers, dbmcli for DB servers/iloms)
        _, stdout, _ = ssh.exec_command("test -f /opt/oracle/cell/cellsrv/bin/cellcli && echo 'cellcli'")
        clitool = stdout.read().decode().strip() or 'dbmcli'
        srvtype = 'cell' if clitool == 'cellcli' else 'dbserver'

        # LIST current users/subscribers
        _, stdout, _ = ssh.exec_command(f"{clitool} -e 'LIST SNMPUSERS'")
        users = stdout.read().decode().splitlines()
        _, stdout, _ = ssh.exec_command(f"{clitool} -e 'LIST SNMPSUBSCRIBERS'")
        subscribers = stdout.read().decode().splitlines()

        if operation == 'check':
            # Return current state (for verification, linked to AGENT_HOME_INFO ports)
            return {'success': True, 'users': users, 'subscribers': subscribers}

        if operation == 'cleanall':
            # Drop all non-protected users/subscribers
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM maamd.PROTECTED_ENTRIES WHERE type = 'snmp_user'")
            protected = [row[0] for row in cursor.fetchall()]
            cursor.close()
            for sub in subscribers:
                ssh.exec_command(f"{clitool} -e 'ALTER {srvtype} DROP SNMPSUBSCRIBER {{{sub}}}'")
            for user in users:
                if user not in protected:
                    ssh.exec_command(f"{clitool} -e 'ALTER {srvtype} DROP SNMPUSER {user}'")
            # Clear maamd tables
            cursor = conn.cursor()
            cursor.execute("DELETE FROM maamd.SNMP_SUBSCRIPTIONS WHERE hostname = :host", {'host': hostname})
            cursor.execute("DELETE FROM maamd.SNMP_USERS WHERE hostname = :host", {'host': hostname})
            conn.commit()
            cursor.close()
            return {'success': True}

        if operation == 'clean':
            # Drop only maa-linked subscribers/users
            for sub in subscribers:
                if 'maa' in sub:  # maa-linked per context
                    ssh.exec_command(f"{clitool} -e 'ALTER {srvtype} DROP SNMPSUBSCRIBER {{{sub}}}'")
            for user in users:
                if 'maa' in user:
                    ssh.exec_command(f"{clitool} -e 'ALTER {srvtype} DROP SNMPUSER {user}'")
            # Clear maa-linked in maamd
            cursor = conn.cursor()
            cursor.execute("DELETE FROM maamd.SNMP_SUBSCRIPTIONS WHERE hostname = :host", {'host': hostname})
            cursor.execute("DELETE FROM maamd.SNMP_USERS WHERE hostname = :host AND user_name LIKE '%maa%'", {'host': hostname})
            conn.commit()
            cursor.close()
            return {'success': True}

        if operation == 'setup':
            # Parse config_content (default empty = no-op)
            lines = config_content.splitlines() if config_content else []
            for line in lines:
                if not line.strip(): continue
                hostIP, udpPort, snmpVer, level, idType, secName = line.split(':')
                # Add v3 user if not exist (sha auth, aes priv, pass "We1come$")
                if snmpVer == '3' and secName not in users:
                    cmd = f"{clitool} -e 'ALTER {srvtype} CREATE SNMPUSER {secName} AUTHPROTOCOL SHA AUTHPASSWORD We1come$ PRIVPROTOCOL AES PRIVPASSWORD We1come$'"
                    ssh.exec_command(cmd)
                    # Update SNMP_USERS
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO maamd.SNMP_USERS (hostname, user_name) VALUES (:host, :user)", {'host': hostname, 'user': secName})
                    conn.commit()
                    cursor.close()
                # Add subscriber if <15 and not exist (respects max 15 per ILOM)
                if len(subscribers) < 15:
                    sub_str = f"{{{hostIP}:{udpPort},version:{snmpVer}}}"
                    if level: sub_str += f",authenticationType:{level}"
                    if idType: sub_str += f",{idType}:{secName}"
                    cmd = f"{clitool} -e 'ALTER {srvtype} CREATE SNMPSUBSCRIBER {sub_str}'"
                    ssh.exec_command(cmd)
                    # Update SNMP_SUBSCRIPTIONS (link to agent port in AGENT_HOME_INFO)
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO maamd.SNMP_SUBSCRIPTIONS (hostname, port, destination) VALUES (:host, :port, :ip)", {'host': hostname, 'port': udpPort, 'ip': hostIP})
                    conn.commit()
                    cursor.close()
            return {'success': True}
        
        return {'success': False, 'message': 'Invalid operation'}
    except Exception as e:
        print(f"SNMP config failed on {hostname}: {str(e)}")
        return {'success': False, 'message': str(e)}
    finally:
        ssh.close()
        conn.close()
