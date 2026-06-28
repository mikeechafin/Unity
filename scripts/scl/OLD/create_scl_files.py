#!/usr/bin/env python3
import os

SCL_DIR = "/home/maatest/mchafin/MAA_APPS_NEW/scripts/scl"
os.makedirs(SCL_DIR, exist_ok=True)

files = {
    "reset_ms_snmp.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py - Storage Server version
alter cell snmpSubscriber=""
""",
    "reset_ms_snmp_db.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py - Database Server version
alter dbserver snmpSubscriber=""
""",
    "get_snmp.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
list cell attributes snmpsubscriber
""",
    "get_snmp_db.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
list dbserver attributes snmpsubscriber
""",
    "restart_cell_services.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
alter cell restart services all
""",
    "restart_cell_services_db.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
alter dbserver restart services all
""",
    "setup_test_asrm.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
alter cell snmpsubscriber +=((host='phoenix235943.dev3sub3phx.databasede3phx.oraclevcn.com',port=162,community=public,type=ASR,asrmPort=16161))
""",
    "setup_test_asrm_db.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
alter dbserver snmpsubscriber +=((host='phoenix235943.dev3sub3phx.databasede3phx.oraclevcn.com',port=162,community=public,type=ASR,asrmPort=16161))
""",
    "set_smtp.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
alter cell smtpServer='smtp.us.oracle.com', smtpFromAddr='maa@oracle.com', smtpFrom='MAA', smtpToAddr='maa@oracle.com', smtpUseSSL=FALSE
""",
    "set_smtp_db.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
alter dbserver smtpServer='smtp.us.oracle.com', smtpFromAddr='maa@oracle.com', smtpFrom='MAA', smtpToAddr='maa@oracle.com', smtpUseSSL=FALSE
""",
    "set_v3user.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
alter cell snmpUser.maaem=(authprotocol=SHA,authpassword=welcome1,privprotocol=AES,privpassword=welcome1)
""",
    "set_v3user_db.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
alter dbserver snmpUser.maaem=(authprotocol=SHA,authpassword=welcome1,privprotocol=AES,privpassword=welcome1)
""",
    "change_celladministrator_password.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
alter user celladministrator password='PASSWORD'
""",
    "remove_software_update.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
alter cell softwareUpdate time=''
""",
    "set_ms_configuration.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py - full multi-line bash script
bash -c 'file="/opt/oracle/cell/cellsrv/deploy/config/cellinit.ora";
changed=0;
grep -q "_trim_ilom_snmp_list=true" "$file" || { echo "_trim_ilom_snmp_list=true" >> "$file"; changed=1; };
grep -q "_cell_send_emails_and_asr_for_simulated_errors=true" "$file" || { echo "_cell_send_emails_and_asr_for_simulated_errors=true" >> "$file"; changed=1; };
grep -q "_cell_allow_reenable_predfail=true" "$file" || { echo "_cell_allow_reenable_predfail=true" >> "$file"; changed=1; };
if [ $changed -eq 1 ]; then
  cellcli -e "alter cell restart services all";
else
  echo "No changes needed - configuration already set";
fi'
""",
    "set_ms_configuration_db.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py - full multi-line bash script
bash -c 'file="/opt/oracle/dbserver/dbms/deploy/config/cellinit.ora";
changed=0;
grep -q "_trim_ilom_snmp_list=true" "$file" || { echo "_trim_ilom_snmp_list=true" >> "$file"; changed=1; };
grep -q "_cell_send_emails_and_asr_for_simulated_errors=true" "$file" || { echo "_cell_send_emails_and_asr_for_simulated_errors=true" >> "$file"; changed=1; };
grep -q "_cell_allow_reenable_predfail=TRUE" "$file" || { echo "_cell_allow_reenable_predfail=TRUE" >> "$file"; changed=1; };
if [ $changed -eq 1 ]; then
  dbmcli -e "alter dbserver restart services all";
else
  echo "No changes needed - configuration already set";
fi'
""",
    "create_celladministrator.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
create role administrator
grant privilege all actions on all objects all attributes with all options to role administrator
create user celladministrator password='TestPass1'
grant role administrator to user celladministrator
""",
    "imageinfo.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
imageinfo
""",
    "reset_dbsnmp.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py - full multi-line bash script
#!/bin/bash
PASS="We1come$"
echo "Starting DBSNMP password reset..."
updated=0
for pid in $(ps -ef | grep -v grep | grep [o]ra_pmon_ | awk '{print $2}'); do
  cmd=$(ps -o command -p $pid | tail -1)
  if [[ $cmd == *ora_pmon_* && ! $cmd == *+ASM* ]]; then
    sid=${cmd##*ora_pmon_}
    home=$(tr '\0' '\n' < /proc/$pid/environ | grep ^ORACLE_HOME= | cut -d= -f2)
    if [ -n "$home" ] && [ -d "$home" ] && [ -x "$home/bin/sqlplus" ]; then
      echo "Updating dbsnmp password for database $sid, ORACLE_HOME=$home"
      su - oracle -c "export ORACLE_SID=$sid; export ORACLE_HOME=$home; export PATH=$home/bin:$PATH; sqlplus / as sysdba <<EOF
alter user dbsnmp identified by $PASS;
alter user dbsnmp account unlock;
EOF"
      if [ $? -eq 0 ]; then
        updated=1
      else
        echo "Failed to update $sid in $home"
      fi
    else
      echo "Skipping invalid home for $sid: $home"
    fi
  fi
done
if [ $updated -eq 0 ]; then
  echo "No running databases found to update."
else
  echo "DBSNMP password reset complete."
fi
""",
    "reset_asmsnmp_password.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py - full multi-line bash script
#!/bin/bash
PASS="We1come$"
echo "Starting ASMSNMP password reset..."
updated=0
for pid in $(ps -ef | grep -v grep | grep [a]sm_pmon_ | awk '{print $2}'); do
  cmd=$(ps -o command -p $pid | tail -1)
  if [[ $cmd == *asm_pmon_* ]]; then
    sid=${cmd##*asm_pmon_}
    home=$(tr '\0' '\n' < /proc/$pid/environ | grep ^ORACLE_HOME= | cut -d= -f2)
    if [ -n "$home" ] && [ -d "$home" ] && [ -x "$home/bin/sqlplus" ]; then
      echo "Updating asmsnmp password for ASM instance $sid, ORACLE_HOME=$home"
      su - oracle -c "export ORACLE_SID=$sid; export ORACLE_HOME=$home; export PATH=$home/bin:$PATH; sqlplus / as sysasm <<EOF
alter user asmsnmp identified by $PASS account unlock;
EOF"
      if [ $? -eq 0 ]; then
        updated=1
      else
        echo "Failed to update $sid in $home"
      fi
    else
      echo "Skipping invalid home for $sid: $home"
    fi
  fi
done
if [ $updated -eq 0 ]; then
  echo "No running ASM instances found to update."
else
  echo "ASMSNMP password reset complete."
fi
""",
    "check_exascale.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
dbmcli -e "list escluster" 2>&1
""",
    "check_storage_type.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
ip a
""",
    "check_virtual.scl": """# Version: 2026-03-23 v1.00
# Changes: Migrated from legacy environment_setup_functions.py
[ -d /EXAVMIMAGES ] && echo "hypervisor" || echo "not a hypervisor"
"""
}

for filename, content in files.items():
    path = os.path.join(SCL_DIR, filename)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    print(f"Created: {path}")

print("\n=== ALL SCL FILES CREATED SUCCESSFULLY ===")
print(f"Location: {SCL_DIR}")
print("Restart the app with: systemctl restart maa_unified_app.service")
