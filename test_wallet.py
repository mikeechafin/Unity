import oracledb

oracledb.init_oracle_client(
    lib_dir="/usr/lib/oracle/21/client64/lib",
    config_dir="/u01/app/oracle/product/21.0.0/dbhome_1/network/admin"
)

try:
    conn = oracledb.connect(user="maamd", password="", dsn="MAAPDB_DEVEL")
    print("SUCCESS! Connected. DB Version:", conn.version)
    conn.close()
except oracledb.Error as e:
    print("ERROR:", e)
