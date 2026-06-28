import oracledb

oracledb.init_oracle_client(
    lib_dir="/opt/oracle/product/26ai/dbhome_1/lib",
    config_dir="/opt/oracle/wallet_store/network"
)

print("Testing full wallet auth (standalone connect - works with your setup)")
try:
    conn = oracledb.connect(dsn="MAAMD")  # Wallet provides user + password
    print("Standalone connect SUCCESS")
    with conn.cursor() as cursor:
        cursor.execute("SELECT SYSDATE FROM DUAL")
        print("Query test: SYSDATE =", cursor.fetchone()[0])
    conn.close()
except Exception as e:
    print("Standalone connect ERROR:", e)

print("\nTesting multiple standalone connects (simulate 'pool' behavior)")
connects = []
for i in range(3):
    try:
        conn = oracledb.connect(dsn="MAAMD")
        print(f"Connect {i+1} SUCCESS")
        with conn.cursor() as cursor:
            cursor.execute("SELECT SYS_CONTEXT('USERENV', 'SESSION_USER') FROM DUAL")
            print(f"Connect {i+1} user: {cursor.fetchone()[0]}")
        connects.append(conn)
    except Exception as e:
        print(f"Connect {i+1} ERROR:", e)

# Close all
for conn in connects:
    conn.close()
print("All standalone connects closed")
