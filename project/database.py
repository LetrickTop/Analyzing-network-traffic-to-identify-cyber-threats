import sqlite3

DB_PATH = "traffic.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            bytes INTEGER,
            service TEXT,
            flag TEXT,
            count INTEGER,
            srv_count INTEGER,
            dst_host_count INTEGER,
            dst_host_srv_count INTEGER
        )
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("База данных обновлена.")