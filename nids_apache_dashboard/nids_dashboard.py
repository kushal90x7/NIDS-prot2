import sqlite3
import time
import random

def init_db():
    conn = sqlite3.connect('nids.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        dest_ip TEXT,
        alert_type TEXT
    )''')
    conn.commit()
    conn.close()

def insert_alert(source_ip, dest_ip, alert_type):
    conn = sqlite3.connect('nids.db')
    c = conn.cursor()
    c.execute("INSERT INTO alerts (timestamp, source_ip, dest_ip, alert_type) VALUES (datetime('now'), ?, ?, ?)",
              (source_ip, dest_ip, alert_type))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    while True:
        insert_alert(f"192.168.1.{random.randint(2,254)}", "10.0.0.1", random.choice(["SQL Injection", "XSS", "Port Scan"]))
        print("Inserted dummy alert")
        time.sleep(5)
