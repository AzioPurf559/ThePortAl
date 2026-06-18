import sqlite3
import re

DB_NAME_LOGS = "logs.db"

def build_database(file_path):
    conn = sqlite3.connect(DB_NAME_LOGS)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            pid INTEGER,
            process_name TEXT,
            memory_kb INTEGER,
            risk_level TEXT,
            risk_score INTEGER,
            source_ip TEXT,
            source_port INTEGER,
            destination_ip TEXT,
            destination_port INTEGER,
            known_status TEXT
        )
    """)

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:

            # Split main fields
            parts = [p.strip() for p in line.split("|")]

            if len(parts) < 6:
                continue

            try:
                # ---- TIME ----
                timestamp = parts[0].replace("Time:", "").strip()

                # ---- PID ----
                pid = int(parts[1].replace("PID:", "").strip())

                # ---- PROCESS ----
                process_name = parts[2].strip()

                # ---- MEMORY ----
                memory_kb = int(parts[3].replace("Memory:", "").replace("KB", "").strip())

                # ---- RISK ----
                risk_part = parts[4].replace("Risk:", "").strip()

                # Example: "HIGH (7)"
                match = re.match(r"(\w+)\s*\((\d+)\)", risk_part)
                if match:
                    risk_level = match.group(1)
                    risk_score = int(match.group(2))
                else:
                    risk_level = "UNKNOWN"
                    risk_score = 0

                # ---- SOURCE ----
                source_raw = parts[5].replace("Source:", "").strip()
                source_ip, source_port = source_raw.split(":")

                # ---- DEST ----
                dest_raw = parts[6].replace("Destination:", "").strip()
                dest_ip, dest_port = dest_raw.split(":")

                cursor.execute("""
                    INSERT INTO logs (
                        timestamp, pid, process_name, memory_kb,
                        risk_level, risk_score,
                        source_ip, source_port,
                        destination_ip, destination_port
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp,
                    pid,
                    process_name,
                    memory_kb,
                    risk_level,
                    risk_score,
                    source_ip,
                    int(source_port),
                    dest_ip,
                    int(dest_port)
                ))

        

            except Exception as e:
                print("Skipping bad line:", e)
                continue

    conn.commit()
    conn.close()

def reset_database():
    conn = sqlite3.connect(DB_NAME_LOGS)
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS logs")
    conn.commit()
    conn.close()

def mark_processes(category, process_names):
    conn = sqlite3.connect(DB_NAME_LOGS)
    cursor = conn.cursor()

    for name in process_names:
        cursor.execute("""
            UPDATE logs
            SET known_status = ?
            WHERE process_name = ?
        """, (category, name))

    conn.commit()
    conn.close()