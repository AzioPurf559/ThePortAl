import sqlite3

def view_logs():
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM logs")
    rows = cursor.fetchall()

    for row in rows:
        print(row)

    conn.close()

def mark_processes(category, processes):
    if not processes:
        return  # avoid invalid SQL

    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()

    placeholders = ",".join(["?"] * len(processes))

    sql = f"""
        UPDATE logs
        SET known_status = ?
        WHERE process_name IN ({placeholders})
    """

    cursor.execute(sql, [category] + processes)
    conn.commit()
    conn.close()

def filter_by_sport(input_sport):
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM logs WHERE SOURCE_PORT = ?",
        (input_sport,)
    )

    rows = cursor.fetchall()

    if not rows:
        print("No results found for SOURCE_PORT:", input_sport)
    else:
        for row in rows:
            print(row)

    conn.close()

def filter_by_process(input_process):
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM logs WHERE process_name = ?",
        (input_process,)
    )

    rows = cursor.fetchall()

    if not rows:
        print("No results found for process name:", input_process)
    else:
        for row in rows:
            print(row)

    conn.close()