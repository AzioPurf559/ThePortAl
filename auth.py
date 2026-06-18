import sqlite3
import bcrypt
import getpass

DB_NAME = "users.db"

def init_db():
    """Creates the database and inserts a default user if it doesn't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create the users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash BLOB NOT NULL
        )
    ''')

    
    # Seed a default user if the table is empty
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        password = "password123".encode('utf-8')
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password, salt)
        
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ('admin', hashed))
        conn.commit()
        print("[System] Database initialized. Default user 'admin' created.")
        
    conn.close()

def login():
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    return username, password

def verify_credentials(username, password):
    """Queries the DB and verifies the password against the stored hash."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # 1. Look up the username
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    
    # 2. If user exists, verify the password
    if result:
        stored_hash = result[0]
        # bcrypt handles extracting the salt and comparing the hashes safely
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
    
    return False
