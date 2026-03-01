import sqlite3
import hashlib

# 1. Initialize the Database (Run this once)
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Create table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# 2. Add a New User (Registration)
try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  (username, hashed_pw, role))
        conn.commit() # <--- THIS IS THE MISSING LINE
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()
    return True
    except sqlite3.IntegrityError:
        success = False # Username already exists
        
    conn.close()
    return success

# 3. Check Login Credentials
def check_login(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    
    c.execute('SELECT role FROM users WHERE username = ? AND password = ?', (username, hashed_pw))
    data = c.fetchone()
    
    conn.close()
    return data[0] if data else None
import sqlite3
import pandas as pd

# ... (Keep all your existing login/register code above this) ...

def setup_dummy_db():
    """Creates a fake database for the WAF sandbox testing."""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Create a dummy students table
    c.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            name TEXT,
            major TEXT,
            gpa REAL
        )
    ''')
    
    # Check if it's empty, if so, add fake data
    c.execute("SELECT COUNT(*) FROM students")
    if c.fetchone()[0] == 0:
        fake_data = [
            (1, 'Alice Smith', 'Computer Science', 3.8),
            (2, 'Bob Jones', 'Information Technology', 3.2),
            (3, 'Charlie Brown', 'Cybersecurity', 3.9),
            (4, 'Diana Prince', 'Data Science', 4.0)
        ]
        c.executemany('INSERT INTO students VALUES (?,?,?,?)', fake_data)
        conn.commit()
    conn.close()

def execute_safe_query(query):
    """Executes a query ONLY if the scanner marks it as safe."""
    try:
        conn = sqlite3.connect('users.db')
        # We use pandas to easily grab the result and format it for Streamlit
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df, None
    except Exception as e:
        return None, str(e)

# Run initialization immediately when imported
init_db()
