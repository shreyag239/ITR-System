import sqlite3
import os

def add_referral_column():
    """Add referral_code column to clients table if it doesn't exist"""
    # Check if database exists
    if not os.path.exists('database.db'):
        print("Database doesn't exist. Please run the app first to create it.")
        return
    
    # Connect to database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Check if referral_code column exists
    cursor.execute("PRAGMA table_info(clients)")
    columns = cursor.fetchall()
    column_names = [column[1] for column in columns]
    
    if 'referral_code' not in column_names:
        print("Adding referral_code column to clients table...")
        try:
            cursor.execute("ALTER TABLE clients ADD COLUMN referral_code TEXT UNIQUE")
            conn.commit()
            print("Column added successfully.")
        except sqlite3.Error as e:
            print(f"Error adding column: {e}")
    else:
        print("referral_code column already exists.")
    
    conn.close()

if __name__ == "__main__":
    add_referral_column()
