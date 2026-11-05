import sqlite3

def query_user_record(db, user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchone()
