import sqlite3

def query_user_record_safe(db, user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor = db.cursor()
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
