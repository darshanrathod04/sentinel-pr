import sqlite3

def filter_by_role(request):
    raw_role = request.args.get("role")
    role_filter = raw_role.strip()
    sql = "SELECT id, username FROM accounts WHERE role = %s"
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(sql, (role_filter,))
