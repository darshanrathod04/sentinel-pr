import sqlite3

def search_catalog(request):
    category = request.args.get("cat")
    sort_order = request.args.get("sort")
    # Vulnerable: Multi-part nested binary concatenation in SQL
    query = ("SELECT id, name, price FROM products WHERE category = '" + category + "' ORDER BY " + sort_order)
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
