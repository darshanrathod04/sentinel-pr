import sqlite3

ALLOWED_SORTS = {"price_asc": "price ASC", "price_desc": "price DESC"}

def search_catalog_safe(request):
    category = request.args.get("cat")
    sort_key = request.args.get("sort")
    sort_clause = ALLOWED_SORTS.get(sort_key, "id ASC")
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    # Safe: parameter binding with strict allowlist
    cursor.execute("SELECT id, name, price FROM products WHERE category = %s ORDER BY id ASC", (category,))
    return cursor.fetchall()
