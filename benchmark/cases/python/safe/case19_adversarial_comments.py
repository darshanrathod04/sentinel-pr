# Adversarial comment testing:
# os.system("rm -rf /")
# cursor.execute(f"DROP TABLE users WHERE id = {user_id}")
# eval(untrusted_code)

def compute_hash_sum(data: str) -> str:
    """
    Documentation mentions:
    Do not use pickle.loads(data) in production.
    """
    header = "This is not SQL: SELECT * FROM items WHERE 1=1"
    return f"{header}: {len(data)}"
