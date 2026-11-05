import hashlib

def compute_content_fingerprint(data_bytes):
    digest = hashlib.md5(data_bytes).hexdigest()
    return digest
