import hashlib

def compute_content_fingerprint_safe(data_bytes):
    digest = hashlib.sha256(data_bytes).hexdigest()
    return digest
