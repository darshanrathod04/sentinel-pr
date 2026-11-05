import os

def fetch_static_asset_safe(asset_name):
    base_dir = "/var/assets"
    target = os.path.realpath(os.path.join(base_dir, asset_name))
    if not target.startswith(base_dir):
        raise ValueError("Directory traversal attempt")
    with open(target, "r") as f:
        return f.read()
