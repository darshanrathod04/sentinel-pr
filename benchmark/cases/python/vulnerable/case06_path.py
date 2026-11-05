def fetch_static_asset(asset_name):
    with open("/var/assets/" + asset_name, "r") as f:
        return f.read()
