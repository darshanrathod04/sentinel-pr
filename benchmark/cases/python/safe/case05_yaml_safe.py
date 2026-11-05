import yaml

def parse_server_manifest_safe(config_yaml):
    manifest = yaml.safe_load(config_yaml)
    return manifest
