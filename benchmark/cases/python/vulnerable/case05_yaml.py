import yaml

def parse_server_manifest(config_yaml):
    manifest = yaml.load(config_yaml)
    return manifest
