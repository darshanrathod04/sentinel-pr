import os

def backup_directory(target_path):
    cmd = "tar -czf /backup/data.tar.gz " + target_path
    os.system(cmd)
