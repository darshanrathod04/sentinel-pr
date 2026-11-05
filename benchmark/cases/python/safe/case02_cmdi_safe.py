import subprocess

def backup_directory_safe(target_path):
    subprocess.run(["tar", "-czf", "/backup/data.tar.gz", target_path], shell=False)
