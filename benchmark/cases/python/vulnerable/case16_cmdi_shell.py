import subprocess

def run_diagnostics(target_host):
    subprocess.run(f"ping -c 1 {target_host}", shell=True)
