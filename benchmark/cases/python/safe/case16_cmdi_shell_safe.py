import subprocess

def run_diagnostics(target_host):
    subprocess.run(["ping", "-c", "1", target_host], shell=False)
