# utils/whitelist.py
# List of trusted processes to prevent accidental isolation of core system components.

TRUSTED_PROCESSES = [
    "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
    "explorer.exe", "RuntimeBroker.exe", "SearchHost.exe",
    "chrome.exe", "firefox.exe", "msedge.exe", # Browsers
    "python.exe", "cmd.exe", "powershell.exe", # Dev tools
    "code.exe", "node.exe" # VS Code and Node
]

def is_trusted(process_name):
    return process_name in TRUSTED_PROCESSES
