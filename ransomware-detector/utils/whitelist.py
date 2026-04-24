# utils/whitelist.py
# List of trusted processes to prevent accidental isolation of core system components.

TRUSTED_PROCESSES = [
    "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
    "explorer.exe", "RuntimeBroker.exe", "SearchHost.exe",
    "chrome.exe", "firefox.exe", "msedge.exe", # Browsers
    "python.exe", "cmd.exe", "powershell.exe", "git.exe", # Dev tools
    "code.exe", "node.exe", "npm.exe", "yarn.exe",
    "Antigravity.exe", "antigravity.exe", "Antigravity", # AI Assistant
    "OneDrive.exe", "System Idle Process", "Memory Compression",
    "RtkAudUService64.exe", "RtkAudioService.exe", "RAVBg64.exe", # Realtek
    "NVDisplay.Container.exe", "nvspcaps64.exe", # NVIDIA
    "igfxCUIService.exe", "conhost.exe", "taskhostw.exe"
]

def is_trusted(process_name):
    if not process_name: return False
    name_lower = process_name.lower()
    # Direct match or substring match for safety
    for trusted in TRUSTED_PROCESSES:
        t_lower = trusted.lower()
        if t_lower == name_lower or t_lower in name_lower:
            return True
    return False
