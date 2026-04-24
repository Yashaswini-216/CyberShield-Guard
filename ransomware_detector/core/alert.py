# core/alert.py
import sys
import ctypes
import threading

def show_popup(title, message):
    """Displays a native Windows message box."""
    # Use a thread so it doesn't block the main monitoring loop
    threading.Thread(target=lambda: ctypes.windll.user32.MessageBoxW(0, message, title, 0x10 | 0x1), daemon=True).start()

def notify_user(pid, name, score, reason):
    """
    Alerts the user via console and native popup.
    """
    alert_msg = (
        f"SUSPICIOUS ACTIVITY DETECTED!\n\n"
        f"Process: {name} ({pid})\n"
        f"Threat Score: {score}/100\n"
        f"Reason: {reason}\n\n"
        "Action: Process has been isolated (SUSPENDED) to protect your files."
    )
    
    # Console alert
    print("\n" + "="*50, file=sys.stderr)
    print("[!] ALERT: RANSOMWARE THREAT DETECTED", file=sys.stderr)
    print("="*50, file=sys.stderr)
    print(f"PROCESS: {name} ({pid})", file=sys.stderr)
    print(f"SCORE:   {score}/100", file=sys.stderr)
    print(f"REASON:  {reason}", file=sys.stderr)
    print("="*50 + "\n", file=sys.stderr)

    # Native Popup
    show_popup("Security Alert - Sentinel", alert_msg)

