# main.py
import threading
import queue
import time
import os
import sys
import ctypes
from core.monitor import MonitorHandler, ProcessScanner, Observer
from core.detector import BehavioralDetector
from core.isolate import suspend_process
from core.alert import notify_user
from core.logger import log_event
from models.model_loader import load_ai_model

# Configuration
MONITOR_PATH = os.getcwd() 
COMM_QUEUE = queue.Queue()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def fs_worker(path):
    def callback(etype, pth, data):
        COMM_QUEUE.put(('fs', {'type': etype, 'path': pth, 'data': data}))
    
    handler = MonitorHandler(callback)
    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()
    try:
        while True: time.sleep(1)
    except: observer.stop()
    observer.join()

def proc_worker():
    scanner = ProcessScanner()
    while True:
        procs = scanner.get_suspicious_procs()
        for p in procs:
            COMM_QUEUE.put(('proc', p))
        time.sleep(1.5)

def print_dashboard():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""
    ========================================================
    [ SENTINEL: ADVANCED RANSOMWARE DETECTION SYSTEM ]
    ========================================================
    [*] Status:        ACTIVE
    [*] Monitoring:    {path}
    [*] Engine:        Heuristic + AI Anomaly Detection
    [*] Log File:      data/log.txt
    ========================================================
    [LIVE FEED]
    """.format(path=MONITOR_PATH))


def main():
    if not is_admin():
        print("[!] WARNING: Not running as Administrator. Isolation features may fail.")
        time.sleep(2)

    # Initialize AI Model Mock
    load_ai_model()
    
    detector = BehavioralDetector()
    print_dashboard()
    
    # Threads
    threads = [
        threading.Thread(target=fs_worker, args=(MONITOR_PATH,), daemon=True),
        threading.Thread(target=proc_worker, daemon=True)
    ]
    for t in threads: t.start()

    try:
        while True:
            try:
                msg_type, data = COMM_QUEUE.get(timeout=0.5)
                
                if msg_type == 'proc':
                    pid, name = data['pid'], data['name']
                    # Process metrics evaluation
                    is_threat, score = detector.evaluate_metrics(pid, data['cpu_percent'], data['io_counters'])
                    
                    if is_threat:
                        notify_user(pid, name, score, "Abnormal resource usage pattern detected by AI/Heuristics")
                        suspend_process(pid)
                        print(f"[{time.strftime('%H:%M:%S')}] [!!!] THREAT NEUTRALIZED: {name} (PID: {pid})")

                elif msg_type == 'fs':
                    # Heuristic event check (entropy, renaming)
                    is_threat, score, reason = detector.check_event(None, data['type'], data['data'])
                    
                    if is_threat:
                        # Since we don't have the PID for FS events directly, we log and alert the user
                        # In a real system, we'd correlate this with the most active process found in proc_worker
                        log_event("UNKNOWN", data['path'], "SUSPICIOUS-FS", reason)
                        print(f"[{time.strftime('%H:%M:%S')}] [!] Suspicious file activity: {os.path.basename(data['path'])}")

            except queue.Empty: continue
    except KeyboardInterrupt:
        print("\n[!] Sentinel shutting down. Stay safe!")

if __name__ == "__main__":
    main()

