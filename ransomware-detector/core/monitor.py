# core/monitor.py
import psutil
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils.whitelist import is_trusted

class MonitorHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event, "modified")

    def on_moved(self, event):
        if not event.is_directory:
            # Check if moving to a suspicious extension
            suspicious_exts = ['.crypt', '.locked', '.enc', '.ransom']
            if any(event.dest_path.lower().endswith(ext) for ext in suspicious_exts):
                self._handle(event, "moved", is_suspicious_rename=True)
            else:
                self._handle(event, "moved")

    def _handle(self, event, type, is_suspicious_rename=False):
        data = None
        path = event.dest_path if type == "moved" else event.src_path
        try:
            # Only read if it might be encrypted (not just renamed)
            if type == "modified" or is_suspicious_rename:
                with open(path, 'rb') as f:
                    data = f.read(2048)
        except:
            pass
        self.callback(type, path, data)

class ProcessScanner:
    def get_suspicious_procs(self):
        sus = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'io_counters']):
            try:
                if is_trusted(proc.info['name']): continue
                
                # Check for significant activity
                cpu = proc.info['cpu_percent'] or 0
                io = proc.info['io_counters']
                
                if cpu > 5.0 or (io and io.write_bytes > 500000):
                    sus.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return sus

