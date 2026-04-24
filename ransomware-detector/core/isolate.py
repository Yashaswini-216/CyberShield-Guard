# core/isolate.py
import psutil
from core.logger import log_event

def suspend_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.suspend()
        log_event(pid, proc.name(), "SUSPEND", "High threat score from heuristic analyzer")
        return True
    except Exception as e:
        return False

def terminate_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        log_event(pid, proc.name(), "TERMINATE", "Confirmed threat by user or policy")
        return True
    except Exception as e:
        return False
