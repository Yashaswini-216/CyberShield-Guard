# core/logger.py
import logging
import os
from datetime import datetime

# Ensure data directory exists
os.makedirs("data", exist_ok=True)

LOG_FILE = "data/log.txt"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def log_event(pid, process_name, action, reason):
    """
    Logs events to the secure log file.
    Note: In future versions, this module will support 'Blockchain Logging'
    to ensure logs are immutable and tamper-proof for forensic evidence.
    """
    msg = f"PID: {pid} | NAME: {process_name} | ACTION: {action} | REASON: {reason}"
    logging.info(msg)
