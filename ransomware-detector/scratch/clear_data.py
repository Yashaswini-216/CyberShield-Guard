import os
import json

data_dir = r"c:\Users\komal\OneDrive\Documents\Hackathon\ransomware-detector\data"
log_path = os.path.join(data_dir, "log.txt")
state_path = os.path.join(data_dir, "state.json")

# Ensure dir exists
os.makedirs(data_dir, exist_ok=True)

# Clear log.txt (empty file)
with open(log_path, "w", encoding="utf-8") as f:
    f.write("")

# Initialize state.json
default_state = {
    "status": "Active",
    "monitored_path": "--",
    "ops_rate": 0,
    "attack_rate": 0,
    "threats_blocked": 0,
    "last_update": 0
}
with open(state_path, "w", encoding="utf-8") as f:
    json.dump(default_state, f)

print("Data files cleared and initialized successfully.")
