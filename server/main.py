from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI(title="Sentinel Security API")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_PATH = os.path.join(os.path.dirname(__file__), "../ransomware-detector/data/log.txt")
STATE_PATH = os.path.join(os.path.dirname(__file__), "../ransomware-detector/data/state.json")

@app.get("/")
async def root():
    return {"message": "Sentinel Security Python API is running"}

@app.get("/api/logs")
async def get_logs():
    """Reads the ransomware detector logs and returns them as a list."""
    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, "r") as f:
                lines = f.readlines()
                # Clean up, reverse to show newest first, and limit to last 50
                log_lines = [line.strip() for line in lines if line.strip()][::-1]
                return log_lines[:50]
        except:
            return []
    return []

@app.get("/api/status")
async def get_status():
    """Returns the current protection status."""
    if os.path.exists(STATE_PATH):
        import json
        try:
            with open(STATE_PATH, "r") as f:
                return json.load(f)
        except:
            pass
    return {
        "status": "Active",
        "monitored_path": "User Home",
        "engine": "Python Heuristic v1.0",
        "threats_blocked": 0,
        "ops_rate": 0,
        "attack_rate": 0
    }

if __name__ == "__main__":
    import uvicorn
    try:
        print("--- Sentinel API Server Starting ---")
        print(f"Log monitor path: {LOG_PATH}")
        uvicorn.run(app, host="127.0.0.1", port=5000, log_level="info")
    except Exception as e:
        print(f"Server failed to start: {e}")
