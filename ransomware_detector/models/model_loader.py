# models/model_loader.py
import os
import time

def load_ai_model():
    """
    Simulates loading a pre-trained ML model (.pkl).
    In a real-world scenario, this would use joblib or pickle to load 
    a Random Forest or LSTM model trained on system call sequences.
    """
    print("[*] Initializing AI Anomaly Detection Engine...")
    time.sleep(1.5) # Simulate heavy loading
    
    model_path = os.path.join("models", "model.pkl")
    if not os.path.exists(model_path):
        # Create a dummy model file if it doesn't exist
        with open(model_path, "wb") as f:
            f.write(b"MOCK_AI_MODEL_DATA")
            
    print("[+] Heuristic weights and AI model loaded successfully.")
    return True

def predict_threat(metrics):
    """
    Mock prediction logic. 
    In reality, this would pass features (CPU, I/O, entropy) to the model.
    """
    # Simple logic to simulate AI "finding" something
    cpu = metrics.get('cpu', 0)
    io_write = metrics.get('io_write', 0)
    
    if cpu > 50 and io_write > 5000000:
        return 0.85 # 85% probability of ransomware behavior
    return 0.05
