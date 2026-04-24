import os
import time
import random
import string

# This script simulates ransomware-like activity to test the detector.
# It creates a 'test_vault' folder and starts 'encrypting' (renaming) files.

TEST_DIR = os.path.join(os.getcwd(), "test_vault")

def generate_random_data(size=1024):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def simulate_activity():
    if not os.path.exists(TEST_DIR):
        os.makedirs(TEST_DIR)
        print(f"[*] Created {TEST_DIR}")

    print("[*] Generating dummy files...")
    for i in range(10):
        with open(os.path.join(TEST_DIR, f"file_{i}.txt"), "wb") as f:
            f.write(generate_random_data())
    
    print("[!] STARTING SIMULATED ENCRYPTION IN 3 SECONDS...")
    time.sleep(3)

    for i in range(10):
        old_path = os.path.join(TEST_DIR, f"file_{i}.txt")
        new_path = os.path.join(TEST_DIR, f"file_{i}.locked")
        
        # High-entropy write (random bytes) + Rename
        with open(old_path, "wb") as f:
            f.write(generate_random_data(2048)) # Writing "encrypted" data
        
        os.rename(old_path, new_path)
        print(f"[!] Encrypted: {new_path}")
        time.sleep(0.5)

if __name__ == "__main__":
    simulate_activity()
