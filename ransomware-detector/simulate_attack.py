import os
import time
import random
import string

def create_test_files():
    os.makedirs("test_vault", exist_ok=True)
    for i in range(10):
        with open(f"test_vault/doc_{i}.txt", "w") as f:
            f.write("Normal document content " * 100)
    
    # Create Honeypots
    with open("test_vault/.shadow_vault", "w") as f:
        f.write("CRITICAL BACKUP DATA")
    print("[*] Test files and honeypots created.")

def simulate_activity():
    print("[*] Simulating normal activity...")
    for _ in range(5):
        with open(f"test_vault/doc_{random.randint(0,9)}.txt", "a") as f:
            f.write(" more data")
        time.sleep(0.5)

def simulate_attack():
    print("[!!!] TRIGGERING PROACTIVE ATTACK SIMULATION...")
    
    # 1. Access Honeypot
    print("[!] Accessing Honeypot...")
    with open("test_vault/.shadow_vault", "r") as f:
        _ = f.read()
    
    time.sleep(1)
    
    # 2. Rapid Renaming to .crypt
    print("[!] Rapidly renaming files to .crypt...")
    for i in range(5):
        old = f"test_vault/doc_{i}.txt"
        new = f"test_vault/doc_{i}.crypt"
        if os.path.exists(old):
            os.rename(old, new)
        time.sleep(0.2)

if __name__ == "__main__":
    create_test_files()
    simulate_activity()
    simulate_attack()
    print("[*] Simulation complete.")
