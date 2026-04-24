# core/detector.py
import math
import time
import os
from collections import Counter

class BehavioralDetector:
    """
    Core detection logic utilizing Heuristic and Behavioral Analysis.
    
    Techniques:
    - Anomaly Detection: Measuring deviance from normal CPU/IO patterns.
    - Heuristics: Shannon Entropy scanning for encryption signatures.
    - AI Mockup: Integrated scoring for potential ransomware behavior.
    """

    def __init__(self):
        self.scores = {}  # PID-based scores
        self.threshold = 75
        self.ops_count = 0
        self.start_time = time.time()
        self.honeypots = [".shadow_vault", "$RECYCLE.BIN_DATA", "backup_config.cfg"]

    def calculate_entropy(self, data):
        """Calculates the Shannon entropy of a data sample."""
        if not data: return 0
        
        counts = Counter(data)
        entropy = 0
        for count in counts.values():
            p_x = float(count) / len(data)
            entropy -= p_x * math.log(p_x, 2)
        return entropy

    def check_event(self, pid, event_type, path, data_sample=None):
        """Analyzes a file system event and returns (is_threat, score, reason)."""
        score_inc = 0
        reasons = []
        self.ops_count += 1

        # PROACTIVE: Honeypot Detection
        filename = os.path.basename(path)
        if any(hp in filename for hp in self.honeypots):
            score_inc += 100
            reasons.append(f"CRITICAL: Honeypot file accessed/modified: {filename}")

        # PROACTIVE: Rapid Extension Change
        if event_type == "moved":
            old_ext = os.path.splitext(path)[0]
            new_ext = os.path.splitext(path)[1]
            suspicious_exts = [".crypt", ".locked", ".encrypted", ".wannacry"]
            if new_ext.lower() in suspicious_exts:
                score_inc += 60
                reasons.append(f"Proactive: File renamed to ransomware extension: {new_ext}")
            else:
                score_inc += 20
                reasons.append("Suspicious renaming activity")

        if data_sample:
            ent = self.calculate_entropy(data_sample)
            if ent > 7.5:
                score_inc += 50
                reasons.append(f"High-entropy encryption signature detected ({ent:.2f})")

        # Update score for the given PID (or global if PID is None)
        target = pid if pid else "GLOBAL"
        self.scores[target] = self.scores.get(target, 0) + score_inc
        
        current_score = self.scores[target]
        if current_score >= self.threshold:
            self.scores[target] = self.threshold + 10 # Cap the score
            return True, self.scores[target], "; ".join(reasons)
        return False, current_score, ""

    def reset_score(self, pid):
        """Resets the score for a given PID."""
        if pid in self.scores:
            del self.scores[pid]

    def evaluate_metrics(self, pid, cpu, io):
        """Evaluates process metrics (CPU/IO) for anomalies."""
        score_inc = 0
        
        # High CPU usage often accompanies encryption
        if cpu > 40:
            score_inc += 15
        
        # Ransomware typically has a high write-to-read ratio
        if io and io.write_bytes > (io.read_bytes * 5):
            score_inc += 25
            
        self.scores[pid] = self.scores.get(pid, 0) + score_inc
        
        # Mock AI factor (simulating advanced anomaly detection)
        ai_threat_factor = 0
        if cpu > 30 and io and io.write_bytes > 1000000:
            ai_threat_factor = 15 # AI detects "unusual pattern"
            self.scores[pid] += ai_threat_factor

        current_score = self.scores.get(pid, 0)
        if current_score >= self.threshold:
            self.scores[pid] = self.threshold + 10 # Cap the score
            return True, self.scores[pid]
        return False, current_score

    def get_ops_per_sec(self):
        elapsed = time.time() - self.start_time
        if elapsed < 1: return self.ops_count
        rate = self.ops_count / elapsed
        # Reset for next interval
        self.ops_count = 0
        self.start_time = time.time()
        return round(rate, 2)

