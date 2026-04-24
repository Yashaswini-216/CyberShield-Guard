# core/detector.py
import math
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

    def calculate_entropy(self, data):
        """Calculates the Shannon entropy of a data sample."""
        if not data: return 0
        
        counts = Counter(data)
        entropy = 0
        for count in counts.values():
            p_x = float(count) / len(data)
            entropy -= p_x * math.log(p_x, 2)
        return entropy

    def check_event(self, pid, event_type, data_sample=None):
        """Analyzes a file system event and returns (is_threat, score, reason)."""
        score_inc = 0
        reasons = []

        if event_type == "moved":
            score_inc += 20
            reasons.append("Suspicious renaming/extension change")

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
            return True, current_score, "; ".join(reasons)
        return False, current_score, ""

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
        # In a real system, this would be a value from a loaded ML model
        ai_threat_factor = 0
        if cpu > 30 and io and io.write_bytes > 1000000:
            ai_threat_factor = 10 # AI detects "unusual pattern"
            self.scores[pid] += ai_threat_factor

        current_score = self.scores.get(pid, 0)
        return current_score >= self.threshold, current_score

