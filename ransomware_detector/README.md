# 🛡️ Sentinel: Ransomware Detection System

## 🔹 1. Project Overview
Sentinel is a robust, modular Ransomware Detection System designed to protect critical file systems from malicious encryption. It employs behavioral analysis and heuristic scoring to identify, isolate, and neutralize threats in real-time.

**Key Capabilities:**
*   🔍 **Monitors System Activity**: Tracks file modifications and process metrics.
*   🧠 **Detects Suspicious Behavior**: Identifies high-entropy writes and rapid renaming.
*   🚫 **Isolates Malicious Processes**: Instantly suspends suspicious PIDs.
*   ⚠️ **Alerts User**: High-visibility console and system notifications.
*   🔒 **Stores Logs Securely**: Detailed activity audit trails.

---

## 🔹 2. Project Structure
```text
ransomware-detector/
│
├── main.py                # Runs the whole system coordinator
│
├── core/
│   ├── monitor.py        # File + Process monitoring workers
│   ├── detector.py       # Heuristic brain & Anomaly Detection
│   ├── isolate.py        # Process suspension & termination
│   ├── alert.py          # Real-time alert system
│   └── logger.py         # Secure logging module (Blockchain ready)
│
├── data/
│   └── log.txt           # Secure audit trail
│
├── models/               # AI/ML Model Storage
│   └── model.pkl
│
├── utils/
│   └── whitelist.py      # List of trusted system processes
│
└── requirements.txt      # Project dependencies
```

---

## 🔹 3. Techniques Utilized
*   **Behavioral Analysis**: Monitoring process interaction with the file system.
*   **Anomaly Detection**: Identifying deviations from baseline system metrics.
*   **Shannon Entropy Calculation**: Detecting encrypted data streams.
*   **Real-time Process Isolation**: Zero-trust approach to unverified processes.

---

## 🔹 4. System Flow
`Input` → `Monitor` → `Detect` → `Status Check`
1.  **If Normal**: Continue monitoring.
2.  **If Suspicious**: `Isolate` → `Alert User` → `Log Event`.

---

## 🔹 5. Final Viva Explanation (Script)
> "Our system, **Sentinel**, continuously monitors file and process activity using specialized Python libraries like `watchdog` and `psutil`. It employs **Behavioral Analysis** to detect patterns characteristic of ransomware, such as high-velocity file renaming and high-entropy data writes. When suspicious activity is flagged, the system immediately **Isolates** the process to prevent further encryption, alerts the user via an integrated notification system, and securely logs the event for forensic analysis. This zero-trust architecture ensures that even zero-day ransomware threats are neutralized before they can cause significant damage."
