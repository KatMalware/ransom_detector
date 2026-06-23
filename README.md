# RansomGuard — Hybrid Ransomware Detection & Prevention System

A Python-based active defense system that detects ransomware behaviors in real-time using Deep Learning models (byte histograms), Shannon entropy measurement, signature matching, and real-time process monitoring.

---

## 🛡️ Key Features

* **Unified CLI Control Center:** A single menu interface (`ransom_guard.py`) to launch everything.
* **Real-time Download Shield:** Automatically monitors `~/Downloads`, scans incoming files using the AI agent, and automatically **quarantines** malicious threats.
* **Deep Learning Analyzer:** Uses a Multi-Layer Perceptron (MLP) trained on byte frequency histograms to identify encrypted ciphertext with 99%+ accuracy.
* **Real-time System Monitor (Sysmon):** Watches active processes and flags anomalies like high write rates (>5 MB/s) or known ransomware process names.
* **Interactive Sandbox Testing:** Safely simulates ransomware encryption, renames files, and drops mock ransom notes in a sandbox directory with a 1-click restore function.

---

## 📁 Project Structure

```
ransomware_detector/
├── ransom_guard.py        # Unified CLI Entry Point (Main Menu)
├── download_watcher.py    # Real-Time Download Folder Shield
├── config.py              # Configuration & Tunable Thresholds
├── entropy.py             # Shannon entropy calculations
├── magic_bytes.py         # File header/signature verifier
├── dl_analyzer.py         # Keras Model Loader & Predictor
├── train_model.py         # Deep Learning model trainer
├── scanner.py             # CLI On-Demand Scanner & Sysmon
├── system_monitor.py      # System calls & process rate inspector
├── test_ransom_sim.py     # Safe sandbox simulation & restore
├── ransom_model.keras     # Pre-trained Deep Learning Model
└── .gitignore             # Git ignore file
```

---

## ⚙️ Installation & Setup

1. **Navigate to the directory:**
   ```bash
   cd ransomware_detector
   ```

2. **Activate the virtual environment & install dependencies:**
   ```bash
   source venv/bin/activate
   pip install watchdog psutil rich tensorflow numpy
   ```

---

## 🚀 How to Run (Single Command)

Start the interactive control center console:
```bash
python ransom_guard.py
```

### Direct CLI Commands:
* **Scan any file/folder:** `python ransom_guard.py scan <path>`
* **Monitor system processes:** `python ransom_guard.py sysmon`
* **Run Download Shield directly:** `python ransom_guard.py shield`
* **Run Attack Sandbox Simulator:** `python ransom_guard.py attack`

---

## 🧪 Testing the Detector (Sandbox Workflow)

1. Run the Control Center: `python ransom_guard.py`.
2. Choose **Option 4** (Sandbox Testing Suite).
3. Select **Setup Sandbox** to generate 10 clean mock files.
4. Scan the sandbox folder using **Option 2** (Scan folder). It will show **SAFE ✅**.
5. Select **Attack Sandbox** to simulate ransomware.
6. Scan again. The AI agent will detect and flag the threats as **CRITICAL 🚨**.
7. Select **Restore Sandbox** to recover all original mock files.
