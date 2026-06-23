"""
Ransomware Detection System — Configuration
All tunable parameters in one place.
"""

import os

# ─── Paths ────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
HONEYPOT_DIR    = os.path.join(BASE_DIR, "honeypot")
LOG_DIR         = os.path.join(BASE_DIR, "logs")
ALERT_LOG_FILE  = os.path.join(LOG_DIR, "alerts.log")
BACKUP_DIR      = os.path.join(BASE_DIR, ".honeypot_backup")

# ─── Detection Thresholds ─────────────────────────────
# If more than this many files are modified within RATE_WINDOW seconds → alert
RATE_THRESHOLD          = 5
RATE_WINDOW_SECONDS     = 3.0

# If more than this many files are deleted within DEL_WINDOW seconds → alert
DELETE_THRESHOLD        = 3
DELETE_WINDOW_SECONDS   = 2.0

# Shannon entropy above this value = likely encrypted (max is 8.0)
ENTROPY_ENCRYPTED_MIN   = 7.5

# If a file's entropy jumps by more than this → suspicious
ENTROPY_SPIKE_DELTA     = 2.0

# ─── Suspicious Extensions ────────────────────────────
RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".crypted", ".crypt", ".pay",
    ".ransom", ".enc", ".ryk", ".locky", ".wncry", ".wcry",
    ".cerber", ".zepto", ".thor", ".aaa", ".abc", ".xyz",
    ".micro", ".dharma", ".onion",
}

# ─── Ransom Note Filenames ────────────────────────────
RANSOM_NOTE_NAMES = {
    "readme_decrypt.txt", "how_to_recover.txt", "how_to_decrypt.txt",
    "decrypt_instructions.txt", "restore_files.txt", "read_me.txt",
    "your_files_are_encrypted.txt", "ransom_note.txt",
    "help_decrypt.html", "recovery.txt", "unlock_files.txt",
}

# ─── Process Whitelist ────────────────────────────────
# Processes that are ALLOWED to touch honeypot files (e.g. editors during setup)
PROCESS_WHITELIST = {
    "python3", "python", "bash", "code", "vim", "nano",
}

# ─── Dashboard ────────────────────────────────────────
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 8080

# ─── Alerts ───────────────────────────────────────────
ALERT_COOLDOWN_SECONDS = 5     # Min gap between repeated alerts
DESKTOP_NOTIFY         = True  # Try notify-send on Linux
