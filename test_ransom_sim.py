#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  RansomGuard — Safe Ransomware Behavior Simulator            ║
║  FOR TESTING THE DETECTOR ONLY                               ║
║                                                              ║
║  This script:                                                ║
║    1. Creates a sandboxed test directory with dummy files     ║
║    2. Simulates ransomware-like behavior on THOSE files only  ║
║    3. Can fully restore everything back to normal             ║
║                                                              ║
║  It NEVER touches any real user files.                        ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python test_ransom_sim.py setup      — Create test sandbox with dummy files
    python test_ransom_sim.py attack     — Simulate ransomware on sandbox files
    python test_ransom_sim.py restore    — Restore sandbox to original state
    python test_ransom_sim.py clean      — Delete the entire sandbox
    python test_ransom_sim.py scan       — Run RansomGuard scanner on sandbox
"""

import os
import sys
import time
import shutil
import random
import string

# ── Sandbox Configuration ──
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SANDBOX_DIR = os.path.join(SCRIPT_DIR, "test_sandbox")
BACKUP_DIR = os.path.join(SCRIPT_DIR, ".test_sandbox_backup")

# Dummy file templates
DUMMY_FILES = {
    "report_q1.docx":      "Quarterly Report Q1 2026\n" + "Revenue data and analysis...\n" * 50,
    "employee_list.csv":    "Name,Department,Salary\n" + "John Doe,Engineering,85000\n" * 30,
    "budget_2026.xlsx":     "Budget Planning Document\n" + "Category,Amount,Notes\n" * 40,
    "meeting_notes.txt":    "Meeting Notes - Project Alpha\n" + "Discussion point: " * 60,
    "credentials.conf":     "[database]\nhost=10.0.0.5\nuser=admin\npassword=s3cretP@ss\n" * 10,
    "source_code.py":       "#!/usr/bin/env python3\nimport os\n" + "def func(): pass\n" * 80,
    "readme.md":            "# Project Documentation\n" + "This is an important project file.\n" * 30,
    "photo_backup.jpg":     "JFIF" + "".join(random.choices(string.ascii_letters, k=2000)),
    "database_dump.sql":    "CREATE TABLE users (id INT, name VARCHAR);\n" + "INSERT INTO users VALUES " * 40,
    "config.xml":           '<?xml version="1.0"?>\n<config>\n' + "  <setting key='x' value='y'/>\n" * 50 + "</config>",
}

# ANSI Colors
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
D = "\033[2m"
X = "\033[0m"


def cmd_setup():
    """Create the sandbox directory with dummy files."""
    print(f"\n{C}{B}[SETUP]{X} Creating test sandbox...\n")

    if os.path.exists(SANDBOX_DIR):
        print(f"  {Y}⚠ Sandbox already exists. Cleaning up first...{X}")
        shutil.rmtree(SANDBOX_DIR)
    if os.path.exists(BACKUP_DIR):
        shutil.rmtree(BACKUP_DIR)

    os.makedirs(SANDBOX_DIR)
    os.makedirs(BACKUP_DIR)

    for fname, content in DUMMY_FILES.items():
        fpath = os.path.join(SANDBOX_DIR, fname)
        with open(fpath, "w") as f:
            f.write(content)

        # Also save a backup copy for restore
        backup_path = os.path.join(BACKUP_DIR, fname)
        with open(backup_path, "w") as f:
            f.write(content)

        size = os.path.getsize(fpath)
        print(f"  {G}✓{X} Created: {fname} ({size} bytes)")

    print(f"\n  {G}{B}✅ Sandbox ready!{X} {len(DUMMY_FILES)} files in {D}{SANDBOX_DIR}{X}")
    print(f"  {D}Backup saved to {BACKUP_DIR}{X}")
    print(f"\n  {Y}Next step:{X} python test_ransom_sim.py attack")


def cmd_attack():
    """Simulate ransomware behavior on sandbox files."""
    if not os.path.exists(SANDBOX_DIR):
        print(f"{R}Error:{X} Sandbox not found. Run 'setup' first.")
        sys.exit(1)

    files = [f for f in os.listdir(SANDBOX_DIR) if os.path.isfile(os.path.join(SANDBOX_DIR, f))]
    if not files:
        print(f"{R}Error:{X} No files in sandbox. Run 'setup' first.")
        sys.exit(1)

    print(f"\n{R}{B}[ATTACK]{X} Simulating ransomware behavior...\n")
    print(f"  {D}Target: {SANDBOX_DIR}{X}")
    print(f"  {D}Files:  {len(files)}{X}\n")

    time.sleep(1)

    # Phase 1: Overwrite file contents with random bytes (simulates encryption)
    print(f"  {R}▸ Phase 1:{X} Overwriting files with random data (simulates AES encryption)...")
    time.sleep(0.5)
    for fname in files:
        fpath = os.path.join(SANDBOX_DIR, fname)
        original_size = os.path.getsize(fpath)
        # Write random bytes (high entropy, mimics ciphertext)
        with open(fpath, "wb") as f:
            f.write(os.urandom(original_size))
        print(f"    {R}✗{X} Encrypted: {fname} → {original_size} bytes of random data")
        time.sleep(0.3)

    # Phase 2: Rename files with ransomware extension
    print(f"\n  {R}▸ Phase 2:{X} Renaming files with .encrypted extension...")
    time.sleep(0.5)
    renamed_files = []
    for fname in files:
        old_path = os.path.join(SANDBOX_DIR, fname)
        new_name = fname + ".encrypted"
        new_path = os.path.join(SANDBOX_DIR, new_name)
        os.rename(old_path, new_path)
        renamed_files.append(new_name)
        print(f"    {R}✗{X} {fname} → {new_name}")
        time.sleep(0.2)

    # Phase 3: Drop ransom note
    print(f"\n  {R}▸ Phase 3:{X} Dropping ransom note...")
    time.sleep(0.5)
    ransom_note = os.path.join(SANDBOX_DIR, "README_RESTORE_FILES.txt")
    with open(ransom_note, "w") as f:
        f.write("""
╔══════════════════════════════════════════════════════════╗
║                YOUR FILES HAVE BEEN ENCRYPTED            ║
║                                                          ║
║  All your important documents, photos, databases,        ║
║  and other files have been encrypted with military        ║
║  grade encryption algorithm.                             ║
║                                                          ║
║  *** THIS IS A SIMULATION FOR TESTING PURPOSES ***       ║
║  *** NO REAL FILES WERE HARMED ***                       ║
║                                                          ║
║  To restore: python test_ransom_sim.py restore           ║
╚══════════════════════════════════════════════════════════╝
""")
    print(f"    {R}✗{X} Dropped: README_RESTORE_FILES.txt")

    print(f"\n  {R}{B}💀 Attack simulation complete!{X}")
    print(f"\n  {Y}Now test your detector:{X}")
    print(f"    python scanner.py scan {SANDBOX_DIR}")
    print(f"\n  {G}To restore:{X} python test_ransom_sim.py restore")


def cmd_restore():
    """Restore sandbox files from backup."""
    if not os.path.exists(BACKUP_DIR):
        print(f"{R}Error:{X} No backup found. Run 'setup' first.")
        sys.exit(1)

    print(f"\n{G}{B}[RESTORE]{X} Restoring sandbox from backup...\n")

    # Clean current sandbox
    if os.path.exists(SANDBOX_DIR):
        shutil.rmtree(SANDBOX_DIR)
    os.makedirs(SANDBOX_DIR)

    # Copy backup files
    for fname in os.listdir(BACKUP_DIR):
        src = os.path.join(BACKUP_DIR, fname)
        dst = os.path.join(SANDBOX_DIR, fname)
        shutil.copy2(src, dst)
        print(f"  {G}✓{X} Restored: {fname}")

    print(f"\n  {G}{B}✅ All files restored!{X}")
    print(f"  {D}Sandbox is back to normal.{X}")


def cmd_clean():
    """Delete sandbox and backup entirely."""
    print(f"\n{Y}{B}[CLEAN]{X} Removing sandbox and backup...\n")

    if os.path.exists(SANDBOX_DIR):
        shutil.rmtree(SANDBOX_DIR)
        print(f"  {G}✓{X} Removed: {SANDBOX_DIR}")
    if os.path.exists(BACKUP_DIR):
        shutil.rmtree(BACKUP_DIR)
        print(f"  {G}✓{X} Removed: {BACKUP_DIR}")

    print(f"\n  {G}{B}✅ Cleaned up!{X}")


def cmd_scan():
    """Run the RansomGuard scanner on the sandbox."""
    if not os.path.exists(SANDBOX_DIR):
        print(f"{R}Error:{X} Sandbox not found. Run 'setup' first.")
        sys.exit(1)

    print(f"\n{C}{B}[SCAN]{X} Launching RansomGuard scanner on sandbox...\n")
    os.system(f"python {os.path.join(SCRIPT_DIR, 'scanner.py')} scan {SANDBOX_DIR}")


def main():
    if len(sys.argv) < 2:
        print(f"""
{C}{B}RansomGuard Test Simulator{X}
{D}Safe, sandboxed ransomware behavior simulation for detector testing.{X}

{B}Commands:{X}
  {C}python test_ransom_sim.py setup{X}     — Create sandbox with dummy files
  {C}python test_ransom_sim.py attack{X}    — Simulate ransomware on sandbox
  {C}python test_ransom_sim.py restore{X}   — Restore files from backup
  {C}python test_ransom_sim.py clean{X}     — Delete sandbox entirely
  {C}python test_ransom_sim.py scan{X}      — Run detector on sandbox

{B}Typical workflow:{X}
  1. {G}setup{X}   → Create test files
  2. {G}scan{X}    → Verify all files show SAFE
  3. {G}attack{X}  → Simulate ransomware
  4. {G}scan{X}    → Verify detector catches CRITICAL threats
  5. {G}restore{X} → Reset sandbox for next test
""")
        return

    cmd = sys.argv[1].lower()

    if cmd == "setup":
        cmd_setup()
    elif cmd == "attack":
        cmd_attack()
    elif cmd == "restore":
        cmd_restore()
    elif cmd == "clean":
        cmd_clean()
    elif cmd == "scan":
        cmd_scan()
    else:
        print(f"{R}Unknown command: '{cmd}'{X}")
        print(f"Use: setup, attack, restore, clean, or scan")
        sys.exit(1)


if __name__ == "__main__":
    main()
