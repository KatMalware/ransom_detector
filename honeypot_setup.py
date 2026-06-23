"""
Ransomware Detection System — Honeypot Setup
Creates a realistic directory tree filled with decoy files that act as bait.
If ransomware touches these files, we catch it immediately.
"""

import os
import random
import string
import shutil
import config


# ─── Realistic file templates ─────────────────────────

_TEXT_BODIES = [
    "Dear Team,\n\nPlease find the quarterly report attached. "
    "Revenue grew 12% compared to Q3. We expect continued growth "
    "in the Asia-Pacific region.\n\nRegards,\nManagement",

    "CONFIDENTIAL — Employee Performance Review 2026\n\n"
    "Employee: John Smith\nDepartment: Engineering\n"
    "Rating: Exceeds Expectations\nNotes: Promoted to Senior.",

    "Meeting Minutes — Board of Directors\nDate: June 2026\n"
    "Agenda: Annual budget review, market expansion strategy, "
    "cybersecurity compliance audit results.",

    "Invoice #20260401\nBilled To: Acme Corp\nAmount: $45,320.00\n"
    "Due Date: 30-Jun-2026\nPayment Terms: Net 30\n"
    "Description: Managed cloud infrastructure services.",

    "Project Roadmap — Fiscal Year 2026-2027\n\n"
    "Phase 1: Requirements gathering (Jul-Aug)\n"
    "Phase 2: Development sprint (Sep-Dec)\n"
    "Phase 3: QA and compliance testing (Jan-Feb)\n"
    "Phase 4: Production deployment (Mar)",
]

_CSV_HEADER = "EmployeeID,Name,Department,Salary,JoinDate\n"
_CSV_ROWS = [
    "1001,Alice Johnson,Engineering,95000,2022-03-15\n",
    "1002,Bob Martinez,Sales,72000,2021-07-01\n",
    "1003,Carol Wang,Finance,88000,2023-01-20\n",
    "1004,David Kim,HR,65000,2020-11-10\n",
    "1005,Eva Patel,Engineering,102000,2019-06-25\n",
    "1006,Frank Chen,Legal,91000,2024-02-14\n",
    "1007,Grace Lee,Marketing,78000,2022-09-30\n",
    "1008,Henry Brown,Operations,70000,2023-05-18\n",
]

# Subdirectories that look like a real corporate share
_SUBDIRS = ["HR", "Finance", "Legal", "Engineering", "Reports", "Backups"]

# Filenames that look valuable to ransomware
_FILE_TEMPLATES = {
    "HR": [
        ("employee_records.csv", "csv"),
        ("salary_data_2026.csv", "csv"),
        ("hiring_pipeline.txt", "txt"),
        ("performance_reviews.txt", "txt"),
        ("benefits_summary.txt", "txt"),
    ],
    "Finance": [
        ("Q4_Financial_Report.txt", "txt"),
        ("annual_budget_2026.csv", "csv"),
        ("invoice_tracker.csv", "csv"),
        ("tax_filings_draft.txt", "txt"),
        ("revenue_forecast.txt", "txt"),
    ],
    "Legal": [
        ("NDA_template.txt", "txt"),
        ("compliance_audit_results.txt", "txt"),
        ("vendor_contracts.txt", "txt"),
        ("litigation_summary.txt", "txt"),
    ],
    "Engineering": [
        ("architecture_design.txt", "txt"),
        ("api_credentials.txt", "txt"),
        ("deployment_checklist.txt", "txt"),
        ("server_inventory.csv", "csv"),
        ("incident_postmortem.txt", "txt"),
    ],
    "Reports": [
        ("board_meeting_minutes.txt", "txt"),
        ("quarterly_KPI_dashboard.csv", "csv"),
        ("market_analysis_2026.txt", "txt"),
        ("customer_feedback.csv", "csv"),
    ],
    "Backups": [
        ("database_dump_jun2026.txt", "txt"),
        ("config_backup.txt", "txt"),
        ("user_accounts_export.csv", "csv"),
    ],
}


def _random_string(length: int = 200) -> str:
    """Generate random readable text to pad file content."""
    words = []
    for _ in range(length // 5):
        word_len = random.randint(2, 10)
        words.append("".join(random.choices(string.ascii_lowercase, k=word_len)))
    return " ".join(words)


def _generate_content(file_type: str) -> str:
    """Generate realistic-looking file content."""
    if file_type == "csv":
        rows = random.sample(_CSV_ROWS, k=min(len(_CSV_ROWS), random.randint(4, 8)))
        return _CSV_HEADER + "".join(rows) + "\n" + _random_string(100)
    else:
        body = random.choice(_TEXT_BODIES)
        return body + "\n\n" + _random_string(150)


def setup_honeypot(honeypot_dir: str = None, force: bool = False) -> dict:
    """
    Create the honeypot directory with realistic decoy files.

    Returns a dict mapping filepath → initial entropy for baseline comparison.
    """
    if honeypot_dir is None:
        honeypot_dir = config.HONEYPOT_DIR

    if os.path.exists(honeypot_dir) and not force:
        # Already set up — just return existing files
        from entropy import file_entropy
        baseline = {}
        for root, _, files in os.walk(honeypot_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                baseline[fpath] = file_entropy(fpath)
        if baseline:
            return baseline

    # Clean and recreate
    if os.path.exists(honeypot_dir):
        shutil.rmtree(honeypot_dir)

    os.makedirs(honeypot_dir, exist_ok=True)

    created = {}
    from entropy import file_entropy

    for subdir in _SUBDIRS:
        subdir_path = os.path.join(honeypot_dir, subdir)
        os.makedirs(subdir_path, exist_ok=True)

        for filename, ftype in _FILE_TEMPLATES.get(subdir, []):
            filepath = os.path.join(subdir_path, filename)
            content = _generate_content(ftype)
            with open(filepath, "w") as f:
                f.write(content)
            created[filepath] = file_entropy(filepath)

    # Add a few top-level files too
    for name in ["README.txt", "company_directory.csv", "important_notes.txt"]:
        filepath = os.path.join(honeypot_dir, name)
        ftype = "csv" if name.endswith(".csv") else "txt"
        with open(filepath, "w") as f:
            f.write(_generate_content(ftype))
        created[filepath] = file_entropy(filepath)

    return created


if __name__ == "__main__":
    print("[*] Setting up honeypot directory...")
    files = setup_honeypot(force=True)
    print(f"[+] Created {len(files)} decoy files in {config.HONEYPOT_DIR}")
    for fpath, ent in sorted(files.items()):
        rel = os.path.relpath(fpath, config.HONEYPOT_DIR)
        print(f"    {rel:45s}  entropy: {ent:.3f}")
