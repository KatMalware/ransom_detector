"""
Ransomware Detection System — Magic Bytes Signatures Checker
Checks if the file contents match the expected file signature / header.
Helps detect ransomware renames (e.g., locking a PDF file and keeping the extension).
"""

import os

# Known signatures (in hexadecimal representation)
SIGNATURES = {
    ".pdf":  [b"\x25\x50\x44\x46"],                          # %PDF
    ".png":  [b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"],          # PNG header
    ".jpg":  [b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", 
              b"\xff\xd8\xff\xee", b"\xff\xd8\xff\xe0"],      # JPEG markers
    ".jpeg": [b"\xff\xd8\xff"],
    ".zip":  [b"\x50\x4b\x03\x04", b"\x50\x4b\x05\x06", b"\x50\x4b\x07\x08"], # PKZIP
    ".docx": [b"\x50\x4b\x03\x04"],                          # Office XML is zipped
    ".xlsx": [b"\x50\x4b\x03\x04"],
    ".pptx": [b"\x50\x4b\x03\x04"],
    ".exe":  [b"\x4d\x5a"],                                  # MZ
    ".elf":  [b"\x7f\x45\x4c\x46"],                          # ELF
    ".tar":  [b"\x75\x73\x74\x61\x72"],                      # ustar (usually offset 257)
    ".gz":   [b"\x1f\x8b"],
    ".ttf":  [b"\x00\x01\x00\x00\x00", b"\x74\x72\x75\x65"],  # TrueType Font
}

def verify_magic_bytes(filepath: str) -> dict:
    """
    Verify if the file header matches its file extension.
    Returns a dict with verification details:
    {
        "status": "MATCH" | "MISMATCH" | "UNKNOWN" | "ERROR",
        "expected": list of bytes,
        "actual": bytes found
    }
    """
    _, ext = os.path.splitext(filepath)
    ext = ext.lower()
    
    if ext not in SIGNATURES:
        return {"status": "UNKNOWN", "expected": None, "actual": None}
        
    try:
        # We only need the first 8 bytes for signature checking
        with open(filepath, "rb") as f:
            actual_header = f.read(8)
    except Exception:
        return {"status": "ERROR", "expected": None, "actual": None}
        
    expected_sigs = SIGNATURES[ext]
    
    for sig in expected_sigs:
        if actual_header.startswith(sig):
            return {
                "status": "MATCH",
                "expected": sig,
                "actual": actual_header[:len(sig)]
            }
            
    return {
        "status": "MISMATCH",
        "expected": expected_sigs[0],
        "actual": actual_header
    }
