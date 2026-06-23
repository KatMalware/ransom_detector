"""
Ransomware Detection System — Agentic Decision Engine
Multi-factor threat assessor that weighs:
  1. Shannon Entropy score
  2. Deep Learning model confidence
  3. Magic Byte header mismatch
  4. Extension anomaly
  5. Process behavior (RAM / I/O / syscalls)

Outputs a structured verdict with reasoning.
"""

import os
from entropy import file_entropy
from magic_bytes import verify_magic_bytes
import config


class AgentVerdict:
    """Structured verdict returned by the agent."""

    def __init__(self):
        self.filepath = ""
        self.verdict = "SAFE"        # SAFE | SUSPICIOUS | CRITICAL
        self.risk_score = 0.0        # 0.0 to 100.0
        self.reasons = []            # List of reasoning strings
        self.factors = {}            # Factor name → score

    def to_dict(self) -> dict:
        return {
            "filepath":   self.filepath,
            "verdict":    self.verdict,
            "risk_score": round(self.risk_score, 1),
            "reasons":    self.reasons,
            "factors":    self.factors,
        }


class AgenticEngine:
    """
    Multi-factor threat assessment agent.
    Analyses files using multiple signals and combines them
    into a weighted risk score with human-readable reasoning.
    """

    # Weight configuration for each factor
    WEIGHTS = {
        "entropy":       0.30,
        "dl_model":      0.35,
        "magic_bytes":   0.15,
        "extension":     0.20,
    }

    VERDICT_THRESHOLDS = {
        "CRITICAL":   70.0,
        "SUSPICIOUS": 40.0,
    }

    def __init__(self, dl_analyzer=None):
        self.dl_analyzer = dl_analyzer

    def analyze_file(self, filepath: str) -> AgentVerdict:
        """
        Run the full agentic analysis pipeline on a single file.
        Returns a structured AgentVerdict.
        """
        v = AgentVerdict()
        v.filepath = filepath

        if not os.path.isfile(filepath):
            v.verdict = "SAFE"
            v.reasons.append("File does not exist or is not a regular file.")
            return v

        # ──────── Factor 1: Shannon Entropy ────────
        ent = file_entropy(filepath)
        ent_risk = self._entropy_risk(ent)
        v.factors["entropy"] = {"value": round(ent, 3), "risk": round(ent_risk, 2)}

        if ent >= 7.8:
            v.reasons.append(
                f"🔴 VERY HIGH entropy ({ent:.3f}/8.0). File appears to be encrypted "
                f"with strong cipher (AES/ChaCha). Normal files score 3.0–6.5."
            )
        elif ent >= 7.0:
            v.reasons.append(
                f"🟡 Elevated entropy ({ent:.3f}/8.0). Could be compressed archive "
                f"or partially encrypted data."
            )
        else:
            v.reasons.append(
                f"🟢 Normal entropy ({ent:.3f}/8.0). Byte distribution is consistent "
                f"with standard file types."
            )

        # ──────── Factor 2: Deep Learning Model ────────
        dl_risk = 0.0
        if self.dl_analyzer and self.dl_analyzer.enabled:
            confidence = self.dl_analyzer.predict(filepath)
            if confidence >= 0:
                dl_risk = confidence
                v.factors["dl_model"] = {"confidence": round(confidence * 100, 1), "risk": round(dl_risk, 2)}

                if confidence >= 0.90:
                    v.reasons.append(
                        f"🔴 AI Neural Network is {confidence*100:.1f}% confident this file "
                        f"has been encrypted by ransomware."
                    )
                elif confidence >= 0.60:
                    v.reasons.append(
                        f"🟡 AI model reports {confidence*100:.1f}% malicious probability. "
                        f"Byte patterns partially match encryption signatures."
                    )
                else:
                    v.reasons.append(
                        f"🟢 AI model reports {confidence*100:.1f}% malicious probability. "
                        f"File appears normal to the neural network."
                    )
            else:
                v.factors["dl_model"] = {"confidence": "N/A", "risk": 0}
                v.reasons.append("⚪ Deep Learning model prediction unavailable.")
        else:
            v.factors["dl_model"] = {"confidence": "N/A (model not loaded)", "risk": 0}
            v.reasons.append("⚪ Deep Learning model not loaded. Run train_model.py first.")

        # ──────── Factor 3: Magic Bytes Verification ────────
        magic = verify_magic_bytes(filepath)
        magic_risk = 0.0

        if magic["status"] == "MISMATCH":
            magic_risk = 1.0
            v.reasons.append(
                f"🔴 MAGIC BYTE MISMATCH! File extension doesn't match actual header. "
                f"Expected: {magic['expected']}, Got: {magic['actual']!r}. "
                f"This indicates the file contents were replaced (likely encrypted)."
            )
        elif magic["status"] == "MATCH":
            v.reasons.append(
                f"🟢 File signature verified. Header matches declared extension."
            )
            if dl_risk > 0.0:
                dl_risk = dl_risk * 0.05
                v.reasons.append("🟢 Magic signature verified. Suppressed AI model false positive risk.")
        else:
            v.reasons.append(
                f"⚪ File type not in signature database. Cannot verify header."
            )

        v.factors["magic_bytes"] = {"status": magic["status"], "risk": magic_risk}

        # ──────── Factor 4: Extension Anomaly ────────
        _, ext = os.path.splitext(filepath)
        ext_risk = 0.0

        if ext.lower() in config.RANSOMWARE_EXTENSIONS:
            ext_risk = 1.0
            v.reasons.append(
                f"🔴 File has a known ransomware extension: '{ext}'. "
                f"This is a strong indicator of encryption."
            )
        else:
            v.reasons.append(
                f"🟢 File extension '{ext}' is not a known ransomware marker."
            )

        v.factors["extension"] = {"ext": ext, "risk": ext_risk}

        # ──────── Weighted Risk Score ────────
        # If DL model is not available, redistribute its weight to entropy
        dl_available = (self.dl_analyzer and self.dl_analyzer.enabled)
        if dl_available:
            w_ent   = self.WEIGHTS["entropy"]
            w_dl    = self.WEIGHTS["dl_model"]
            w_magic = self.WEIGHTS["magic_bytes"]
            w_ext   = self.WEIGHTS["extension"]
        else:
            # No DL model: give entropy 50%, magic 20%, extension 30%
            w_ent   = 0.50
            w_dl    = 0.0
            w_magic = 0.20
            w_ext   = 0.30

        weighted_score = (
            ent_risk   * w_ent   * 100 +
            dl_risk    * w_dl    * 100 +
            magic_risk * w_magic * 100 +
            ext_risk   * w_ext   * 100
        )

        v.risk_score = min(weighted_score, 100.0)

        # ──────── Final Verdict ────────
        if v.risk_score >= self.VERDICT_THRESHOLDS["CRITICAL"]:
            v.verdict = "CRITICAL"
        elif v.risk_score >= self.VERDICT_THRESHOLDS["SUSPICIOUS"]:
            v.verdict = "SUSPICIOUS"
        else:
            v.verdict = "SAFE"

        return v

    @staticmethod
    def _entropy_risk(entropy_val: float) -> float:
        """
        Convert Shannon entropy (0–8) to a risk score (0.0–1.0).
        Normal files: ~4.0  → risk ≈ 0.0
        Compressed:   ~7.0  → risk ≈ 0.5
        Encrypted:    ~7.9  → risk ≈ 1.0
        """
        if entropy_val < 5.0:
            return 0.0
        elif entropy_val < 7.0:
            return (entropy_val - 5.0) / 4.0  # 0.0 to 0.5
        else:
            return 0.5 + (entropy_val - 7.0) / 2.0  # 0.5 to 1.0
