"""
Ransomware Detection System — Deep Learning Analyzer
Extracts 256-byte histograms and uses a trained Keras model for ransomware classification.
"""

import os
import numpy as np

# Suppress TensorFlow logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
try:
    import tensorflow as tf
except ImportError:
    tf = None

def get_byte_histogram(filepath: str) -> np.ndarray:
    """
    Read a file and return a normalized 256-bin histogram of its byte values.
    Returns an array of shape (256,).
    """
    histogram = np.zeros(256, dtype=np.float32)
    try:
        with open(filepath, "rb") as f:
            data = f.read()
            if not data:
                return histogram
            
            # Count byte frequencies
            counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            # Normalize to 0.0 - 1.0 range
            histogram = counts.astype(np.float32) / len(data)
    except Exception:
        pass
    
    return histogram

class DLAnalyzer:
    """Loads the trained DL model and predicts file maliciousness."""
    
    def __init__(self, model_path: str = "ransom_model.keras"):
        self.model_path = os.path.join(os.path.dirname(__file__), model_path)
        self.model = None
        self.enabled = False
        
        if tf is None:
            print("[!] TensorFlow not found. Deep Learning detection disabled.")
            return
            
        if os.path.exists(self.model_path):
            try:
                self.model = tf.keras.models.load_model(self.model_path)
                self.enabled = True
                print(f"[+] Deep Learning model loaded: {model_path}")
            except Exception as e:
                print(f"[!] Failed to load DL model: {e}")
        else:
            print(f"[!] DL model not found at {self.model_path}. Run train_model.py first.")

    def predict(self, filepath: str) -> float:
        """
        Return the model's confidence (0.0 to 1.0) that the file is encrypted/ransomware.
        Returns -1.0 if the model is not enabled or failed.
        """
        if not self.enabled or self.model is None:
            return -1.0
            
        hist = get_byte_histogram(filepath)
        if np.sum(hist) == 0:
            return 0.0  # Empty file or error reading
            
        # Neural network expects a batch dimension: shape (1, 256)
        hist_batch = np.expand_dims(hist, axis=0)
        
        try:
            # Predict
            prediction = self.model.predict(hist_batch, verbose=0)
            return float(prediction[0][0])
        except Exception:
            return -1.0

if __name__ == "__main__":
    # Test script
    analyzer = DLAnalyzer()
    if analyzer.enabled:
        print("Model is ready.")
