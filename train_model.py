"""
Ransomware Detection System — Deep Learning Model Trainer
Generates synthetic data (Normal vs Encrypted file histograms) and trains a Neural Network.
"""

import os
import random
import string
import numpy as np

# Suppress TensorFlow logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
try:
    import tensorflow as tf
except ImportError:
    print("[!] TensorFlow not installed. Run: pip install tensorflow numpy")
    exit(1)

# Training configuration
NUM_SAMPLES_PER_CLASS = 15000
EPOCHS = 8
BATCH_SIZE = 64
MODEL_FILENAME = "ransom_model.keras"

def generate_normal_histogram() -> np.ndarray:
    """
    Simulate a normal file's byte histogram.
    Normal files usually contain text (ASCII), structured data, or specific headers,
    meaning their byte distribution is skewed, not uniform.
    """
    length = random.randint(1000, 10000)
    
    # 80% chance of being text/code/csv
    if random.random() < 0.8:
        chars = string.ascii_letters + string.digits + " \n\t.,;:!?-_{}[]()=\"'/\\"
        # Give some characters higher weights to make it more realistic
        data = "".join(random.choices(chars, k=length)).encode('utf-8')
    else:
        # 20% chance of being some binary format with skewed bytes
        # Just create random bytes but heavily bias towards 0x00, 0xFF, etc.
        data = bytearray(length)
        for i in range(length):
            if random.random() < 0.3:
                data[i] = 0x00
            elif random.random() < 0.1:
                data[i] = 0xFF
            else:
                data[i] = random.randint(0, 255)
                
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    return counts.astype(np.float32) / len(data)

def generate_encrypted_histogram() -> np.ndarray:
    """
    Simulate an encrypted file's byte histogram.
    Strong encryption (like AES used by ransomware) produces ciphertext
    that is computationally indistinguishable from true random data.
    """
    length = random.randint(1000, 10000)
    data = os.urandom(length)
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    return counts.astype(np.float32) / len(data)

def generate_dataset():
    print(f"[*] Generating synthetic dataset ({NUM_SAMPLES_PER_CLASS} samples per class)...")
    X = []
    y = []
    
    for _ in range(NUM_SAMPLES_PER_CLASS):
        # Class 0: Normal File
        X.append(generate_normal_histogram())
        y.append(0.0)
        
        # Class 1: Encrypted File (Ransomware)
        X.append(generate_encrypted_histogram())
        y.append(1.0)
        
    X = np.array(X)
    y = np.array(y)
    
    # Shuffle the dataset
    indices = np.arange(X.shape[0])
    np.random.shuffle(indices)
    
    return X[indices], y[indices]

def build_model():
    """Build a Multi-Layer Perceptron (MLP) for classification."""
    model = tf.keras.Sequential([
        # Input is 256 dimensions (one for each possible byte value)
        tf.keras.layers.Dense(128, activation='relu', input_shape=(256,)),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid') # Output 0.0 to 1.0
    ])
    
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    return model

def main():
    X, y = generate_dataset()
    
    print("[*] Building Deep Learning Model...")
    model = build_model()
    model.summary()
    
    print("\n[*] Starting Training...")
    # Train the model with an 80/20 train/validation split
    history = model.fit(
        X, y,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=0.2,
        verbose=1
    )
    
    # Save the model
    model_path = os.path.join(os.path.dirname(__file__), MODEL_FILENAME)
    model.save(model_path)
    print(f"\n[+] Training Complete! Model saved to: {model_path}")

if __name__ == "__main__":
    main()
