from google.colab import drive
drive.mount('/content/drive')

!pip install cryptography

"""**AES-256 Encryption Code**"""

import psutil
import tracemalloc
import time
import os
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from os import urandom
# Function to derive encryption key using a password and a salt
def derive_key(password: str, salt: bytes) -> bytes:
    kdf_instance = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf_instance.derive(password.encode())

# Function to encrypt data using AES in CBC mode
def encrypt_data(plain_data: bytes, key: bytes) -> (bytes, bytes):
    iv = urandom(16)
    cipher_instance = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher_instance.encryptor()

    # Add padding to the plaintext
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_data) + padder.finalize()

    encrypted_output = encryptor.update(padded_data) + encryptor.finalize()
    return iv, encrypted_output

# Function to decrypt data
def decrypt_data(iv: bytes, encrypted_content: bytes, key: bytes) -> bytes:
    cipher_instance = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher_instance.decryptor()

    padded_content = decryptor.update(encrypted_content) + decryptor.finalize()

    # Remove padding from the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_content) + unpadder.finalize()

# Function to encrypt a file
def encrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, "rb") as f:
        plain_text = f.read()

    salt = urandom(16)
    key = derive_key(password, salt)
    iv, encrypted_text = encrypt_data(plain_text, key)

    with open(output_file, "wb") as f:
        f.write(salt + iv + encrypted_text)

# Function to decrypt a file
def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, "rb") as f:
        file_content = f.read()

    salt = file_content[:16]
    iv = file_content[16:32]
    encrypted_content = file_content[32:]

    key = derive_key(password, salt)
    decrypted_text = decrypt_data(iv, encrypted_content, key)

    with open(output_file, "wb") as f:
        f.write(decrypted_text)

"""**Testing the Implementation**

**Basic Encryption/Decryption**
"""

# Example for verifying encryption and decryption functionality
password = "passwordforencrytion"
test_data = b"This is a test message for validation."

# Derive a key and perform encryption/decryption
test_salt = urandom(16)
test_key = derive_key(password, test_salt)
test_iv, test_encrypted_data = encrypt_data(test_data, test_key)
print(test_encrypted_data);
test_decrypted_data = decrypt_data(test_iv, test_encrypted_data, test_key)
assert test_data == test_decrypted_data
print("Encryption/Decryption Verification Successful")

"""**File Encryption/Decryption**"""

# File paths for testing
input_path = "/content/drive/MyDrive/bigData assignment/assignment1/input1.txt"
encrypted_path = "/content/drive/MyDrive/bigData assignment/assignment1/encrypted_output.bin"
decrypted_path = "/content/drive/MyDrive/bigData assignment/assignment1/decrypted_output.txt"

# Write a test file
with open(input_path, "w") as f:
    f.write("This is a sample file content to test encryption.")
print("Test file created successfully!")

# Perform encryption and decryption on test files
encrypt_file(input_path, encrypted_path, password)
decrypt_file(encrypted_path, decrypted_path, password)

# Validate decrypted content matches the original
with open(input_path, "rb") as original, open(decrypted_path, "rb") as decrypted:
    assert original.read() == decrypted.read()
print("File Encryption/Decryption Test Passed!")

"""**Performance Analysis**"""

test_files = [
    "/content/drive/MyDrive/bigData assignment/assignment1/1mb.txt",
    "/content/drive/MyDrive/bigData assignment/assignment1/10mb.txt",
    "/content/drive/MyDrive/bigData assignment/assignment1/50mb.txt",
    "/content/drive/MyDrive/bigData assignment/assignment1/70mb.txt",
    "/content/drive/MyDrive/bigData assignment/assignment1/100mb.txt"
]
performance_results = []
memory_usage = []
cpu_usage = []

# Performance analysis
for test_file in test_files:
    file_size_mb = os.path.getsize(test_file) / (1024 * 1024)
    print(f"Processing file: {test_file}, Size: {file_size_mb:.2f} MB")

    # Start tracking memory
    tracemalloc.start()

    # Monitor CPU usage
    process = psutil.Process(os.getpid())
    start_cpu_time = process.cpu_times().user  # Start user CPU time

    # Measure encryption time
    encrypted_file = f"{test_file}.enc"
    start_time = time.time()
    encrypt_file(test_file, encrypted_file, password)
    encryption_time = time.time() - start_time

    # Measure peak memory during encryption
    peak_memory_encryption = tracemalloc.get_traced_memory()[1] / (1024 * 1024)  # In MB

    # Measure decryption time
    decrypted_file = f"{test_file}.dec"
    start_time = time.time()
    decrypt_file(encrypted_file, decrypted_file, password)
    decryption_time = time.time() - start_time

    # Measure peak memory during decryption
    peak_memory_decryption = tracemalloc.get_traced_memory()[1] / (1024 * 1024)  # In MB

    # End CPU monitoring
    end_cpu_time = process.cpu_times().user
    cpu_time = end_cpu_time - start_cpu_time  # Total CPU time used
    cpu_percent = psutil.cpu_percent(interval=1)  # Measure CPU utilization during operations

    tracemalloc.stop()

    # Store memory, CPU, and performance metrics
    memory_usage.append({"file": test_file, "encryption_memory": peak_memory_encryption, "decryption_memory": peak_memory_decryption})
    cpu_usage.append({"file": test_file, "cpu_time_sec": cpu_time, "cpu_percent": cpu_percent})
    performance_results.append({
        "filename": os.path.basename(test_file),
        "file_size_mb": file_size_mb,
        "encryption_time": encryption_time,
        "decryption_time": decryption_time
    })

    # Cleanup temporary files
    os.remove(encrypted_file)
    os.remove(decrypted_file)

# Display performance data
print("\n--- Performance Results ---")
for result in performance_results:
    print(f"File: {result['filename']}, Size: {result['file_size_mb']:.2f} MB, "
          f"Encryption Time: {result['encryption_time']:.4f} sec, "
          f"Decryption Time: {result['decryption_time']:.4f} sec")

# Memory and CPU Results
print("\n--- Memory Usage ---")
for mem in memory_usage:
    print(f"File: {os.path.basename(mem['file'])}, Encryption Memory: {mem['encryption_memory']:.4f} MB, Decryption Memory: {mem['decryption_memory']:.4f} MB")

print("\n--- CPU Time and Utilization ---")
for cpu in cpu_usage:
    print(f"File: {os.path.basename(cpu['file'])}, CPU Time: {cpu['cpu_time_sec']:.4f} sec, CPU Utilization: {cpu['cpu_percent']:.2f}%")

# Visualization
file_sizes = [result['file_size_mb'] for result in performance_results]
encryption_times = [result['encryption_time'] for result in performance_results]
decryption_times = [result['decryption_time'] for result in performance_results]
encryption_memories = [mem['encryption_memory'] for mem in memory_usage]
decryption_memories = [mem['decryption_memory'] for mem in memory_usage]
cpu_times = [cpu['cpu_time_sec'] for cpu in cpu_usage]
cpu_percents = [cpu['cpu_percent'] for cpu in cpu_usage]

# Plot encryption and decryption times
plt.figure(figsize=(10, 6))
plt.plot(file_sizes, encryption_times, label="Encryption Time (sec)", marker="o", color="blue")
plt.plot(file_sizes, decryption_times, label="Decryption Time (sec)", marker="s", color="green")
plt.xlabel("File Size (MB)")
plt.ylabel("Time (Seconds)")
plt.title("AES Encryption and Decryption Times")
plt.legend()
plt.grid(True)
plt.show()

# Plot memory usage
plt.figure(figsize=(10, 6))
plt.plot(file_sizes, encryption_memories, label="Encryption Memory (MB)", marker="o", color="purple")
plt.plot(file_sizes, decryption_memories, label="Decryption Memory (MB)", marker="s", color="orange")
plt.xlabel("File Size (MB)")
plt.ylabel("Memory Usage (MB)")
plt.title("Memory Usage During AES Operations")
plt.legend()
plt.grid(True)
plt.show()

# Plot CPU time
plt.figure(figsize=(10, 6))
plt.bar([os.path.basename(cpu['file']) for cpu in cpu_usage], cpu_times, color="cyan", alpha=0.7)
plt.xlabel("File")
plt.ylabel("CPU Time (Seconds)")
plt.title("CPU Time for AES Encryption and Decryption")
plt.grid(axis="y")
plt.show()

# Plot CPU Utilization
plt.figure(figsize=(10, 6))
plt.bar([os.path.basename(cpu['file']) for cpu in cpu_usage], cpu_percents, color="magenta", alpha=0.7)
plt.xlabel("File")
plt.ylabel("CPU Utilization (%)")
plt.title("CPU Utilization During AES Encryption and Decryption")
plt.grid(axis="y")
plt.show()

# Recommendations for Optimization
print("\n--- Recommendations for Optimization ---")
print("1. Use larger buffer sizes for file I/O operations to reduce overhead.")
print("2. Adjust PBKDF2 iterations based on security needs to balance performance.")
print("3. Parallelize encryption and decryption for larger files on multi-core systems.")
print("4. Minimize peak memory usage by optimizing the padding mechanism.")
