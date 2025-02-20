!pip install pycryptodome psutil matplotlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time
import psutil
import matplotlib.pyplot as plt
import numpy as np

# Generate RSA key pair
def generate_rsa_keypair(bits=2048):
    try:
        key = RSA.generate(bits)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        print(private_key)
        return private_key, public_key
    except Exception as e:
        print(f"Error generating RSA keys: {e}")
        return None, None

# Encrypt message
def rsa_encrypt(message, public_key):
    try:
        recipient_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        encrypted_msg = cipher_rsa.encrypt(message)
        return encrypted_msg
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

# Decrypt message
def rsa_decrypt(encrypted_msg, private_key):
    try:
        key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(key)
        decrypted_msg = cipher_rsa.decrypt(encrypted_msg)
        return decrypted_msg
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# Performance Testing
def measure_performance():
    key_sizes = [1024, 2048, 4096]
    message_sizes = [32, 64, 128, 256]
    encryption_times = {size: [] for size in key_sizes}
    decryption_times = {size: [] for size in key_sizes}
    cpu_usage = {size: [] for size in key_sizes}

    for key_size in key_sizes:
        private_key, public_key = generate_rsa_keypair(key_size)
        for msg_size in message_sizes:
            message = b"A" * msg_size

            # Measure encryption time
            start_time = time.time()
            encrypted_msg = rsa_encrypt(message, public_key)
            encryption_times[key_size].append(time.time() - start_time)

            # Measure decryption time
            start_time = time.time()
            decrypted_msg = rsa_decrypt(encrypted_msg, private_key)
            decryption_times[key_size].append(time.time() - start_time)

            # Measure CPU utilization
            cpu_usage[key_size].append(psutil.cpu_percent(interval=0.1))

    # Plot results
    plot_performance(message_sizes, encryption_times, decryption_times, cpu_usage)

def plot_performance(message_sizes, encryption_times, decryption_times, cpu_usage):
    plt.figure()
    for key_size in encryption_times:
        plt.plot(message_sizes, encryption_times[key_size], label=f'Encryption ({key_size}-bit)')
    plt.xlabel('Message Size (bytes)')
    plt.ylabel('Time (s)')
    plt.legend()
    plt.title('RSA Encryption Performance')
    plt.show()

    plt.figure()
    for key_size in decryption_times:
        plt.plot(message_sizes, decryption_times[key_size], label=f'Decryption ({key_size}-bit)')
    plt.xlabel('Message Size (bytes)')
    plt.ylabel('Time (s)')
    plt.legend()
    plt.title('RSA Decryption Performance')
    plt.show()

    plt.figure()
    for key_size in cpu_usage:
        plt.plot(message_sizes, cpu_usage[key_size], label=f'CPU Usage ({key_size}-bit)')
    plt.xlabel('Message Size (bytes)')
    plt.ylabel('CPU Usage (%)')
    plt.legend()
    plt.title('CPU Utilization During RSA Operations')
    plt.show()

# Security Analysis and Mitigation
## Potential Vulnerabilities:
# 1. Small key sizes (1024-bit) are vulnerable to brute-force attacks
# 2. Side-channel attacks (timing attacks, power analysis)
# 3. Padding oracle attacks on improper implementations

## Mitigation Strategies:
# 1. Use at least 2048-bit keys (preferably 4096-bit for long-term security)
# 2. Implement constant-time algorithms to resist timing attacks
# 3. Use OAEP padding to prevent padding oracle attacks

# Test Cases
def test_rsa():
    print("Running test cases...")
    private_key, public_key = generate_rsa_keypair(2048)

    sample_messages = [b"Hello, RSA!", b"Short message", b"This is a longer message that we will encrypt using RSA to test its performance.", b""]

    for msg in sample_messages:
        print(f"Original message: {msg}")
        encrypted_msg = rsa_encrypt(msg, public_key)
        print(f"Encrypted message: {encrypted_msg}")
        decrypted_msg = rsa_decrypt(encrypted_msg, private_key)
        print(f"Decrypted message: {decrypted_msg}")
        assert decrypted_msg == msg, "Decryption failed!"
        print("Test passed.\n")

    print("All tests completed successfully.")

# Run performance tests and test cases
if __name__ == "__main__":
    test_rsa()
    measure_performance()
