import hashlib
import os
import json

# File to store user data
USER_DATA_FILE = "users.json"

# Load user data from file
def load_users():
    if not os.path.exists(USER_DATA_FILE):
        return {}
    with open(USER_DATA_FILE, "r") as file:
        return json.load(file)

# Save user data to file
def save_users(users):
    with open(USER_DATA_FILE, "w") as file:
        json.dump(users, file)

# Hash password with SHA-256 and a salt
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32).hex()  # Generate a random salt
    hash_obj = hashlib.sha256((salt + password).encode())
    return salt, hash_obj.hexdigest()

# Register a new user
def register(username, password):
    users = load_users()
    if username in users:
        print("Username already exists!")
        return False
    salt, hashed_password = hash_password(password)
    users[username] = {"salt": salt, "password": hashed_password}
    save_users(users)
    print("User registered successfully!")
    return True

# Authenticate a user
def login(username, password):
    users = load_users()
    if username not in users:
        print("Invalid username or password!")
        return False
    salt = users[username]["salt"]
    hashed_password = hash_password(password, salt)[1]
    if hashed_password == users[username]["password"]:
        print("Login successful!")
        return True
    else:
        print("Invalid username or password!")
        return False

# Example usage
if __name__ == "__main__":
    while True:
        choice = input("Do you want to Register or Login? (Q to quit): ").strip().lower()
        if choice == 'r':
            user = input("Enter username: ")
            pwd = input("Enter password: ")
            register(user, pwd)
        elif choice == 'l':
            user = input("Enter username: ")
            pwd = input("Enter password: ")
            login(user, pwd)
        elif choice == 'q':
            break
        else:
            print("Invalid option! Choose R, L, or Q.")
