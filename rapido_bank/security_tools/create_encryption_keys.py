import os
import shutil
from cryptography.fernet import Fernet
import time
from datetime import datetime

def generate_key():
    """ Generate and return a Fernet encryption key. """
    return Fernet.generate_key()

def save_key(key, filename):
    """ Save the key to a specified file. """
    with open(filename, 'wb') as file:
        file.write(key)
    print(f"Key saved to {filename}")

def get_timestamped_filename(base_dir, prefix, extension):
    """ Generate a timestamped filename for storing keys. """
    timestamp = datetime.now().strftime('%Y%m%d%H%M')
    return os.path.join(base_dir, f"{prefix}_{timestamp}.{extension}")

def encrypt_directory(directory, key, key_path):
    """ Encrypt all files in a given directory with the provided key and log the encryption. """
    fernet = Fernet(key)
    print(f"Starting encryption of directory {directory} using key {key_path}")
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as file:
                original = file.read()
            encrypted = fernet.encrypt(original)
            with open(file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted)
            print(f"Encrypted {file_path}")
    print(f"Encryption complete for directory {directory}")

def start_key_rotation():
    """ Start the key rotation for project and portfolios, and encrypt directories. """
    threading.Thread(target=lambda: create_project_key_and_encrypt('some_project_directory'), daemon=True).start()
    threading.Thread(target=lambda: create_portfolio_keys_and_encrypt('portfolios'), daemon=True).start()

def create_project_key_and_encrypt(directory):
    while True:
        key = generate_key()
        key_path = get_timestamped_filename('admin/encryption_keys', 'project_key', 'key')
        save_key(key, key_path)
        encrypt_directory(directory, key, key_path)
        print(f"Project key regenerated and applied. Next update in 4 hours.")
        time.sleep(14400)

def create_portfolio_keys_and_encrypt(portfolio_dir):
    while True:
        for person in os.listdir(portfolio_dir):
            person_dir = os.path.join(portfolio_dir, person)
            if os.path.isdir(person_dir):
                key = generate_key()
                key_path = get_timestamped_filename(person_dir, 'encryption_key', 'key')
                save_key(key, key_path)
                encrypt_directory(person_dir, key, key_path)
                admin_key_path = get_timestamped_filename('admin/encryption_keys', f'{person}_key', 'key')
                shutil.copy(key_path, admin_key_path)
                print(f"Encryption key for {person} regenerated and applied.")
        print("All portfolio keys regenerated. Next update in 4 hours.")
        time.sleep(14400)

if __name__ == "__main__":
    print("Starting MTD system key rotation and encryption...")
    start_key_rotation()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down MTD system...")
