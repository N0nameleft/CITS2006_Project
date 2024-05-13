import os
import shutil
import threading
import yara
import time
from datetime import datetime, timedelta
import random
import string

def load_yara_rules():
    yara_rules_file = os.path.join(os.path.dirname(__file__), 'yara_rules.yar')
    print(f"Attempting to load YARA rules from: {yara_rules_file}")
    try:
        return yara.compile(filepath=yara_rules_file)
    except yara.SyntaxError as e:
        print(f"Error loading YARA rules: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def monitor_files_with_yara(rules, directory):
    print(f"Monitoring directory: {directory}")  # Debug print
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            matches = rules.match(file_path)
            if matches:
                print(f"Yara Alert: {matches} in {file_path}")
                handle_yara_alert(file_path)

def handle_yara_alert(file_path):
    print("Handling Yara alert for:", file_path)
    if not check_permission(file_path):
        revert_changes(file_path)
    rotate_keys()

def generate_key(length=50):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def vigenere_encrypt(plaintext, key):
    encrypted_text = []
    key_length = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = (ord(key[i % key_length]) - ord('a')) % 26
            if char.islower():
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            encrypted_char = char
        encrypted_text.append(encrypted_char)
    return ''.join(encrypted_text)

def rotate_keys():
    directory_to_encrypt = os.path.join(os.path.dirname(__file__), '..', 'logs', 'important_logs')
    new_key = generate_key()
    print(f"New encryption key generated. Rotating keys in directory: {directory_to_encrypt}")
    try:
        for filename in os.listdir(directory_to_encrypt):
            file_path = os.path.join(directory_to_encrypt, filename)
            with open(file_path, 'r') as file:
                file_contents = file.read()
            encrypted_contents = vigenere_encrypt(file_contents, new_key)
            with open(file_path, 'w') as file:
                file.write(encrypted_contents)
            print(f"Re-encrypted {file_path} with new key.")
    except Exception as e:
        print(f"Failed to encrypt {file_path}: {e}")

def check_permission(file_path):
    authorized_changes = {}
    try:
        with open('authorized_changes.log', 'r') as log:
            for line in log:
                path, status = line.strip().split(',')
                authorized_changes[path] = status
    except FileNotFoundError:
        print("Authorization log not found.")
        return False
    return authorized_changes.get(file_path, 'unauthorized') == 'authorized'

def revert_changes(file_path):
    backup_directory = os.path.join(os.path.dirname(__file__), 'backup_directory', 'backups')
    backup_file_path = os.path.join(backup_directory, os.path.basename(file_path))
    try:
        if os.path.exists(backup_file_path):
            shutil.copy(backup_file_path, file_path)
            print(f"Reverted changes for {file_path}")
        else:
            print(f"No backup found for {file_path}")
    except Exception as e:
        print(f"Failed to revert changes for {file_path}: {e}")

def backup_files():
    source_directory = os.path.join(os.path.dirname(__file__), '..', 'logs', 'important_logs')
    backup_directory = os.path.join(os.path.dirname(__file__), 'backup_directory', 'backups')
    # Ensure the backup directory exists
    if not os.path.exists(backup_directory):
        os.makedirs(backup_directory)
    print(f"Backing up files from {source_directory} to {backup_directory}")  # Debug print
    try:
        items_to_backup = os.listdir(source_directory)
        for item in items_to_backup:
            source_item = os.path.join(source_directory, item)
            # Check if it's a file and handle accordingly
            if os.path.isfile(source_item):
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                backup_file = os.path.join(backup_directory, f"{timestamp}_{item}")
                shutil.copy2(source_item, backup_file)
                print(f"Backed up file {source_item} to {backup_file}")
            else:
                print(f"Skipped {source_item}, not a file.")
    except Exception as e:
        print(f"Failed to backup items from {source_directory}: {e}")
        

def schedule_key_rotation(interval_seconds):
    next_rotation = datetime.now() + timedelta(seconds=interval_seconds)
    while True:
        if datetime.now() >= next_rotation:
            rotate_keys()
            next_rotation = datetime.now() + timedelta(seconds=interval_seconds)
        time.sleep(10)

if __name__ == "__main__":
    rules = load_yara_rules()
    monitored_directory = os.path.join(os.path.dirname(__file__), '..', 'logs', 'important_logs')
    key_rotation_interval_seconds = 3600  # Rotate keys every hour

    threading.Thread(target=monitor_files_with_yara, args=(rules, monitored_directory), daemon=True).start()
    threading.Thread(target=backup_files, daemon=True).start()
    threading.Thread(target=schedule_key_rotation, args=(key_rotation_interval_seconds,), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down MTD system...")
