import os
import shutil
import threading
import yara
import time
from datetime import datetime, timedelta
import zipfile
import requests
from cipher import generate_key, vigenere_encrypt
from hashing import simple_hash

# API configuration
API_KEY = 'API_KEY_HERE'  # Ensure to replace with your actual API key
API_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
API_UPLOAD_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'

def load_yara_rules():
    yara_rules_file = os.path.join(os.path.dirname(__file__), 'yara_rules.yar')
    print("\nYARA Rules Status:")
    print(f"Attempting to load YARA rules from: {yara_rules_file}")
    try:
        rules = yara.compile(filepath=yara_rules_file)
        print("Status: Loading Completed")
        return rules
    except yara.SyntaxError as e:
        print(f"Status: Error loading YARA rules: {e}")
        return None
    except Exception as e:
        print(f"Status: An error occurred: {e}")
        return None

def monitor_files_with_yara(rules, directory):
    print("\nMonitoring Directory:")
    print(f"Directory: {directory}")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file.startswith('.') or file == "yara_rules.yar":
                continue
            if not os.path.exists(file_path):
                print(f"File not found: {file_path}")
                continue
            try:
                matches = rules.match(file_path)
                if matches:
                    print(f"Yara Alert: {matches} in {file_path}")
                    handle_yara_alert(file_path)
            except yara.Error as e:
                print(f"Error scanning file {file_path} with YARA: {e}")

def handle_yara_alert(file_path):
    print("\nHandling Yara alert for:", file_path)
    try:
        file_hash = simple_hash(file_path)  # Using imported hashing function
        result = scan_file(file_hash)
        if result:
            severity = categorize_result(result)
            print(f"Severity: {severity}")
            if severity in ['Severe', 'Extreme']:
                isolate_and_test_malware(file_path)
        else:
            print("Failed to scan the file. Malware test cannot be performed.")
    except Exception as e:
        print(f"Error handling file {file_path}: {e}")

def scan_file(file_hash):
    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(API_URL, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error {response.status_code} scanning file hash {file_hash}: {response.text}")
        return None

def categorize_result(result):
    """Categorize the result based on community score."""
    if result is None:
        return 'Error: No data available'
    positives = result.get('positives')
    total = result.get('total')
    if positives is None or total is None:
        print(f"Incomplete data in result: {result}")
        return 'Error: Incomplete data'
    score = positives / total * 100
    if score == 0:
        return 'Benign'
    elif score < 10:
        return 'Mild'
    elif score < 20:
        return 'Severe'
    else:
        return 'Extreme'

def isolate_and_test_malware(file_path):
    """Isolate the flagged file and perform malware tests."""
    secure_location = './isolated_files'
    if not os.path.exists(secure_location):
        os.makedirs(secure_location)
    try:
        shutil.move(file_path, os.path.join(secure_location, os.path.basename(file_path)))
        print(f"File {file_path} isolated for malware testing.")
        file_hash = simple_hash(os.path.join(secure_location, os.path.basename(file_path)))
        result = scan_file(file_hash)
        if result:
            severity = categorize_result(result)
            print(f"Malware Test Result: {severity}")
            if severity in ['Severe', 'Extreme']:
                print(f"Malware detected! Deleting file: {file_path}")
                os.remove(os.path.join(secure_location, os.path.basename(file_path)))
            else:
                print("File is not identified as malware.")
        else:
            print("Malware test failed.")
    except Exception as e:
        print(f"Error isolating and testing malware for file {file_path}: {e}")

def rotate_keys():
    directory_to_encrypt = os.path.join(os.path.dirname(__file__), '..', 'logs', 'important_logs')
    new_key = generate_key()
    print(f"\nNew encryption key generated. Rotating keys in directory: {directory_to_encrypt}")
    try:
        for filename in os.listdir(directory_to_encrypt):
            file_path = os.path.join(directory_to_encrypt, filename)
            with open(file_path, 'r') as file:
                file_contents = file.read()
            encrypted_contents = vigenere_encrypt(file_contents, new_key)
            with open(file_path, 'w') as file:
                file.write(encrypted_contents)
        # Move the print statement here to confirm completion of the entire directory
        print(f"\nRe-encrypted {directory_to_encrypt} with new key.")
    except Exception as e:
        print(f"\nFailed to encrypt {directory_to_encrypt}: {e}")

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

def backup_hourly_files():
    source_directory = os.path.join(os.path.dirname(__file__), '..', 'logs', 'important_logs')
    backup_directory = os.path.join(os.path.dirname(__file__), 'backup_directory', 'hourly_backups')
    # Ensure the backup directory exists
    if not os.path.exists(backup_directory):
        os.makedirs(backup_directory)
    print(f"\nHourly Backup Status: Backing up files from {source_directory} to {backup_directory}")
    try:
        # Create a unique filename for the backup based on the current timestamp
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        hourly_backup_file = os.path.join(backup_directory, f"hourly_backup_{timestamp}.zip")
        with zipfile.ZipFile(hourly_backup_file, 'w') as zipf:
            for root, dirs, files in os.walk(source_directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, start=os.path.dirname(source_directory)))
        print(f"\nBackup Status: Hourly backup completed.")
    except Exception as e:
        print(f"\nBackup Status: Failed to backup hourly items from {source_directory}: {e}")

def main():
    rules = load_yara_rules()
    if not rules:
        return

    monitored_directory = os.path.join(os.path.dirname(__file__), '..', 'logs', 'important_logs')
    key_rotation_interval_seconds = 3600  # Rotate keys every hour

    threading.Thread(target=monitor_files_with_yara, args=(rules, monitored_directory), daemon=True).start()
    threading.Thread(target=backup_hourly_files, daemon=True).start()
    threading.Thread(target=rotate_keys, args=(), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down MTD system...")

if __name__ == "__main__":
    main()
