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
API_KEY = '71167f90aa45e318c20e4708ea715dd76990f263d8b146fa4080b60d10f69c6d'  # do not steal my api key i stg
API_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
API_UPLOAD_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'

file_locations = {}
backups_completed = False  # Flag to track if backups have been completed

def load_yara_rules():
    yara_rules_file = os.path.join(os.path.dirname(__file__), 'yara_rules.yar')
    try:
        rules = yara.compile(filepath=yara_rules_file)
        print(f"\nYARA Rules Status: \n-> Attempting to load YARA rules from: {yara_rules_file}\n-> YARA Status: Loading Completed")
        return rules
    except yara.SyntaxError as e:
        print(f"f\nYARA Rules Status: \n-> Attempting to load YARA rules from: {yara_rules_file}\n-> YARA Status: Error loading YARA rules: {e}")
        return None
    except Exception as e:
        print(f"f\nYARA Rules Status: \n-> Attempting to load YARA rules from: {yara_rules_file}\n-> YARA Status: An error occurred: {e}")
        return None

def monitor_files_with_yara(rules, directory):
    global backups_completed  # Access the global flag
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            # Skip files that have been moved or are not to be scanned
            if file_path in file_locations or file.startswith('.') or file == "yara_rules.yar":
                continue
            try:
                matches = rules.match(file_path)
                if matches:
                    print(f"\nMonitoring Directory: \n-> Directory:{directory}\n->Yara Alert: {matches} in {file_path}")
                    handle_yara_alert(file_path)
            except yara.Error as e:
                print(f"\nMonitoring Directory: \n-> Directory:{directory}\n->Error scanning file {file_path} with YARA: {e}")

def handle_yara_alert(file_path):
    global file_locations
    print("\nHandling Yara alert for:", file_path)
    if os.path.exists(file_path):
        new_path = isolate_file_for_testing(file_path)
        file_locations[file_path] = new_path
        test_malware(new_path)
    else:
        print(f"File no longer exists at path: {file_path}")

def isolate_file_for_testing(file_path):
    secure_location = os.path.join(os.path.dirname(__file__), '..', 'isolated_yara_alerted_files')
    if not os.path.exists(secure_location):
        os.makedirs(secure_location)
    new_path = os.path.join(secure_location, os.path.basename(file_path))
    if os.path.exists(file_path):  # Check if file still exists before moving
        shutil.move(file_path, new_path)
        return new_path
    else:
        print(f"Failed to move, file does not exist: {file_path}")
        return file_path  # Return original path if move fails

def test_malware(file_path):
    if backups_completed:  # Perform this operation only after backups are completed
        file_hash = simple_hash(file_path)
        result = scan_file(file_hash)
        if result:
            severity = categorize_result(result)
            print(f"File: {file_path} - Severity: {severity}")
            if severity in ['Severe', 'Extreme']:
                response = input("Delete isolated file? Type 'Accept' to confirm: ")
                if response == "Accept":
                    os.remove(file_path)
                    print("File deleted.")
            else:
                response = input("Restore file? Type 'Accept' to confirm: ")
                if response == "Accept":
                    restore_file(file_path)
        else:
            print(f"Malware test failed for: {file_path}")

def scan_file(file_hash):
    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(API_URL, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error {response.status_code} scanning file hash {file_hash}: {response.text}")
        return None

def categorize_result(result):
    if result is None:
        return 'Error: No data available'
    positives = result.get('positives')
    total = result.get('total')
    if positives is None or total is None:
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

def restore_file(file_path):
    original_location = [k for k, v in file_locations.items() if v == file_path]
    if original_location:
        shutil.move(file_path, original_location[0])
        print(f"File restored to original location: {original_location[0]}")

def rotate_keys():
    global backups_completed  # Access the global flag
    directory_to_encrypt = os.path.join(os.path.dirname(__file__), '..', 'logs', 'important_logs')
    if backups_completed:  # Perform this operation only after backups are completed
        new_key = generate_key()
        try:
            for filename in os.listdir(directory_to_encrypt):
                file_path = os.path.join(directory_to_encrypt, filename)
                with open(file_path, 'r') as file:
                    file_contents = file.read()
                encrypted_contents = vigenere_encrypt(file_contents, new_key)
                with open(file_path, 'w') as file:
                    file.write(encrypted_contents)
            # Move the print statement here to confirm completion of the entire directory
            print(f"\nRotating Keys:\n-> New encryption key generated.\n-> Rotating keys in directory: {directory_to_encrypt}\n-> Re-encrypted {directory_to_encrypt} with new key.")
        except Exception as e:
            print(f"\nRotating Keys:\n-> New encryption key generated. \n-> Rotating keys in directory: {directory_to_encrypt}\n-> Failed to encrypt {directory_to_encrypt}: {e}")

def backup_hourly_files():
    source_directory = os.path.join(os.path.dirname(__file__), '..', 'logs', 'important_logs')
    backup_directory = os.path.join(os.path.dirname(__file__), 'backup_directory', 'hourly_backups')
    # Ensure the backup directory exists
    if not os.path.exists(backup_directory):
        os.makedirs(backup_directory)
    try:
        # Create a unique filename for the backup based on the current timestamp
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        hourly_backup_file = os.path.join(backup_directory, f"hourly_backup_{timestamp}.zip")
        with zipfile.ZipFile(hourly_backup_file, 'w') as zipf:
            for root, dirs, files in os.walk(source_directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, start=os.path.dirname(source_directory)))
        print(f"\nHourly Backup Status:\n->Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Hourly backup completed.")
    except Exception as e:
        print(f"\nHourly Backup Status:\n->Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Failed to backup hourly items from [{source_directory}]: {e}")

def backup_daily_files():
    global backups_completed  # Access the global flag
    while True:
        # Calculate the next backup time for the next day at a specific time (e.g., 2:00 AM)
        next_backup_time = datetime.now().replace(hour=2, minute=0, second=0, microsecond=0)
        if datetime.now() > next_backup_time:
            # Create the backup immediately if the current time has passed the scheduled backup time
            create_daily_backup()
            backups_completed = True  # Set flag to indicate backups are completed
            # Schedule the next backup for the next day at the same time
            next_backup_time += timedelta(days=1)
        # Calculate the time to sleep until the next backup
        time_to_sleep = (next_backup_time - datetime.now()).total_seconds()
        # Sleep until the next backup time
        time.sleep(time_to_sleep)

def create_daily_backup():
    # Define the source directory to be backed up
    source_directory = os.path.join(os.path.dirname(__file__), '..', 'logs', 'important_logs')
    # Define the backup directory for daily backups
    backup_directory = os.path.join(os.path.dirname(__file__), 'backup_directory', 'daily_backups')
    # Ensure the backup directory exists
    if not os.path.exists(backup_directory):
        os.makedirs(backup_directory)
    # Create a unique filename for the daily backup based on the current date
    backup_filename = datetime.now().strftime("%Y-%m-%d") + "_db.zip"
    # Create the full path for the backup file
    backup_filepath = os.path.join(backup_directory, backup_filename)
    try:
        # Create a ZIP file containing the contents of the source directory
        with zipfile.ZipFile(backup_filepath, 'w') as backup_zip:
            for root, _, files in os.walk(source_directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    backup_zip.write(file_path, os.path.relpath(file_path, source_directory))
        print(f"\nDaily Backup Status:\n-> Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Daily backup completed.")
    except Exception as e:
        print(f"\nDaily Backup Status:\n-> Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Failed to create daily backup: {e}")


def main():
    rules = load_yara_rules()
    if not rules:
        return

    monitored_directory = os.path.join(os.path.dirname(__file__), '..', 'logs', 'important_logs')
    key_rotation_interval_seconds = 3600  # Rotate keys every hour

    threading.Thread(target=monitor_files_with_yara, args=(rules, monitored_directory), daemon=True).start()
    threading.Thread(target=backup_hourly_files, daemon=True).start()
    threading.Thread(target=rotate_keys, args=(), daemon=True).start()
    threading.Thread(target=backup_daily_files, daemon=True).start()  # Start the daily backup thread

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down MTD system...")

if __name__ == "__main__":
    main()
