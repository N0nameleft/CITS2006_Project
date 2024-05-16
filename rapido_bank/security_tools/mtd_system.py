import os 
import shutil
import threading
import yara
import time
from datetime import datetime, timedelta
import requests
from cipher import generate_key, vigenere_encrypt
from create_encryption_keys import create_keys_for_portfolio, create_project_key_and_encrypt
from yara_engine import load_yara_rules, scan_file, start_yara_engine
from hashing import simple_hash

# API configuration
API_KEY = os.getenv('YARA_API_KEY')
API_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
API_UPLOAD_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'

file_locations = {}
backups_completed = False  # Flag to track if backups have been completed



def handle_yara_alert(file_path):
    """Handle actions based on YARA alerts detected in files."""
    print("\nHandling Yara alert for:", file_path)
    if not os.path.exists(file_path):
        print(f"File no longer exists at path: {file_path}")
        return

    rules = load_yara_rules()
    matches = scan_file(rules, file_path)  # Use the function from yara_engine
    if matches:
        new_path = isolate_file_for_testing(file_path)
        file_locations[file_path] = new_path
        test_malware(new_path)
    else:
        print(f"No YARA matches or file ignored: {file_path}")

def isolate_file_for_testing(file_path):
    """Isolate the suspicious file for further investigation."""
    secure_location = os.path.join(os.path.dirname(__file__), '..', 'isolated_yara_alerted_files')
    if not os.path.exists(secure_location):
        os.makedirs(secure_location)
    new_path = os.path.join(secure_location, os.path.basename(file_path))
    shutil.move(file_path, new_path)
    print(f"File isolated to {new_path}")
    return new_path

def test_malware(file_path):
    """Test the isolated file for malware."""
    file_hash = simple_hash(file_path)
    result = scan_file(file_hash)
    if result:
        severity = categorize_result(result)
        print(f"File: {file_path} - Severity: {severity}")
        handle_severity(file_path, severity)
    else:
        print(f"Malware test failed for: {file_path}")

def handle_severity(file_path, severity):
    """Take action based on the severity of the malware detection."""
    if severity in ['Severe', 'Extreme']:
        os.remove(file_path)
        print("File deleted due to severe threat.")
    elif severity == 'Mild':
        restore_file(file_path)

def categorize_result(result):
    """Categorize the API response into severity levels."""
    if result is None:
        return 'Error: No data available'
    positives = result.get('positives', 0)
    total = result.get('total', 1)
    score = (positives / total) * 100
    return 'Extreme' if score > 20 else 'Severe' if score > 10 else 'Mild' if score > 0 else 'Benign'

def restore_file(file_path):
    """Restore the original file location from backup."""
    original_location = file_locations.get(file_path)
    if original_location:
        shutil.move(file_path, original_location)
        print(f"File restored to original location: {original_location}")


def rotate_keys():
    global backups_completed  # Access the global flag
    directory_to_encrypt = '/opt/rapido_bank'
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
    source_directory = '/opt/rapido_bank/'
    backup_directory = '/opt/rapido_bank/backups'
    
    # Ensure the backup directory exists
    if not os.path.exists(backup_directory):
        os.makedirs(backup_directory)
    
    while True:
        
        try:
            # Delete any existing backup directories ending with '_hb'
            for dirname in os.listdir(backup_directory):
                if dirname.endswith('_hb'):
                    dir_path = os.path.join(backup_directory, dirname)
                    if os.path.isdir(dir_path):
                        shutil.rmtree(dir_path)
            
            # Create the directory for the current hourly backup
            hourly_backup_dir = os.path.join(backup_directory, f"{datetime.now().strftime('%Y%m%d%H%m%s')}_hb")
            os.makedirs(hourly_backup_dir)
            
            for dirpath, dirnames, filenames in os.walk(source_directory):
                # Skip the backup directory
                if os.path.commonpath([dirpath, backup_directory]) == backup_directory:
                    continue
                
                for filename in filenames:
                    source_item = os.path.join(dirpath, filename)
                    # Ensure the target backup path mirrors the source structure
                    relative_path = os.path.relpath(dirpath, source_directory)
                    target_directory = os.path.join(hourly_backup_dir, relative_path)
                    
                    # Create target directory if it doesn't exist
                    if not os.path.exists(target_directory):
                        os.makedirs(target_directory)
                    
                    target_item = os.path.join(target_directory, filename)
                    # Copy the file to the backup directory
                    shutil.copy2(source_item, target_item)
                
            print(f"\nHourly Backup Status:\n-> Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Hourly backup completed.")

                        
            
        except Exception as e:
                print(f"\nHourly Backup Status:\n-> Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Hourly backup completed.")
        
        # Sleep for an hour before the next backup
        time.sleep(3600)



def backup_daily_files():
    source_directory = '/opt/rapido_bank/'
    backup_directory = '/opt/rapido_bank/backups'

    while True:
        # Calculate the next backup time for the next day at 2:00 AM
        next_backup_time = datetime.now().replace(hour=0, minute=0, second=0)
        if datetime.now() > next_backup_time:
            # Adjust the next backup time to the next day at 2:00 AM
            next_backup_time += timedelta(days=1)
        
        # Calculate the time to sleep until the next backup
        time_to_sleep = (next_backup_time - datetime.now()).total_seconds()

        try:
            # Create or override the directory for the current daily backup
            daily_backup_dir = os.path.join(backup_directory, f"{datetime.now().strftime('%Y-%m-%d')}_db")

            if not os.path.exists(daily_backup_dir):
                os.makedirs(daily_backup_dir)

            for dirpath, dirnames, filenames in os.walk(source_directory):
                if os.path.commonpath([dirpath, backup_directory]) == backup_directory:
                    continue
                for filename in filenames:
                    source_item = os.path.join(dirpath, filename)
                    # Ensure the target backup path mirrors the source structure
                    relative_path = os.path.relpath(dirpath, source_directory)
                    target_directory = os.path.join(daily_backup_dir, relative_path)
                    
                    # Create target directory if it doesn't exist
                    if not os.path.exists(target_directory):
                        os.makedirs(target_directory)
                    
                    target_item = os.path.join(target_directory, filename)
                    # Copy the file to the backup directory
                    shutil.copy2(source_item, target_item)
            
            print(f"\nDaily Backup Status:\n-> Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Daily backup completed.")
    
        except Exception as e:
            print(f"\nDaily Backup Status:\n-> Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Failed to create daily backup: {e}")

        # Sleep until the next backup time
        time.sleep(time_to_sleep)

def schedule_key_regeneration(interval_hours=2):
    """Schedule key regeneration every specified number of hours."""
    while True:
        # Assuming these functions accept the directory and admin keys path
        create_project_key_and_encrypt('/opt/rapido_bank', 'rapido_bank/admin/encryption_keys')
        create_keys_for_portfolio('rapido_bank/portfolios', 'rapido_bank/admin/encryption_keys')
        print(f"Keys regenerated, next regeneration in {interval_hours} hours.")
        time.sleep(interval_hours * 3600)


### I will fix these issues of the function names####

def start_mtd():
    """Starts the Malware Threat Detection (MTD) system and all associated processes."""
    print("Initializing MTD system...")

    # Start the YARA engine in a separate thread to begin scanning.
    threading.Thread(target=start_yara_engine, daemon=True).start()

    # Start automated key rotation for both project-wide and individual portfolios.
    threading.Thread(target=schedule_key_regeneration, args=(2,), daemon=True).start()

    # Start the routines for rotating encryption keys across sensitive directories.
    threading.Thread(target=rotate_keys, daemon=True).start()

    # Initiate continuous backup processes: daily and hourly.
    threading.Thread(target=backup_daily_files, daemon=True).start()
    threading.Thread(target=backup_hourly_files, daemon=True).start()

    try:
        # Keep the main thread alive to maintain daemon threads.
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down MTD system...")

if __name__ == "__main__":
    start_mtd()