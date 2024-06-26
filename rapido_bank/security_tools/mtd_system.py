import os
import shutil
import threading
import time
import argparse
from datetime import datetime, timedelta
from cipher import generate_key, vigenere_encrypt
from create_encryption_keys import create_keys_for_portfolio, create_project_key_and_encrypt, initialize_encryption_keys
from yara_engine import load_yara_rules, scan_file, start_yara_engine
from hashing import hash_file
from get_nonauthorized_users import *
from security_recom import log_event

# API configuration
API_KEY = os.getenv('YARA_API_KEY')
API_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
API_UPLOAD_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'

file_locations = {}
backups_completed = False  # Flag to track if backups have been completed

def simple_hash(file_path):
    """A simplified wrapper to use hash_file from hashing.py."""
    return hash_file(file_path)

def handle_yara_alert(file_path, verbose):
    """Handle actions based on YARA alerts detected in files."""
    if verbose:
        print("\nHandling Yara alert for:", file_path)
        """----------security recommendation------------"""
        log_event('YARA Alert', f"File {file_path} matched YARA rules.")
        """---------------------------------------------"""
        
    if not os.path.exists(file_path):
        if verbose:
            print(f"File no longer exists at path: {file_path}")
            """----------security recommendation------------"""
            log_event('YARA Alert - file non-exist', f"File {file_path} matched YARA rules, but does not exist anymore.")
            """---------------------------------------------"""
        return

    rules = load_yara_rules()
    matches = scan_file(rules, file_path)  # Use the function from yara_engine
    if matches:
        new_path = isolate_file_for_testing(file_path, verbose)
        file_locations[file_path] = new_path
        test_malware(new_path, verbose)
    elif verbose:
        print(f"No YARA matches or file ignored: {file_path}")
        """----------security recommendation------------"""
        log_event('YARA Alert - no matching rules', f"File {file_path} raised YARA alert but did not match any rules.")
        """---------------------------------------------"""

def isolate_file_for_testing(file_path, verbose):
    """Isolate the suspicious file for further investigation."""
    secure_location = os.path.join(os.path.dirname(__file__), '..', 'isolated_yara_alerted_files')
    if not os.path.exists(secure_location):
        os.makedirs(secure_location)
    new_path = os.path.join(secure_location, os.path.basename(file_path))
    shutil.move(file_path, new_path)
    if verbose:
        print(f"File isolated to {new_path}")
        """----------security recommendation------------"""
        log_event('Isolated File', f"File {file_path} has been isolated due to highly suspicious.")
        """---------------------------------------------"""
    return new_path

def test_malware(file_path, verbose):
    """Test the isolated file for malware."""
    file_hash = simple_hash(file_path)
    result = scan_file(file_hash)
    if result:
        severity = categorize_result(result)
        if verbose:
            print(f"File: {file_path} - Severity: {severity}")
            """----------security recommendation------------"""
            log_event('Malware Test', f"File {file_path} tested positive. Severity: {severity}.")
            """---------------------------------------------"""
        handle_severity(file_path, severity, verbose)
    elif verbose:
        print(f"Malware test failed for: {file_path}")
        """----------security recommendation------------"""
        log_event('Malware Test - Failed', f"File {file_path} was not able to be detected by malware test.")
        """---------------------------------------------"""

def handle_severity(file_path, severity, verbose):
    """Take action based on the severity of the malware detection."""
    if severity in ['Severe', 'Extreme']:
        os.remove(file_path)
        if verbose:
            print("File deleted due to severe threat.")
            """----------security recommendation------------"""
            log_event('File Deletion', f"File {file_path} deleted due to severity: {severity}.")    
            """---------------------------------------------"""
    elif severity == 'Mild':
        restore_file(file_path, verbose)

def categorize_result(result):
    """Categorize the API response into severity levels."""
    if result is None:
        return 'Error: No data available'
    positives = result.get('positives', 0)
    total = result.get('total', 1)
    score = (positives / total) * 100
    return 'Extreme' if score > 20 else 'Severe' if score > 10 else 'Mild' if score > 0 else 'Benign'

def restore_file(file_path, verbose):
    """Restore the original file location from backup."""
    original_location = file_locations.get(file_path)
    if original_location:
        shutil.move(file_path, original_location)
        if verbose:
            print(f"File restored to original location: {original_location}")
            """----------security recommendation------------"""
            log_event('File Restoration', f"File {file_path} restored to original location: {original_location}.")
            """---------------------------------------------"""

def rotate_keys(verbose):
    """ Rotate keys by re-encrypting data with the latest generated keys from a specified directory. """
    global backups_completed
    if not backups_completed:
        if verbose:
            print("Backups not completed. Key rotation deferred.")
            """----------security recommendation------------"""
            log_event('Backup Needed', "Backups not completed. Key rotation deferred.")
            """---------------------------------------------"""
        return

    # Path where the latest keys are stored
    key_directory = '/opt/rapido_bank/admin/encryption_keys'
    directory_to_encrypt = '/opt/rapido_bank'

    security_events_log = '/opt/rapido_bank/logs/important_logs/security_events.log'

    try:
        for root, dirs, files in os.walk(directory_to_encrypt):
            # Ensure the file is not in a directory to skip
            if any(skip in root for skip in ['backups', 'shared', 'security_tools', 'portfolios', 'admin/encryption_keys']):
                continue

            for filename in files:
                file_path = os.path.join(root, filename)

                # Exclude specific files from encryption
                if file_path == security_events_log or file_path.endswith('.key'):  # Skip encryption key and security log file
                    continue

                # Attempt to find a key file that matches this directory or file
                possible_key_files = [k for k in os.listdir(key_directory) if 'project_key' in k]
                if not possible_key_files:
                    if verbose:
                        print("No encryption keys available.")
                        """----------security recommendation------------"""
                        log_event('Key not Found', "key not found.")
                        """---------------------------------------------"""
                    continue

                # Sort to get the latest key file
                latest_key_file = sorted(possible_key_files)[-1]
                key_path = os.path.join(key_directory, latest_key_file)
                
                # Read the latest key
                with open(key_path, 'r') as kf:
                    key = kf.read()

                # Encrypt the file
                with open(file_path, 'r') as file:
                    file_contents = file.read()
                encrypted_contents = vigenere_encrypt(file_contents, key)
                with open(file_path, 'w') as file:
                    file.write(encrypted_contents)

        if verbose:
            print(f"Rotated keys using the latest available keys for all files in {directory_to_encrypt} except for the key file and security events log.")
            """----------security recommendation------------"""
            log_event('Key Rotation', f"Keys rotated for all files in {directory_to_encrypt} except for the key file and security events log.")
            """---------------------------------------------"""

    except Exception as e:
        if verbose:
            print(f"Error during key rotation: {e}")
            """----------security recommendation------------"""
            log_event('Key Rotation Error', f"Error during key rotation: {e}")
            """---------------------------------------------"""


def backup_hourly_files(verbose):
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
            hourly_backup_dir = os.path.join(backup_directory, f"{datetime.now().strftime('%Y%m%d%H%M%S')}_hb")
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
                
            if verbose:
                print(f"\nHourly Backup Status:\n-> Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Hourly backup completed.")
                """----------security recommendation------------"""
                log_event('Hourly Backup', 'Hourly backup completed successfully.')
                """---------------------------------------------"""

        except Exception as e:
            if verbose:
                print(f"\nHourly Backup Status:\n-> Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Failed to complete backup: {e}")
                """----------security recommendation------------"""
                log_event('Hourly Backup Error', f"Failed to complete backup: {e}")
                """---------------------------------------------"""
        
        # Sleep for an hour before the next backup
        time.sleep(3600)

def backup_daily_files(verbose):
    source_directory = '/opt/rapido_bank/'
    backup_directory = '/opt/rapido_bank/backups'

    while True:
        # Calculate the next backup time for the next day at 2:00 AM
        next_backup_time = datetime.now().replace(hour=2, minute=0, second=0)
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
            
            if verbose:
                print(f"\nDaily Backup Status:\n-> Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Daily backup completed.")
                """----------security recommendation------------"""
                log_event('Daily Backup', 'Daily backup completed successfully.')
                """---------------------------------------------"""
    
        except Exception as e:
            if verbose:
                print(f"\nDaily Backup Status:\n-> Backing up files from [{source_directory}] to [{backup_directory}]\n-> Backup Status: Failed to create daily backup: {e}")
                """----------security recommendation------------"""
                log_event('Daily Backup Error', f"Failed to create daily backup: {e}")
                """---------------------------------------------"""

        # Sleep until the next backup time
        time.sleep(time_to_sleep)

def schedule_key_regeneration(interval_hours=2, verbose=False):
    """Schedule key regeneration every specified number of hours."""
    while True:
        # Assuming these functions accept the directory and admin keys path
        create_project_key_and_encrypt('/opt/rapido_bank', '/opt/rapido_bank/admin/encryption_keys')
        create_keys_for_portfolio('/opt/rapido_bank/portfolios', '/opt/rapido_bank/admin/encryption_keys')
        if verbose:
            print(f"Keys regenerated, next regeneration in {interval_hours} hours.")
            """----------security recommendation------------"""
            log_event('Key Regeneration', f"Keys regenerated, next regeneration in {interval_hours} hours.")
            """---------------------------------------------"""
        time.sleep(interval_hours * 3600)

def start_mtd(verbose=False):
    """Starts the Malware Threat Detection (MTD) system and all associated processes."""
    if verbose:
        print("Initializing MTD system...")

    # Initialize encryption keys
    initialize_encryption_keys('/opt/rapido_bank')

    # Start the YARA engine in a separate thread to begin scanning.
    threading.Thread(target=start_yara_engine, daemon=True, args=(verbose,)).start()

    # Start automated key rotation for both project-wide and individual portfolios.
    threading.Thread(target=schedule_key_regeneration, args=(2, verbose), daemon=True).start()

    # Start the routines for rotating encryption keys across sensitive directories.
    threading.Thread(target=rotate_keys, args=(verbose,), daemon=True).start()

    # Initiate continuous backup processes: daily and hourly.
    threading.Thread(target=backup_daily_files, args=(verbose,), daemon=True).start()
    threading.Thread(target=backup_hourly_files, args=(verbose,), daemon=True).start()

    # Check and revoke non-authorized users
    non_authorized_users = check_authorized_users(authorized_users)
    if non_authorized_users:
        revoke_permissions(non_authorized_users)
        if verbose:
            print(f"Revoked permissions for non-authorized users: {non_authorized_users}")
            """----------security recommendation------------"""
            log_event('Unauthorized User', f"User {non_authorized_users} is not authorised.")
            """---------------------------------------------"""

    try:
        # Keep the main thread alive to maintain daemon threads.
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        if verbose:
            print("Shutting down MTD system...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start the Malware Threat Detection (MTD) system.')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()
    start_mtd(verbose=args.verbose)

