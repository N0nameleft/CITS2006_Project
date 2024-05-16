import os
from datetime import datetime
from cipher import generate_key, vigenere_encrypt
from security_recom import log_event

def save_key(key, filename, verbose=False):
    """Save the encryption key to a specified file."""
    try:
        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)
        with open(filename, 'w') as file:
            file.write(key)
        if verbose:
            print(f"Key saved to {filename}")
    except PermissionError:
        if verbose:
            print(f"Permission denied: {filename}")
            """----------security recommendation------------"""
            log_event('Save Key Permission Denied', f"Current user does not have permission to {filename}, save key failed")
            """---------------------------------------------"""

    except Exception as e:
        if verbose:
            print(f"Error saving key to {filename}: {e}")
            """----------security recommendation------------"""
            log_event('Save Key Error', f"An error occurred while saving the key to {filename}.")
            """---------------------------------------------"""


def get_timestamped_filename(base_dir, prefix, extension='key'):
    """Generate a timestamped filename for storing keys."""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    return os.path.join(base_dir, f"{prefix}_{timestamp}.{extension}")

def encrypt_directory(directory, key, exclusions=None, verbose=False):
    """Encrypt all files in a directory, excluding specified subdirectories."""
    exclusions = exclusions or []
    for root, dirs, files in os.walk(directory, topdown=True):
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in exclusions]  # Skip excluded directories
        for file in files:
            file_path = os.path.join(root, file)
            if not any(file_path.startswith(excluded) for excluded in exclusions):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    encrypted_content = vigenere_encrypt(content, key)
                    with open(file_path, 'w') as f:
                        f.write(encrypted_content)
                    if verbose:
                        print(f"Encrypted {file_path}")
                except PermissionError:
                    if verbose:
                        print(f"Permission denied: {file_path}")
                        """----------security recommendation------------"""
                        log_event('Encryption Permission Denied', f"Current user does not have permission to {file_path}, encryption failed")
                        """---------------------------------------------"""
                except Exception as e:
                    if verbose:
                        print(f"Error encrypting {file_path}: {e}")
                        """----------security recommendation------------"""
                        log_event('Encryption Error', f"An error occurred while trying to encrypt {file_path}.")
                        """---------------------------------------------"""

def create_keys_for_portfolio(portfolio_dir, admin_dir, verbose=False):
    """Create individual keys for each portfolio and copy them to the admin directory."""
    for person in os.listdir(portfolio_dir):
        person_dir = os.path.join(portfolio_dir, person)
        if os.path.isdir(person_dir):
            key = generate_key()
            # Save the key within the person's directory and the admin directory
            person_key_path = os.path.join(person_dir, 'encryption_key.key')
            admin_key_path = get_timestamped_filename(admin_dir, f'{person}_encryption_key')
            save_key(key, person_key_path, verbose)
            save_key(key, admin_key_path, verbose)
            # Encrypt all files in the person's directory, excluding the key file
            encrypt_directory(person_dir, key, exclusions=[person_key_path], verbose=verbose)
            if verbose:
                print(f"Encryption key for {person} created, saved, and applied to their portfolio.")

def create_project_key_and_encrypt(project_dir, admin_dir, verbose=False):
    """Create a master key for the project, save it, and encrypt the project directory."""
    exclusions = [
        os.path.join(project_dir, 'shared'),
        os.path.join(project_dir, 'backups'),
        os.path.join(project_dir, 'security_tools'),
        os.path.join(project_dir, 'admin', 'encryption_keys')
    ]
    master_key = generate_key()
    master_key_path = get_timestamped_filename(admin_dir, 'master_project_key')
    save_key(master_key, master_key_path, verbose)
    encrypt_directory(project_dir, master_key, exclusions, verbose=verbose)
    if verbose:
        print(f"Master key created and applied to project directory: {project_dir}")

def initialize_encryption_keys(rapido_bank_dir, verbose=False):
    """Initialize encryption keys for the project and portfolios."""
    admin_keys_dir = os.path.join(rapido_bank_dir, 'admin', 'encryption_keys')
    portfolios_dir = os.path.join(rapido_bank_dir, 'portfolios')

    # Generate and save the master key for the project
    create_project_key_and_encrypt(rapido_bank_dir, admin_keys_dir, verbose)

    # Handle portfolio keys
    create_keys_for_portfolio(portfolios_dir, admin_keys_dir, verbose)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Initialize encryption keys for the project.')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    rapido_bank_dir = '/opt/rapido_bank'
    initialize_encryption_keys(rapido_bank_dir, verbose=args.verbose)

