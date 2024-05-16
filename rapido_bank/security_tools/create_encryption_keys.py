import os
import shutil
from datetime import datetime
from cipher import generate_key, vigenere_encrypt

def save_key(key, filename):
    """Save the encryption key to a specified file."""
    with open(filename, 'w') as file:
        file.write(key)
    print(f"Key saved to {filename}")

def get_timestamped_filename(base_dir, prefix, extension='key'):
    """Generate a timestamped filename for storing keys."""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    return os.path.join(base_dir, f"{prefix}_{timestamp}.{extension}")

def encrypt_directory(directory, key, exclusions):
    """Encrypt all files in a directory, excluding specified subdirectories."""
    for root, dirs, files in os.walk(directory, topdown=True):
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in exclusions]  # Modify dirs in-place to skip exclusions
        for file in files:
            file_path = os.path.join(root, file)
            if not any(file_path.startswith(excluded) for excluded in exclusions):
                with open(file_path, 'r') as f:
                    content = f.read()
                encrypted_content = vigenere_encrypt(content, key)
                with open(file_path, 'w') as f:
                    f.write(encrypted_content)
                print(f"Encrypted {file_path}")

def create_keys_for_portfolio(portfolio_dir, admin_dir):
    """Create individual keys for each portfolio and copy them to the admin directory."""
    for person in os.listdir(portfolio_dir):
        person_dir = os.path.join(portfolio_dir, person)
        if os.path.isdir(person_dir):
            key = generate_key()
            person_key_path = get_timestamped_filename(person_dir, 'encryption_key')
            admin_key_path = get_timestamped_filename(admin_dir, f'{person}_encryption_key')
            save_key(key, person_key_path)
            shutil.copy(person_key_path, admin_key_path)
            print(f"Key for {person} created and copied to admin directory.")

if __name__ == "__main__":
    rapido_bank_dir = 'rapido_bank'
    exclusions = [
        os.path.join(rapido_bank_dir, 'shared'),
        os.path.join(rapido_bank_dir, 'backups'),
        os.path.join(rapido_bank_dir, 'portfolios'),
        os.path.join(rapido_bank_dir, 'security_tools')  # Exclude the security_tools directory
    ]
    admin_keys_dir = os.path.join(rapido_bank_dir, 'admin', 'encryption_keys')
    portfolios_dir = os.path.join(rapido_bank_dir, 'portfolios')

    # Generate and save the master key for the project
    master_key = generate_key()
    master_key_path = get_timestamped_filename(admin_keys_dir, 'master_project_key')
    save_key(master_key, master_key_path)
    
    # Encrypt the project directory with exclusions
    encrypt_directory(rapido_bank_dir, master_key, exclusions)

    # Handle portfolio keys
    create_keys_for_portfolio(portfolios_dir, admin_keys_dir)
