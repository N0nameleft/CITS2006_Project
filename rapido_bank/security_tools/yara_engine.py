import yara
import os

def load_yara_rules():
    try:
        return yara.compile(filepath='/opt/rapido_bank/yara_engine/yara_rules.yar')
    except yara.SyntaxError as e: 
        print("Error loading YARA rules:", e)
        return None

def scan_file(rules, file_path, is_hidden=False):
    # If the file is hidden, print a different message
    if is_hidden:
        print(f"Processing hidden file: {file_path}")
    # Scan a single file with the given YARA rules
    try:
        matches = rules.match(file_path)
        if matches:
            print(f"Match found in {file_path}: {matches}")
    except yara.Error as e:
        print(f"Error scanning file {file_path}: {e}")

def scan_directory(rules, directory):
    # Recursively scan each file in the directory
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            # Check if the file is hidden
            is_hidden = file.startswith('.')
            if file == "yara_rules.yar":
                continue
            scan_file(rules, file_path, is_hidden)

def main():
    # Load YARA rules
    rules = load_yara_rules()
    if not rules:
        return

    # Directory to scan
    directory_to_scan = '/opt/rapido_bank'  # Adjust this path to your needs

    # Start the scanning process
    print(f"Starting scan of {directory_to_scan}")
    scan_directory(rules, directory_to_scan)
    print("Scanning completed.")

if __name__ == "__main__":
    main()

