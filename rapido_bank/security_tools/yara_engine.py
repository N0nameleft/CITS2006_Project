import subprocess
import yara
import os
import psutil

def load_yara_rules():
    try:
        return yara.compile(filepath='/opt/rapido_bank/security_tools/yara_rules.yar')
    except yara.SyntaxError as e:
        print("Error loading YARA rules:", e)
        return None

def scan_file(rules, file_path, is_hidden=False):
    if is_hidden:
        print(f"Processing hidden file: {file_path}")
    try:
        matches = rules.match(file_path)
        if matches:
            print(f"Match found in {file_path}: {matches}")
    except yara.Error as e:
        print(f"Error scanning file {file_path}: {e}")

def scan_directory(rules, directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file.startswith('.') or file == "yara_rules.yar":
                continue
            scan_file(rules, file_path, file.startswith('.'))

def read_process_maps(pid):
    maps_file = f"/proc/{pid}/maps"
    regions = []
    try:
        with open(maps_file, 'r') as file:
            for line in file:
                parts = line.split()
                addr_range = parts[0]
                perms = parts[1]
                pathname = parts[-1] if parts else ""
                # Focus on heap, stack, and writable areas
                if 'rw-p' in perms and ('[heap]' in pathname or '[stack]' in pathname or pathname == ""):
                    start_addr, end_addr = addr_range.split('-')
                    regions.append((start_addr, end_addr, pathname))
    except Exception as e:
        print(f"Failed to read memory maps for PID {pid}: {e}")
    return regions

def read_process_memory(args):
    cmd = ['/opt/rapido_bank/security_tools/readmem'] + args
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=False)
    output, errors = proc.communicate()
    if errors:
        print(f"Errors from readmem: {errors.decode()}")
    return output

def should_scan_process(name):
    skip_processes = ["readmem", "init", "systemd", "sshd", "bash", "sh", "zsh"]
    return not any(proc_name in name for proc_name in skip_processes)

def scan_process_memory(rules, pid, name):
    if not should_scan_process(name):
        print(f"Skipping scanning for process: {name} (PID: {pid})")
        return
    if os.getpid() == pid:
        print(f"Skipping self: {name} (PID: {pid})")
        return

    print(f"Initiating scan for {name} (PID: {pid})")
    memory_regions = read_process_maps(pid)
    args = [str(pid)]  # Start with the PID
    for start_addr, end_addr, region_type in memory_regions:
        print(f"Preparing to scan {region_type} memory region {start_addr}-{end_addr}")
        start_addr_int = int(start_addr, 16)
        end_addr_int = int(end_addr, 16)
        size = end_addr_int - start_addr_int
        args.extend([start_addr, str(size)])  # Append each address and size to the command line arguments

    if len(args) > 1:
        memory_contents = read_process_memory(args)
        matches = rules.match(data=memory_contents)
        if matches:
            print(f"YARA matches found in PID {pid}: {matches}")
        else:
            print(f"No YARA matches found in PID {pid}")
    else:
        print(f"No readable memory regions found for PID {pid}")

def main():
    rules = load_yara_rules()
    if not rules:
        return

    directory_to_scan = '/opt/rapido_bank'
    print(f"Starting scan of {directory_to_scan}")
    scan_directory(rules, directory_to_scan)

    print("Starting scan of process memory.")
    for proc in psutil.process_iter(['pid', 'name']):
        scan_process_memory(rules, proc.pid, proc.name())

    print("Scanning completed.")

if __name__ == "__main__":
    main()

