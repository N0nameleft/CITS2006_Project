import os
import time
# import tkinter as tk
# from tkinter import messagebox
# import threading
# import queue

def hash_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_bytes = file.read()

        hash_value = 0
        for byte in file_bytes:
            # Rotate left and combine with current byte value
            hash_value = ((hash_value << 5) - hash_value + byte) & 0xFFFFFFFFFFFFFFFF

        # Convert hash value to a string base-16 (hexadecimal)
        hash_str = hex(hash_value)[2:].upper()
        hash_str = (hash_str * 10)[:50]  # 50 chars
        return hash_str
    
    except Exception as e:
        return f"Error: {str(e)}"

def hash_folder(folder_path):
    hash_value = 0
    folder_hashes = {}
    try:
        for root, dirs, files in os.walk(folder_path):
            # Sort directories and files to ensure consistent hashing order
            dirs.sort()
            files.sort()
            
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                dir_hash, _ = hash_folder(dir_path)
                folder_hashes[dir_path] = dir_hash
                # Combine the directory name and its hash
                combined = dir_name + dir_hash
                for char in combined:
                    hash_value = ((hash_value << 5) - hash_value + ord(char)) & 0xFFFFFFFFFFFFFFFF
            
            for file_name in files:
                file_path = os.path.join(root, file_name)
                file_hash = hash_file(file_path)
                folder_hashes[file_path] = file_hash
                # Combine the file name and its hash
                combined = file_name + file_hash
                for char in combined:
                    hash_value = ((hash_value << 5) - hash_value + ord(char)) & 0xFFFFFFFFFFFFFFFF
        
        hash_str = hex(hash_value)[2:].upper()
        hash_str = (hash_str * 10)[:50]  # 50 char long
        return hash_str, folder_hashes
    
    except Exception as e:
        return f"Error: {str(e)}", {}

def compare_hashes(old_hashes, new_hashes):
    changes = []
    for path, new_hash in new_hashes.items():
        old_hash = old_hashes.get(path)
        if old_hash != new_hash:
            changes.append((path, old_hash, new_hash))
    return changes

# commandline output
def show_alert(changes):
    for change in changes:
        print(f"Changed: {change[0]}\nOld Hash: {change[1]}\nNew Hash: {change[2]}\n")

"""tkinter thread for prompting alert"""
# def alert_thread_func(alert_queue):
#     root = tk.Tk()
#     root.withdraw()
    
#     while True:
#         changes = alert_queue.get()
#         if changes is None:
#             break
#         change_details = "\n".join([f"Changed: {path}\nOld Hash: {old_hash}\nNew Hash: {new_hash}" for path, old_hash, new_hash in changes])
#         messagebox.showinfo("Folder Change Detected", change_details)
#     root.quit()

# def show_alert(alert_queue, changes):
#     alert_queue.put(changes)

def monitor_folder(folder_path):
    previous_hash, previous_hashes = hash_folder(folder_path)
    
    while True:
        time.sleep(1)  # Sleep for 10 minutes
        current_hash, current_hashes = hash_folder(folder_path)
        
        if current_hash != previous_hash:
            changes = compare_hashes(previous_hashes, current_hashes)
            show_alert(changes)
        
        previous_hash = current_hash
        previous_hashes = current_hashes

if __name__ == "__main__":
    folder_to_monitor = "../"
    monitor_folder(folder_to_monitor)

"""tkinter"""
# if __name__ == "__main__":
#     folder_to_monitor = "./"
    
#     alert_queue = queue.Queue()
#     alert_thread = threading.Thread(target=alert_thread_func, args=(alert_queue,))
#     alert_thread.start()

#     monitor_folder(folder_to_monitor, alert_queue)
    
#     # Send None to the queue to stop the alert thread when the script exits
#     alert_queue.put(None)
#     alert_thread.join()

# test
# file_path = "main.py"
# hash_output = hash_file(file_path)
# print("Hash of the file:", hash_output)
# folder_path = '../'
# print(hash_folder(folder_path))
