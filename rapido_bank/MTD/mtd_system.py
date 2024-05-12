import os  # Provides functions for interacting with the operating system, like handling file paths.
import time  # Allows us to use functionality related to time, notably sleep delays.
import threading  # Enables the use of threads, allowing the program to run multiple operations at once.
import logging  # Facilitates logging events for debugging and monitoring the application.
import signal
from watchdog.observers import Observer  # Watches for filesystem events.
from watchdog.events import FileSystemEventHandler  # Handles the filesystem events that the observer catches.
import binascii  # Converts between binary and ASCII. Used here to format binary data for logging.

# Setup basic configuration for logging.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# Configures the logging system to display messages of level INFO and above,
# and to show the time, log level, and message content in each log entry.
# Define the directory to monitor using a relative path


MONITOR_DIR = os.path.join(os.path.dirname(__file__), '../yara_engine')
# Sets the directory to be monitored. It constructs a path by joining the directory
# of the current script (__file__) with the relative path '../yara_engine'.

if not os.path.exists(MONITOR_DIR):
    os.makedirs(MONITOR_DIR)  # Creates the directory if it does not exist.
    logging.info(f"Created directory: {MONITOR_DIR}")
else:
    logging.info(f"Monitoring directory: {MONITOR_DIR}")
# Checks if the directory exists. If not, it creates the directory and logs that it was created.
# If it does exist, it logs that it is being monitored.



# Simple custom encryption and hashing functions.
def simple_encrypt(data, key):
    key_sum = sum(bytearray(key.encode('utf-8'))) % 256
    encrypted = bytearray((byte + key_sum) % 256 for byte in bytearray(data))
    return bytes(encrypted)
# This function encrypts data by shifting each byte by the sum of the bytes in the key.



def simple_hash(data):
    hash_sum = sum(bytearray(data)) % (10**49)  # Simplistic hash function
    return f"{hash_sum:050d}"  # Return a 50-character string
# This function generates a simplistic hash by summing the bytes in data and formatting it to a fixed length.



# Encryption key (as a simple example)
# Defines a very basic encryption key used by the simple_encrypt function.
encryption_key = "this_is_a_very_simple_key"
# Global flag to indicate whether the next modification should be ignored
ignore_next_modification = {}



def encrypt_file(file_path):
    global ignore_next_modification
    try:
        ignore_next_modification[file_path] = True  # Set flag to ignore the next modification
        with open(file_path, 'rb') as file: # Opens file to read bytes ('rb' mode)
            file_data = file.read() # Reads the data from the file
        encrypted_data = simple_encrypt(file_data, encryption_key) # Encrypts the data
        with open(file_path, 'wb') as file: # Opens file to write bytes ('wb' mode)
            file.write(encrypted_data) # Writes the encrypted data back to the file
        file_hash = simple_hash(file_data) # Computes a hash of the original data
        logging.info(f"Encrypted {file_path} and hashed with hash: {binascii.hexlify(bytearray(file_hash.encode())).decode()}")
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}") # Tries to encrypt a file and log the hash of the data. Catches and logs any exceptions.
    finally:
        # Use a timer to reset the flag after a short delay to ensure it covers the modification event
        threading.Timer(1, lambda: ignore_next_modification.pop(file_path, None)).start()



class FileEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('.yar'):
            if not ignore_next_modification.get(event.src_path, False):  # Check the flag
                logging.info(f"YARA file modified: {event.src_path}")
                encrypt_file(event.src_path)
            else:
                logging.info(f"Ignored modification triggered by encryption: {event.src_path}")

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith('.yar'):
            logging.info(f"YARA file created: {event.src_path}")
            encrypt_file(event.src_path)
# A class derived from FileSystemEventHandler, which overrides methods to handle file modifications and creations.
# If a file (not a directory) is modified or created, it logs this event and calls encrypt_file on the file.




def simulate_time_based_rotation():
    while True:
        time.sleep(3600)  # Waits for 3600 seconds (1 hour) before executing the next line.
        global encryption_key
        encryption_key = "new_simple_key"  # Changes the global encryption_key.
        logging.info("Encryption key rotated.")
# A function intended to run in its own thread that simulates changing the encryption key every hour.

observer = Observer()  # Creates an observer object that monitors file system events.
handler = FileEventHandler()  # Creates an instance of the custom event handler.
observer.schedule(handler, MONITOR_DIR, recursive=True)  # Schedules the handler to watch the monitoring directory.
observer.start()  # Starts the observer.


rotation_thread = threading.Thread(target=simulate_time_based_rotation)  # Creates a thread for key rotation.
rotation_thread.start()  # Starts the key rotation thread.

# Signal handling for graceful shutdown
def handle_signal(signum, frame):
    logging.info("Signal received, stopping observer.")
    observer.stop()
    observer.join()
    rotation_thread.join()
    logging.info("Cleanup completed, exiting.")
    exit(0)

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

# Keep the script running until interrupted.
try:
    while True:
        time.sleep(1)  # Keeps the main thread alive, checking every second.
except KeyboardInterrupt:
    observer.stop()  # Stops the observer on Ctrl+C or other interrupt signal.


observer.join()  # Waits for the observer thread to finish.
rotation_thread.join()  # Waits for the rotation thread to finish.
# This block keeps the script running until it's interrupted by the user, at which point it stops and cleans up.

