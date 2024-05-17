from hashing import *
from mtd_system import *
from security_recom import main as sec_rec
import threading
import time

LOG_FILE_PATH = '/opt/rapido_bank/logs/important_logs/security_events.log'
MONITOR_FOLDER_PATH =  "/opt/rapido_bank/"
def main(verbose):
    # Create threads
    monitor_thread = threading.Thread(target=monitor_folder, args=(MONITOR_FOLDER_PATH,))
    mtd_thread = threading.Thread(target=start_mtd, args=(verbose,))
    sec_rec_thread = threading.Thread(target=sec_rec, args=(LOG_FILE_PATH,))

    # Start threads
    monitor_thread.start()
    mtd_thread.start()
    time.sleep(30)
    sec_rec_thread.start()

    # Join threads to ensure they complete before exiting
    monitor_thread.join()
    mtd_thread.join()
    sec_rec_thread.join()

if __name__ == "__main__":
    verbose = True
    main(verbose)
