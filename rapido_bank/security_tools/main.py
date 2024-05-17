from hashing import *
from mtd_system import *
from security_recom import main as sec_rec

LOG_FILE_PATH = '/opt/rapido_bank/logs/important_logs/security_events.log'
MONITOR_FOLDER_PATH =  "/opt/rapido_bank/"
def main(verbose):
    monitor_folder(MONITOR_FOLDER_PATH)
    start_mtd(verbose)
    sec_rec(LOG_FILE_PATH)

if __name__ == "__main__":
    verbose = True
    main(verbose)
