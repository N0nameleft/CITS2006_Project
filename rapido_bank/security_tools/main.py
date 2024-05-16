from cipher import *
from hashing import *
from mtd_system import *
from yara_engine import *
from create_encryption_keys import *
from get_nonauthorized_users import *


def main():
    start_yara_engine()
    start_mtd()

if __name__ == "__main__":
    main()
