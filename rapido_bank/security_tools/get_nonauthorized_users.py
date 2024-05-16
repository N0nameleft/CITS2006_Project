import pwd
authorized_users = [
    'admin', 'charles', 'mathilde', 'diego', 'santiago', 'maria', 'maxwell',
    'root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail',
    'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', '_apt',
    'nobody', 'ubuntu'
]


def get_system_users():
    """Retrieve a list of all users on the system."""
    users = [user.pw_name for user in pwd.getpwall()]
    return users

def check_authorized_users(authorized_users):
    """Check for non-authorized users on the system."""
    system_users = get_system_users()
    non_authorized_users = [user for user in system_users if user not in authorized_users]
    
    if non_authorized_users:
        print("Non-authorized users found:")
        for user in non_authorized_users:
            print(f"- {user}")
    else:
        print("No non-authorized users found. All users are authorized.")

if __name__ == "__main__":
    check_authorized_users(authorized_users)

