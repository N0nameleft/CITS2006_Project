import pwd
import subprocess

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
    
    return non_authorized_users

def revoke_permissions(non_authorized_users):
    """Revoke permissions of non-authorized users by locking their accounts."""
    for user in non_authorized_users:
        try:
            # Lock the account
            subprocess.run(['usermod', '-L', user], check=True)
            
            # Expire the account immediately
            subprocess.run(['usermod', '--expiredate', '1', user], check=True)
            
            # Remove the user from all groups
            subprocess.run(['usermod', '-G', '', user], check=True)
            
            # Change the user's shell to /usr/sbin/nologin
            subprocess.run(['usermod', '-s', '/usr/sbin/nologin', user], check=True)
            
            print(f"Revoked permissions for user: {user}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to revoke permissions for user: {user}. Error: {e}")

if __name__ == "__main__":
    non_authorized_users = check_authorized_users(authorized_users)

    if non_authorized_users:
        revoke_permissions(non_authorized_users)

