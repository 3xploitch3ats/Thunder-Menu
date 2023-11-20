import os
import getpass
import winreg as reg

def get_current_username():
    return getpass.getuser()

def remove_from_startup(username, key_name):
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

    try:
        key = reg.HKEY_CURRENT_USER
        reg_key = reg.OpenKey(key, key_path, 0, reg.KEY_ALL_ACCESS)
        reg.DeleteValue(reg_key, key_name)
        reg.CloseKey(reg_key)
        print(f"Key '{key_name}' removed from startup registry for user '{username}'.")
    except FileNotFoundError:
        print(f"Key '{key_name}' not found in the registry for user '{username}'.")
    except Exception as e:
        print(f"Error removing '{key_name}' from startup registry for user '{username}': {e}")

if __name__ == "__main__":
    username = get_current_username()
    key_name = "xmrig_checker_" + username
    remove_from_startup(username, key_name)
