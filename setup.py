import os
import sys
import subprocess
import tkinter as tk
from tkinter import filedialog

# Path to the config file storing mingw64.exe location
config_file = "mingw64_path.txt"

# Function to select mingw64.exe using a file dialog
def select_mingw64():
    root = tk.Tk()
    root.withdraw()
    
    mingw64_path = filedialog.askopenfilename(
        title="Select mingw64.exe",
        filetypes=[("Executable Files", "*.exe")]
    )
    
    if not mingw64_path:
        print("❌ No file selected. Exiting.")
        sys.exit(1)
    
    if not os.path.exists(mingw64_path) or not mingw64_path.endswith(".exe"):
        print("❌ Invalid mingw64.exe path. Please select the correct executable.")
        sys.exit(1)
    
    with open(config_file, 'w') as f:
        f.write(mingw64_path)
    
    print(f"✔ mingw64.exe location saved in {config_file}.")
    return mingw64_path

# Load mingw64.exe path from the config file if it exists
if os.path.exists(config_file):
    with open(config_file, 'r') as f:
        mingw64_path = f.read().strip()
    
    if not os.path.exists(mingw64_path) or not mingw64_path.endswith(".exe"):
        print(f"❌ Invalid mingw64.exe path in {config_file}. Please select it again.")
        mingw64_path = select_mingw64()
else:
    mingw64_path = select_mingw64()

# Get the directory of the Python script
script_dir = os.path.dirname(os.path.realpath(__file__))

# Ensure compatibility for running as a PyInstaller bundled executable
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS  # Use this if running from a bundled PyInstaller executable
else:
    base_path = os.path.dirname(os.path.abspath(__file__))

# Access the necessary files (e.g., choose-mingw64.ps1, build.sh, CMakeLists.txt, mingw64_path.txt)
ps_script_path = os.path.join(base_path, "choose-mingw64.ps1")
build_script_path = os.path.join(base_path, "build.sh")
cmake_file_path = os.path.join(base_path, "CMakeLists.txt")
mingw64_path_file = os.path.join(base_path, "mingw64_path.txt")

# Check if these files exist after being unpacked in the PyInstaller temporary directory
if not os.path.exists(ps_script_path):
    print(f"❌ PowerShell script not found at {ps_script_path}.")
    sys.exit(1)
if not os.path.exists(build_script_path):
    print(f"❌ Build script not found at {build_script_path}.")
    sys.exit(1)
if not os.path.exists(cmake_file_path):
    print(f"❌ CMakeLists.txt not found at {cmake_file_path}.")
    sys.exit(1)
if not os.path.exists(mingw64_path_file):
    print(f"❌ mingw64_path.txt not found at {mingw64_path_file}.")
    sys.exit(1)

print(f"PowerShell script located at: {ps_script_path}")
print(f"Build script located at: {build_script_path}")
print(f"CMakeLists.txt located at: {cmake_file_path}")
print(f"mingw64_path.txt located at: {mingw64_path_file}")

# Change to the directory of the script where build.sh is located
os.chdir(script_dir)

# Launch mingw64.exe and run the build.sh script
print(f"Launching mingw64 in directory: {script_dir}")
subprocess.run([mingw64_path, build_script_path], check=True)

input("Press Enter to exit.")
