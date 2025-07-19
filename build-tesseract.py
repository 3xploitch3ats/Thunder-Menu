import os
import sys
import json
import subprocess
import datetime
import tkinter as tk
from tkinter import filedialog

BUILD_TYPE = "Release"

def get_config_path():
    if getattr(sys, 'frozen', False):
        # Compilé avec PyInstaller
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(__file__)
    return os.path.join(base_path, "msys2_config.json")

CONFIG_FILE = get_config_path()

REQUIRED_PACKAGES = [
    "git", "cmake", "ninja", "make",
    "mingw-w64-x86_64-cmake",
    "mingw-w64-x86_64-toolchain",
    "mingw-w64-x86_64-leptonica",
    "mingw-w64-x86_64-icu",
    "mingw-w64-x86_64-libarchive",
    "mingw-w64-x86_64-pango",
    "mingw-w64-x86_64-cairo",
    "mingw-w64-x86_64-fontconfig",
    "mingw-w64-x86_64-glib2",
    "mingw-w64-x86_64-libjpeg-turbo",
    "mingw-w64-x86_64-libpng",
    "mingw-w64-x86_64-libtiff",
    "mingw-w64-x86_64-zlib"
]

def show_message(message, color="white"):
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {message}")

def load_msys2_config(force_use=False):
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                conf = json.load(f)
                msys_path = conf.get("MSYS2Path", "")
                if force_use or os.path.exists(os.path.join(msys_path, "msys2.exe")):
                    return msys_path
        except Exception:
            pass
    return None

def save_msys2_config(msys_path):
    data = {
        "MSYS2Path": msys_path,
        "LastUpdated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def select_msys2():
    root = tk.Tk()
    root.withdraw()
    path = filedialog.askopenfilename(title="Select msys2.exe", filetypes=[("MSYS2", "msys2.exe")])
    if path:
        msys_path = os.path.dirname(path)
        save_msys2_config(msys_path)
        return msys_path
    else:
        show_message("Aborted.", "red")
        sys.exit(1)

def get_msys2_path():
    stored = load_msys2_config(force_use=True)
    if stored:
        return stored

    defaults = [
        r"C:\msys64",
        os.path.join(os.environ.get("ProgramFiles", ""), "msys64"),
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "msys64")
    ]
    for d in defaults:
        if os.path.exists(os.path.join(d, "msys2.exe")):
            save_msys2_config(d)
            return d

    return select_msys2()

def check_and_install_packages(msys_path, bash_exe):
    show_message("Checking and installing required MSYS2 packages...", "yellow")
    missing = []
    for pkg in REQUIRED_PACKAGES:
        result = subprocess.run([bash_exe, "-lc", f"pacman -Qi {pkg} >/dev/null 2>&1; echo $?"],
                                capture_output=True, text=True)
        if result.stdout.strip() != "0":
            missing.append(pkg)

    if missing:
        show_message("Missing packages: " + ", ".join(missing), "cyan")
        show_message("→ Running: pacman -Syu", "yellow")
        subprocess.run([bash_exe, "-lc", "pacman -Syu --noconfirm"])
        for pkg in missing:
            show_message(f"→ Installing {pkg}", "cyan")
            subprocess.run([bash_exe, "-lc", f"pacman -S --needed --noconfirm {pkg}"])
    else:
        show_message("All required packages are already installed.", "green")

def main():
    if getattr(sys, 'frozen', False):
        script_root = os.path.dirname(sys.executable)
    else:
        script_root = os.path.dirname(__file__)

    msys_path = get_msys2_path()
    mingw_path = os.path.join(msys_path, "mingw64")
    cmake_exe = os.path.join(mingw_path, "bin", "cmake.exe")
    bash_exe = os.path.join(msys_path, "usr", "bin", "bash.exe")

    if not os.path.exists(bash_exe):
        show_message("bash.exe not found!", "red")
        input("Press Enter to exit...")
        sys.exit(1)

    show_message(f"Using MSYS2 at {msys_path}", "cyan")
    check_and_install_packages(msys_path, bash_exe)

    install_dir = os.path.join(script_root, "tesseract-install")
    source_dir = os.path.join(script_root, "tesseract-src")
    build_dir = os.path.join(script_root, "tesseract-build")
    tesseract_repo = "https://github.com/tesseract-ocr/tesseract.git"

    if not os.path.exists(source_dir):
        show_message("Cloning Tesseract...")
        subprocess.run(["git", "clone", "--recursive", tesseract_repo, source_dir])
    else:
        show_message("Updating Tesseract...")
        subprocess.run(["git", "-C", source_dir, "pull"])
        subprocess.run(["git", "-C", source_dir, "submodule", "update", "--init", "--recursive"])

    if os.path.exists(build_dir):
        subprocess.run(["rmdir", "/S", "/Q", build_dir], shell=True)
    os.makedirs(build_dir, exist_ok=True)

    os.environ["PATH"] = f"{os.path.join(mingw_path, 'bin')};{os.environ['PATH']}"

    cmake_args = [
        "-G", "Ninja",
        "-S", source_dir,
        "-B", build_dir,
        f"-DCMAKE_BUILD_TYPE={BUILD_TYPE}",
        f"-DCMAKE_INSTALL_PREFIX={install_dir}",
        "-DBUILD_SHARED_LIBS=ON",
        "-DBUILD_TRAINING_TOOLS=OFF",
        "-DBUILD_TESTS=OFF",
        "-DBUILD_DOCS=OFF",
        "-DENABLE_TRAINING=OFF",
        f"-DLeptonica_DIR={os.path.join(mingw_path, 'lib', 'cmake', 'leptonica')}",
        "-DSW_BUILD=OFF",
        "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY"
    ]

    show_message("Running CMake configuration...", "cyan")
    result = subprocess.run([cmake_exe] + cmake_args)
    if result.returncode != 0:
        show_message("CMake failed.", "red")
        input("Press Enter to exit...")
        sys.exit(1)

    show_message("Building...", "cyan")
    result = subprocess.run([cmake_exe, "--build", build_dir, "--parallel", "4"])
    if result.returncode != 0:
        show_message("Build failed.", "red")
        input("Press Enter to exit...")
        sys.exit(1)

    show_message(f"Installing to {install_dir}", "cyan")
    subprocess.run([cmake_exe, "--install", build_dir])

    tess_exe = os.path.join(install_dir, "bin", "tesseract.exe")
    if os.path.exists(tess_exe):
        version = subprocess.run([tess_exe, "--version"], capture_output=True, text=True)
        show_message("Installed version:\n" + version.stdout, "green")
    else:
        show_message("❌ tesseract.exe not found after install!", "red")

    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
