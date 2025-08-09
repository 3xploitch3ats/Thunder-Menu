import os
import sys
import subprocess
import tkinter as tk
from tkinter import filedialog
import json
import urllib.request
import ctypes
import shutil

CONFIG_FILE = "build_config.json"
XMAKE_INSTALLER_URL = "https://github.com/xmake-io/xmake/releases/download/v3.0.1/xmake-dev.win64.exe"
MSYS2_DEPENDENCIES = [
    "base-devel",
    "git",
    "mingw-w64-x86_64-toolchain"
]

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_as_admin():
    if sys.platform == "win32" and not is_admin():
        params = " ".join(f'"{arg}"' for arg in sys.argv)
        print("[INFO] Relance en mode administrateur...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit(0)

def run(cmd, cwd=None, shell=True):
    print(f"> {cmd}")
    result = subprocess.run(cmd, cwd=cwd, shell=shell)
    if result.returncode != 0:
        raise RuntimeError(f"Commande échouée: {cmd}")

def add_path(new_path):
    current_path = os.environ.get("PATH", "")
    if new_path not in current_path:
        os.environ["PATH"] = new_path + os.pathsep + current_path
    print(f"[INFO] PATH mis à jour avec : {new_path}")

def download_and_install_xmake():
    local_installer = "xmake-dev.win64.exe"
    install_dir = os.path.expandvars(r"%LOCALAPPDATA%\xmake")
    xmake_exe = os.path.join(install_dir, "xmake.exe")

    if os.path.isfile(xmake_exe):
        print(f"[INFO] xmake déjà installé ici : {xmake_exe}")
        return xmake_exe

    if not os.path.isfile(local_installer):
        print("[INFO] Téléchargement de l'installateur xmake...")
        urllib.request.urlretrieve(XMAKE_INSTALLER_URL, local_installer)
        print("[INFO] Téléchargement terminé.")

    if not os.path.exists(install_dir):
        os.makedirs(install_dir)

    print("[INFO] Installation silencieuse de xmake...")
    cmd = f'"{os.path.abspath(local_installer)}" /S /D={install_dir}'
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        raise RuntimeError("Installation de xmake échouée")

    if not os.path.isfile(xmake_exe):
        raise FileNotFoundError(f"xmake.exe non trouvé dans {install_dir}")

    print(f"[INFO] xmake installé dans : {xmake_exe}")
    return xmake_exe

def select_msys2_folder():
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
            msys2_path = config.get("msys2_path", "")
            if msys2_path and os.path.isdir(msys2_path):
                print(f"[INFO] Chargement du dossier MSYS2 depuis config : {msys2_path}")
                return msys2_path
        except Exception:
            pass

    root = tk.Tk()
    root.withdraw()
    folder = filedialog.askdirectory(title="Sélectionnez le dossier racine MSYS2 (ex: F:/msys64)")
    root.destroy()

    if folder and os.path.isdir(folder):
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump({"msys2_path": folder}, f)
        return folder
    return None

def add_msys2_to_path(msys2_path):
    mingw64_bin = os.path.join(msys2_path, "mingw64", "bin")
    usr_bin = os.path.join(msys2_path, "usr", "bin")

    for p in [mingw64_bin, usr_bin]:
        if p not in os.environ.get("PATH", ""):
            os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")
    print(f"[INFO] PATH mis à jour avec MSYS2 : {[mingw64_bin, usr_bin]}")

def check_and_install_dependencies(msys2_path):
    pacman = os.path.join(msys2_path, "usr", "bin", "pacman.exe")
    if not os.path.isfile(pacman):
        raise FileNotFoundError(f"pacman.exe introuvable dans {pacman}")

    result = subprocess.run([pacman, "-Q"], capture_output=True, text=True, shell=True)
    installed = set()
    if result.returncode == 0:
        installed = {line.split()[0] for line in result.stdout.splitlines()}

    to_install = [pkg for pkg in MSYS2_DEPENDENCIES if pkg not in installed]
    if to_install:
        print(f"[INFO] Paquets manquants : {', '.join(to_install)}")
        run(f'"{pacman}" -Syu --noconfirm')
        run(f'"{pacman}" -S --needed --noconfirm ' + " ".join(to_install))
    else:
        print("[INFO] Tous les paquets MSYS2 nécessaires sont déjà installés.")

def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

def build_unitydoorstop(xmake_exe):
    base_dir = get_base_dir()
    print(f"[INFO] Base dir : {base_dir}")

    clone_root = os.path.join(base_dir, "UnityDoorstop")
    repo = os.path.join(clone_root, "UnityDoorstop")

    if not os.path.exists(clone_root):
        os.makedirs(clone_root)

    if os.path.isdir(repo) and os.listdir(repo):
        print(f"[INFO] Le dossier {repo} existe déjà et n'est pas vide. Utilisation sans recloner.")
    else:
        os.chdir(clone_root)
        print(f"[DEBUG] Dossier courant : {os.getcwd()}")
        print("[INFO] Clonage du dépôt UnityDoorstop...")
        run("git clone --recursive https://github.com/NeighTools/UnityDoorstop.git")

    os.chdir(repo)

    if os.path.isfile("build.bat"):
        print("[INFO] Lancement de build.bat...")
        run("build.bat")

    print("[INFO] Configuration xmake...")
    run(f'"{xmake_exe}" f -a x64 -m release')

    print("[INFO] Compilation avec xmake...")
    run(f'"{xmake_exe}"')

    print("[INFO] Génération du projet Visual Studio...")

    try:
        run(f'"{xmake_exe}" project -k vsxmake2022')
        project_subfolder = "vsxmake2022"
        old_sln_name = "vsxmake2022.sln"
    except Exception:
        print("[WARN] Échec génération vsxmake2022, tentative avec vs2019...")
        run(f'"{xmake_exe}" project -k vs2019')
        project_subfolder = "vs2019"
        old_sln_name = "vs2019.sln"

    old_sln_path = os.path.join(repo, project_subfolder, old_sln_name)
    new_sln_name = os.path.basename(repo) + ".sln"
    new_sln_path = os.path.join(repo, project_subfolder, new_sln_name)

    if os.path.isfile(old_sln_path):
        if os.path.isfile(new_sln_path):
            os.remove(new_sln_path)
        os.rename(old_sln_path, new_sln_path)

    sln_path = os.path.abspath(new_sln_path)
    print(f"[INFO] Solution Visual Studio générée ici : {sln_path}")

def main():
    run_as_admin()

    base_dir = get_base_dir()
    print(f"[INFO] Dossier de travail forcé sur : {base_dir}")
    os.chdir(base_dir)

    msys2_path = select_msys2_folder()
    if not msys2_path or not os.path.isdir(msys2_path):
        print("[ERREUR] Dossier MSYS2 invalide.")
        input("Appuyez sur Entrée pour quitter...")
        sys.exit(1)

    try:
        add_msys2_to_path(msys2_path)
        check_and_install_dependencies(msys2_path)

        xmake_exe = download_and_install_xmake()
        add_path(os.path.dirname(xmake_exe))

        build_unitydoorstop(xmake_exe)

        print("\n✅ Build terminé avec succès.")
    except Exception as e:
        print(f"\n❌ Erreur durant le build : {e}")

    if sys.stdin.isatty():
        input("Appuyez sur Entrée pour quitter...")

if __name__ == "__main__":
    main()
