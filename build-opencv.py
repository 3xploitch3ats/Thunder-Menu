import os
import sys
import json
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime

def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()
CONFIG_FILE = os.path.join(BASE_DIR, "msys2_config.json")
OPENCV_VERSION = "4.12.0"  # Laisser vide "" pour la dernière version

def show_msg(msg):
    print(f"[INFO] {msg}")

def save_msys2_config(msys2_path):
    data = {
        "MSYS2Path": msys2_path,
        "LastUpdated": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    show_msg(f"💾 Chemin MSYS2 sauvegardé dans {CONFIG_FILE}")

def load_msys2_config():
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            path = data.get("MSYS2Path", "")
            if path and os.path.isdir(path):
                show_msg(f"✅ Chargement chemin MSYS2 depuis config : {path}")
                return path
    return None

def select_msys2_folder():
    root = tk.Tk()
    root.withdraw()
    folder = filedialog.askdirectory(title="Sélectionnez le dossier MSYS2 (contenant msys2.exe)")
    if not folder:
        messagebox.showwarning("Annulé", "Aucun dossier sélectionné. Le script va quitter.")
        sys.exit(1)
    save_msys2_config(folder)
    return folder

def run_command(cmd, cwd=None):
    """Lance une commande et affiche la sortie."""
    print(f"➤ {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    result = subprocess.run(cmd, cwd=cwd, shell=False)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd)

def is_tool_in_path(tool):
    """Check si un outil est dans le PATH Windows"""
    from shutil import which
    return which(tool) is not None

def msys2_pacman_install(msys2_path, package):
    """Installe un package via pacman dans MSYS2"""
    pacman_path = os.path.join(msys2_path, "usr", "bin", "pacman.exe")
    if not os.path.isfile(pacman_path):
        raise FileNotFoundError(f"pacman.exe introuvable dans {pacman_path}")
    print(f"📦 Installation du package {package} via pacman...")
    # -Sy --noconfirm pour synchroniser la base et installer sans confirmation
    subprocess.run([pacman_path, "-Sy", "--noconfirm", package], check=True)

def check_and_install_dependencies(msys2_path):
    """
    Vérifie et installe via pacman les dépendances si absentes.
    Dépendances clés ici :
      - git
      - cmake (mingw-w64-x86_64-cmake)
      - mingw-w64-x86_64-toolchain (gcc, make, etc.)
    """

    # Outils à vérifier : outil_windows: package_msys2
    tools_packages = {
        "git": "git",
        "cmake": "mingw-w64-x86_64-cmake",
        "gcc": "mingw-w64-x86_64-toolchain",  # gcc et make etc
    }

    # Pour vérifier cmake et git, on va chercher dans PATH Windows
    # Pour gcc, ce sera plus difficile, on peut juste tester "gcc --version"
    # On préfère utiliser le cmake du msys2 directement

    # Dossier mingw64/bin
    mingw_bin = os.path.join(msys2_path, "mingw64", "bin")

    missing = []

    # Vérifier git (dans Windows PATH)
    if not is_tool_in_path("git"):
        missing.append("git")
    # Vérifier cmake (dans mingw64/bin)
    cmake_path = os.path.join(mingw_bin, "cmake.exe")
    if not os.path.isfile(cmake_path):
        missing.append("cmake")
    # Vérifier gcc (dans mingw64/bin)
    gcc_path = os.path.join(mingw_bin, "gcc.exe")
    if not os.path.isfile(gcc_path):
        missing.append("gcc")

    if not missing:
        show_msg("✅ Toutes les dépendances sont présentes.")
        return

    # Confirmer installation via dialog tkinter
    root = tk.Tk()
    root.withdraw()
    msg = f"Les dépendances suivantes sont manquantes : {', '.join(missing)}.\nVoulez-vous les installer via MSYS2 pacman ?"
    if not messagebox.askyesno("Installation des dépendances", msg):
        messagebox.showerror("Dépendances manquantes", "Les dépendances sont nécessaires pour continuer.")
        sys.exit(1)

    # Installer les packages manquants
    for dep in missing:
        package = tools_packages.get(dep)
        if package:
            try:
                msys2_pacman_install(msys2_path, package)
                show_msg(f"✅ Package {package} installé.")
            except Exception as e:
                messagebox.showerror("Erreur installation", f"Impossible d'installer {package} : {e}")
                sys.exit(1)
        else:
            messagebox.showerror("Erreur", f"Dépendance inconnue : {dep}")
            sys.exit(1)

def clone_opencv_repos():
    if not os.path.isdir("opencv"):
        show_msg("📦 Clonage du dépôt OpenCV...")
        run_command(["git", "clone", "--recursive", "https://github.com/opencv/opencv.git"])
    else:
        show_msg("📂 Le dépôt opencv existe déjà.")

    if not os.path.isdir("opencv_contrib"):
        show_msg("📦 Clonage du dépôt OpenCV_contrib...")
        run_command(["git", "clone", "--recursive", "https://github.com/opencv/opencv_contrib.git"])
    else:
        show_msg("📂 Le dépôt opencv_contrib existe déjà.")

def checkout_version(version):
    if version:
        show_msg(f"📌 Bascule sur la version {version}...")
        run_command(["git", "checkout", version], cwd="opencv")
        run_command(["git", "checkout", version], cwd="opencv_contrib")

def configure_cmake(msys2_path):
    build_dir = "opencv_build"
    os.makedirs(build_dir, exist_ok=True)
    cmake_path = os.path.join(msys2_path, "mingw64", "bin", "cmake.exe")
    if not os.path.isfile(cmake_path):
        raise FileNotFoundError(f"CMake introuvable ici : {cmake_path}")

    cmake_cmd = [
        cmake_path, "-G", "Visual Studio 17 2022", "-A", "x64", "../opencv",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_SHARED_LIBS=ON",
        "-DWITH_IPP=ON",
        "-DBUILD_opencv_world=ON",
        "-DOPENCV_EXTRA_MODULES_PATH=../opencv_contrib/modules"
    ]
    show_msg("🔧 Configuration du projet avec CMake...")
    run_command(cmake_cmd, cwd=build_dir)

def open_visual_studio_solution():
    sln_path = os.path.join("opencv_build", "OpenCV.sln")
    if os.path.isfile(sln_path):
        show_msg("🚀 Ouverture de Visual Studio...")
        os.startfile(sln_path)
    else:
        print(f"⚠️ Fichier OpenCV.sln introuvable dans {os.path.abspath('opencv_build')}")

def main():
    try:
        msys2_path = load_msys2_config()
        if not msys2_path:
            msys2_path = select_msys2_folder()

        check_and_install_dependencies(msys2_path)

        clone_opencv_repos()
        checkout_version(OPENCV_VERSION)
        configure_cmake(msys2_path)
        input("✅ CMake terminé. Appuyez sur Entrée pour ouvrir Visual Studio...")
        open_visual_studio_solution()
    except subprocess.CalledProcessError as e:
        print(f"❌ Une commande a échoué : {e}")
        input("Appuyez sur Entrée pour quitter...")
    except Exception as e:
        import traceback
        print("❌ Erreur inattendue:")
        traceback.print_exc()
        input("Appuyez sur Entrée pour quitter...")

if __name__ == "__main__":
    main()
