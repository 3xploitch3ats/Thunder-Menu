import os
import sys
import subprocess
import json
import tkinter as tk
from tkinter import ttk, filedialog
import multiprocessing
import shutil
import ctypes
import tempfile
import urllib.request
import zipfile
import importlib
import re

MAX_CMD_LENGTH = 30000      # Windows limit
MAX_CHUNK_SIZE = 1024 * 1024  # 1 MB

def install_openjdk_silently(msys2_path, version="24"):
    base_url = f"https://jdk.java.net/{version}/"
    download_url = None

    try:
        with urllib.request.urlopen(base_url) as response:
            html = response.read().decode()
            # Recherche un lien vers un zip Windows x64 (regex plus générique et insensible à la casse)
            m = re.search(r'href="(.*?openjdk-' + re.escape(version) + r'.*?windows-x64_bin\.zip)"', html, re.IGNORECASE)
            if m:
                link = m.group(1)
                if link.startswith("http"):
                    download_url = link
                else:
                    download_url = base_url + link
            else:
                print(f"[❌] Impossible de trouver le fichier ZIP JDK {version} Windows x64.")
                return False
    except Exception as e:
        print(f"[❌] Erreur lors de la récupération de la page: {e}")
        return False

    #dest = os.path.join(msys2_path, "tmp", os.path.basename(download_url))
    #dest = os.path.join(BASE_DIR, "tmp", os.path.basename(download_url))
    dest = os.path.join(BASE_DIR, os.path.basename(download_url))

    os.makedirs(os.path.dirname(dest), exist_ok=True)

    print(f"[INFO] Téléchargement de {download_url} …")
    try:
        urllib.request.urlretrieve(download_url, dest)
    except Exception as e:
        print(f"[❌] Erreur lors du téléchargement : {e}")
        return False

    extract_dir = os.path.join(msys2_path, "mingw64", f"jdk{version}")
    print(f"[INFO] Extraction vers {extract_dir} …")
    try:
        with zipfile.ZipFile(dest, 'r') as z:
            z.extractall(extract_dir)
               # os.remove(dest)  # supprime l’archive après extraction
    except Exception as e:
        print(f"[❌] Erreur lors de l'extraction : {e}")
        return False

    # Mettre à jour le PATH et JAVA_HOME (uniquement pour le processus actuel)
    bin_dir = os.path.join(extract_dir, "bin")
    os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")
    os.environ["JAVA_HOME"] = extract_dir
    # Après extraction dans extract_dir, détecter le dossier exact (ex: jdk-24)
    jdk_subfolder = None
    for name in os.listdir(extract_dir):
        full_path = os.path.join(extract_dir, name)
        if os.path.isdir(full_path) and re.match(r"jdk-?\d+", name):
            jdk_subfolder = full_path
            break
    if jdk_subfolder:
        os.environ["JAVA_HOME"] = jdk_subfolder
        bin_dir = os.path.join(jdk_subfolder, "bin")
    else:
        bin_dir = os.path.join(extract_dir, "bin")

    print(f"[✅] OpenJDK {version} installé et PATH & JAVA_HOME mis à jour.")
    return True


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
        
#if not is_admin():
#    print("⚠️ Relance en mode Administrateur...")
#    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
#    sys.exit()
def ensure_admin():
    if not is_admin():
        if "--as-admin" not in sys.argv:
            print("⚠️ Relance en mode Administrateur...")
            params = " ".join([f'"{arg}"' for arg in sys.argv] + ['"--as-admin"'])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            sys.exit()

if getattr(sys, 'frozen', False):
    # Cas: exécutable .exe généré par PyInstaller
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Cas: script lancé avec Python
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

msys2_path = os.path.join(BASE_DIR, "msys64")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

OPENCV_VERSIONS = [
    "4.12.0", "4.11.0", "4.10.0", "4.9.1", "4.9.0",
    "4.8.1", "4.8.0", "4.7.0", "4.6.0", "4.5.5"
]

def show_msg(msg):
    print(f"[INFO] {msg}")

def run_command_chunked(base_cmd, args, cwd=None, env=None):
    total_length = len(" ".join(base_cmd + args))
    if total_length < MAX_CMD_LENGTH:
        return run_command(base_cmd + args, cwd=cwd, env=env)

    show_msg("⚠️ Ligne de commande trop longue, fractionnement par fichiers de 1MB...")

    chunks = []
    current_chunk = []
    current_size = 0

    for arg in args:
        size = len(arg.encode("utf-8")) + 1  # +1 for space or newline
        if current_size + size > MAX_CHUNK_SIZE and current_chunk:
            chunks.append(current_chunk)
            current_chunk = []
            current_size = 0
        current_chunk.append(arg)
        current_size += size

    if current_chunk:
        chunks.append(current_chunk)

    temp_files = []
    try:
        # Crée un dossier temporaire dans BASE_DIR
        temp_dir = os.path.join(BASE_DIR, "command_chunks")
        os.makedirs(temp_dir, exist_ok=True)

        # Crée les fichiers de chunks dans ce dossier
        for i, chunk in enumerate(chunks):
            temp_path = os.path.join(temp_dir, f"chunk_{i}.txt")
            with open(temp_path, "w", encoding="utf-8") as tf:
                tf.write("\n".join(chunk))
            temp_files.append(temp_path)

        # Ajoute chaque fichier comme @file
        cmd_with_chunks = base_cmd + [f"@{f}" for f in temp_files]
        return run_command(cmd_with_chunks, cwd=cwd, env=env)
    finally:
        # Nettoyage des fichiers temporaires
        for f in temp_files:
            try:
                os.remove(f)
            except Exception:
                pass

def run_command(cmd, cwd=None, shell=False, env=None):
    print(f"\n➤ {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        result = subprocess.run(cmd, cwd=cwd, shell=shell, env=env, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERREUR] La commande a échoué : {e}")
        raise


def remove_locks(msys2_path):

    show_msg("🔓 Suppression des fichiers lock...")
    lock_paths = [
        os.path.join(msys2_path, "var", "lib", "pacman", "db.lck"),
        os.path.join(msys2_path, "var", "cache", "pacman", "pkg", ".pacman.lck")
    ]
    for lock_file in lock_paths:
        if os.path.exists(lock_file):
            try:
                os.remove(lock_file)
                show_msg(f"🗑️ Fichier lock supprimé : {lock_file}")
            except PermissionError:
                show_msg(f"❌ Permission refusée pour supprimer {lock_file}. Lancez le script en mode Administrateur ou fermez MSYS2.")
            except Exception as e:
                show_msg(f"⚠️ Erreur suppression lock {lock_file} : {e}")

def clean_previous_build():
    build_dir = os.path.join(BASE_DIR, "opencv_build")
    if os.path.isdir(build_dir):
        show_msg("🧹 Nettoyage de l'ancien dossier de build...")
        shutil.rmtree(build_dir)
def export_dep(msys2_path):
    try:
        print("🔧 Export des variables d’environnement MSYS2...")

        msys_mingw64_bin = os.path.join(msys2_path, "mingw64", "bin")
        msys_usr_bin = os.path.join(msys2_path, "usr", "bin")

        # N'ajoute que les chemins indispensables, pas tous
        paths_to_add = [msys_mingw64_bin, msys_usr_bin]

        current_path = os.environ.get("PATH", "")
        
        # Eviter doublons
        existing_paths = current_path.split(os.pathsep)
        paths_to_add_filtered = [p for p in paths_to_add if p not in existing_paths]

        # Construire le nouveau PATH
        new_path = os.pathsep.join(paths_to_add_filtered + existing_paths)
        os.environ["PATH"] = new_path

        # Variables utiles
        os.environ["PKG_CONFIG_PATH"] = os.path.join(msys2_path, "mingw64", "lib", "pkgconfig")
        os.environ["CMAKE_PREFIX_PATH"] = os.path.join(msys2_path, "mingw64")
        os.environ["OpenCV_DIR"] = os.path.join(msys2_path, "mingw64", "share", "OpenCV")

        # Dépendances spécifiques comme SuiteSparse, Ceres, Glog, etc.
        third_party_prefix = os.path.join(msys2_path, "mingw64")

        os.environ["SUITESPARSE_ROOT_DIR"] = third_party_prefix
        os.environ["CERES_DIR"] = third_party_prefix
        os.environ["GFLAGS_DIR"] = third_party_prefix
        os.environ["GLOG_DIR"] = third_party_prefix

        os.environ["METIS_DIR"] = third_party_prefix
        os.environ["METIS_INCLUDE_DIR"] = os.path.join(third_party_prefix, "include")
        os.environ["METIS_LIBRARY"] = os.path.join(third_party_prefix, "lib", "libmetis.dll.a")

        # Fortran compiler
        gfortran_path = os.path.join(msys2_path, "mingw64", "bin", "gfortran.exe")
        if os.path.isfile(gfortran_path):
            os.environ["FC"] = gfortran_path
            print(f"✅ Compilateur Fortran détecté et variable FC exportée: {gfortran_path}")
        else:
            print("⚠️ Compilateur Fortran (gfortran.exe) non trouvé, certaines fonctionnalités pourraient être limitées.")

        print("✅ Variables d’environnement exportées.")

    except Exception as e:
        print(f"[ERREUR] Impossible d’exporter les variables d’environnement : {e}")

def install_if_missing(package_name):
    try:
        importlib.import_module(package_name)
        print(f"{package_name} est déjà installé.")
    except ImportError:
        print(f"{package_name} non trouvé, installation...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        
def check_and_install_msys2_packages(msys2_path):
    pacman_path = os.path.join(msys2_path, "usr", "bin", "pacman.exe")
    if not os.path.isfile(pacman_path):
        raise FileNotFoundError(f"pacman introuvable dans {pacman_path}")

    packages = [
    "python",
        "mingw-w64-x86_64-libavif",
        "mingw-w64-x86_64-openjpeg2",
        "mingw-w64-x86_64-vtk",
        "nasm",
        "mingw-w64-x86_64-gcc", "mingw-w64-x86_64-cmake", "mingw-w64-x86_64-toolchain",
        "base-devel", "cmake", "git", "mingw-w64-x86_64-blas",
        "mingw-w64-x86_64-lapack",        
        "ninja", "zip", "unzip", "pkg-config",
        "mingw-w64-x86_64-ninja",
        "mingw-w64-x86_64-opencv", "mingw-w64-x86_64-ffmpeg", "mingw-w64-x86_64-libjpeg-turbo",
        "mingw-w64-x86_64-libpng", "mingw-w64-x86_64-libtiff", "mingw-w64-x86_64-openexr",
        "mingw-w64-x86_64-eigen3", "mingw-w64-x86_64-tbb", "mingw-w64-x86_64-gtk3",
        "mingw-w64-x86_64-qt5", "mingw-w64-x86_64-harfbuzz", "mingw-w64-x86_64-freetype",
        "mingw-w64-x86_64-gcc-fortran",
        "mingw-w64-x86_64-openblas",
        "mingw-w64-x86_64-metis",
        "mingw-w64-x86_64-suitesparse",
        "mingw-w64-x86_64-ceres-solver",
        "mingw-w64-x86_64-gflags",
        "mingw-w64-x86_64-glog"
        #"mingw-w64-x86_64-openjdk",  # Java
        #"mingw-w64-x86_64-cuda"  # Seulement si tu as CUDA   
    ]
    result = subprocess.run([pacman_path, "-Q"], capture_output=True, text=True, shell=True)
    installed = {line.split()[0] for line in result.stdout.splitlines()} if result.returncode == 0 else set()
    to_install = [pkg for pkg in packages if pkg not in installed]

    if to_install:
        show_msg("🔄 Mise à jour de la base de paquets MSYS2...")
        run_command([pacman_path, "-Syu", "--noconfirm"], shell=True)
        show_msg(f"⬇️ Installation des paquets : {' '.join(to_install)}")
        run_command([pacman_path, "-S", "--needed", "--noconfirm"] + to_install, shell=True)
    else:
        show_msg("✅ Tous les paquets MSYS2 nécessaires sont déjà installés.")

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

def get_short_path(path):
    buf = ctypes.create_unicode_buffer(260)
    if ctypes.windll.kernel32.GetShortPathNameW(path, buf, 260):
        return buf.value
    return path
    
def configure_cmake(build_dir, msys2_path):
    os.makedirs(build_dir, exist_ok=True)

    # Définit les chemins AVANT de les raccourcir
    opencv_dir = os.path.abspath(os.path.join(BASE_DIR, "opencv"))
    contrib_modules = os.path.abspath(os.path.join(BASE_DIR, "opencv_contrib", "modules"))

    # Puis récupère les chemins courts
    opencv_dir_short = get_short_path(opencv_dir)
    contrib_modules_short = get_short_path(contrib_modules)

    cmake_cmd = [
        #"cmake", "-G", "MSYS Makefiles", opencv_dir_short,
        "cmake", "-G", "MinGW Makefiles", opencv_dir_short,
        "-DCMAKE_EXE_LINKER_FLAGS=-Wl,--allow-multiple-definition",
        "-DCMAKE_RC_FLAGS=--use-temp-file",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DENABLE_RUN_TIME_CHECKING=OFF", #mingw
        "-DCMAKE_CXX_FLAGS=-D__MINGW__", #mingw
        "-DCMAKE_C_FLAGS=-D__MINGW__", #mingw
        "-DBUILD_SHARED_LIBS=ON",
        "-DBUILD_opencv_world=ON",
        "-DWITH_IPP=OFF",
        "-DWITH_TIFF=ON",
        "-DWITH_JPEG=ON",
        "-DWITH_PNG=ON",
        "-DWITH_WEBP=ON",
        "-DWITH_OPENEXR=ON",
        "-DWITH_OPENJPEG=ON",      # préfèrer OPENJPEG si disponible
        "-DWITH_OPENGL=ON",
        "-DWITH_VTK=OFF",
        "-DWITH_FFMPEG=ON",
        "-DWITH_GSTREAMER=ON",
        "-DWITH_GTK=OFF",
        "-DWITH_QT=OFF",
        "-DWITH_OPENCL=ON",
        "-DWITH_EIGEN=ON",
        "-DWITH_CUDA=OFF",          # mettre ON si tu as CUDA configuré
        "-DBUILD_DOCS=OFF",
        "-DBUILD_JAVA=ON",
        "-DOPENCV_EXTRA_MODULES_PATH=" + contrib_modules_short,
        "-DENABLE_PRECOMPILED_HEADERS=OFF",
        "-DWITH_OPENCL=ON",  # optionnel, active le support GPU OpenCL
        "-DBUILD_EXAMPLES=OFF",  # inutile sauf si tu veux les exemples    
        # Modules OpenCV
        "-DBUILD_opencv_dnn=ON",
        "-DBUILD_opencv_video=ON",
        "-DBUILD_opencv_videoio=ON",
        "-DBUILD_opencv_highgui=ON",
        "-DBUILD_opencv_imgcodecs=ON",
        "-DBUILD_opencv_imgproc=ON",
        "-DBUILD_opencv_calib3d=ON",
        "-DBUILD_opencv_photo=ON",
        "-DBUILD_opencv_ml=ON",
        "-DBUILD_opencv_flann=ON",
        "-DBUILD_opencv_objdetect=ON",
        "-DBUILD_opencv_features2d=ON",
        "-DBUILD_opencv_tracking=ON",
        "-DBUILD_opencv_text=ON",
        "-DBUILD_opencv_face=ON",
        "-DBUILD_opencv_freetype=ON",
        "-DBUILD_opencv_stitching=ON",
        "-DBUILD_opencv_aruco=ON",
        "-DBUILD_opencv_intensity_transform=ON",
        "-DBUILD_opencv_objc=OFF",
        "-DBUILD_opencv_js=OFF",
        "-DBUILD_TESTS=OFF",
        "-DBUILD_PERF_TESTS=OFF",        
        "-DCMAKE_INSTALL_PREFIX=install",
        "-DBUILD_USE_SYMLINKS=ON",
        "-DOPENCV_ENABLE_ALLOCATOR_STATS=OFF",
        "-DOPENCV_GENERATE_PKGCONFIG=ON",
        "-DOPENCV_FORCE_3RDPARTY_BUILD=ON",
        "-DENABLE_CXX11=ON",
        "-DCMAKE_USE_SYMLINKS=OFF",
        "-DOPENCV_ENABLE_NONFREE=ON",
        "-DBUILD_opencv_sfm=OFF",
        "-DWITH_DIRECTML=OFF",
        "-DWITH_CERES=OFF",
    ]

    # Ajout des variables JAVA si JAVA_HOME est défini et valide
    java_home = os.environ.get("JAVA_HOME")
    if java_home and os.path.isdir(java_home):
        java_include = os.path.join(java_home, "include")
        java_include_win = os.path.join(java_include, "win32")
        java_jvm_lib = os.path.join(java_home, "lib", "server", "jvm.dll")

        if os.path.isfile(java_jvm_lib) and os.path.isdir(java_include) and os.path.isdir(java_include_win):
            cmake_cmd.extend([
                f"-DJAVA_HOME={java_home}",
                f"-DJAVA_INCLUDE_PATH={java_include}",
                f"-DJAVA_INCLUDE_PATH2={java_include_win}",
                f"-DJAVA_JVM_LIBRARY={java_jvm_lib}",
            ])
            print(f"✅ Variables JAVA ajoutées à la configuration CMake.")
        else:
            print(f"⚠️ Attention : chemins Java invalides, vérifiez l'installation JDK dans {java_home}")
    else:
        print("⚠️ JAVA_HOME non défini ou invalide, build Java risque d’échouer.")
        
    env = os.environ.copy()
    env["PATH"] = os.path.join(msys2_path, "mingw64", "bin") + os.pathsep + env.get("PATH", "")

    show_msg("🔧 Configuration CMake...")
    export_dep(msys2_path)
    #run_command(cmake_cmd, cwd=build_dir, env=os.environ.copy())
    #run_command(cmake_cmd, cwd=build_dir, env=env)
    run_command_chunked(["cmake"], cmake_cmd[1:], cwd=build_dir, env=env)

def build_make(build_dir, msys2_path):
    makefile = os.path.join(build_dir, "Makefile")
    if not os.path.isfile(makefile):
        raise FileNotFoundError("❌ Makefile introuvable. Vérifiez que la configuration CMake a réussi.")

    #env = os.environ.copy()
    #msys_usr_bin = os.path.join(msys2_path, "usr", "bin")
    #env["PATH"] = msys_usr_bin + os.pathsep + env.get("PATH", "")
    #bash_path = os.path.join(msys2_path, "usr", "bin", "bash.exe")
    ##cpu_count = multiprocessing.cpu_count()
    #show_msg(f"🏗️ Compilation avec make...")
    ## Construire la commande bash avec export explicite
    #cmd = f'export PATH="{msys_usr_bin}:$PATH"; make'
    ##run_command([bash_path, "-c", cmd], cwd=build_dir, env=env)
    env = os.environ.copy()
    mingw_bin = os.path.join(msys2_path, "mingw64", "bin")
    env["PATH"] = mingw_bin + os.pathsep + env.get("PATH", "")
    bash_path = os.path.join(msys2_path, "usr", "bin", "bash.exe")

    show_msg(f"🏗️ Compilation avec mingw32-make...")

    # Construire la commande bash avec export explicite
    cmd = f'export PATH="{mingw_bin}:$PATH"; mingw32-make'
    
    run_command_chunked([bash_path, "-c"], [cmd], cwd=build_dir, env=env)
    
    #show_msg("🚀 Installation avec make install...")
    #cmd_install = f'export PATH="{msys_usr_bin}:$PATH"; make install'
    ##run_command([bash_path, "-c", cmd_install], cwd=build_dir, env=env)
    show_msg("🚀 Installation avec mingw32-make install...")
    cmd_install = f'export PATH="{mingw_bin}:$PATH"; mingw32-make install'
    
    run_command_chunked([bash_path, "-c"], [cmd_install], cwd=build_dir, env=env)

def save_config(msys2_path, version):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"msys2_path": msys2_path, "opencv_version": version}, f, indent=4)

def load_config():
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def select_msys2_folder():
    root = tk.Tk()
    root.withdraw()
    folder = filedialog.askdirectory(title="Sélectionnez le dossier MSYS2")
    root.destroy()
    return folder

def main():
    config = load_config()
    root = tk.Tk()
    root.title("Build OpenCV avec MSYS2")

    frame = ttk.Frame(root, padding=10)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="Version OpenCV :").pack(pady=5)
    version_var = tk.StringVar(value=config.get("opencv_version", OPENCV_VERSIONS[0]))
    combo = ttk.Combobox(frame, textvariable=version_var, values=OPENCV_VERSIONS, state="readonly")
    combo.pack()

    ttk.Label(frame, text="Chemin MSYS2 :").pack(pady=5)
    msys2_var = tk.StringVar(value=config.get("msys2_path", msys2_path))
    entry = ttk.Entry(frame, textvariable=msys2_var, width=40)
    entry.pack(side="left", fill="x", expand=True, padx=(0,5))

    def browse_msys2():
        folder = select_msys2_folder()
        if folder:
            msys2_var.set(folder)

    ttk.Button(frame, text="Parcourir", command=browse_msys2).pack(side="left")

    def start_build():
        path = msys2_var.get().strip()
        version = version_var.get()
        if not path or not os.path.isdir(path):
            print("[ERREUR] Dossier MSYS2 invalide.")
            return
    
        save_config(path, version)
        root.destroy()

        try:
            
            remove_locks(path)
            clean_previous_build()
            install_if_missing("numpy")
            check_and_install_msys2_packages(path)
            clone_opencv_repos()
            checkout_version(version)
            build_dir = os.path.join(BASE_DIR, "opencv_build")
            install_openjdk_silently(msys2_path)
            configure_cmake(build_dir, path)
            build_make(build_dir, path)
            print("\n✅ Compilation terminée avec succès.")
        except Exception as e:
            print(f"\n[ERREUR] Une erreur est survenue : {e}")

        if sys.stdin.isatty():
            input("Appuyez sur Entrée pour quitter...")

    ttk.Button(frame, text="Démarrer la compilation", command=start_build).pack(pady=15)
    root.mainloop()

if __name__ == "__main__":
    main()
