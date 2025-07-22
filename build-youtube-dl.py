import os
import sys
import subprocess
import shutil
import json
import time
import ctypes

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except ImportError:
    tk = None  # Pas d'interface graphique possible


# --- Utilitaires ---

def print_msg(msg):
    print(msg)


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def relaunch_as_admin():
    print_msg("[🔁] Redémarrage du script en mode administrateur...")
    python_exe = sys.executable
    script = os.path.abspath(sys.argv[0])
    args = sys.argv[1:]
    params = [script] + args
    params_quoted = " ".join(f'"{arg}"' for arg in params)
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", python_exe, params_quoted, None, 1)
    except Exception as e:
        print_msg(f"Échec redémarrage en admin : {e}")
        sys.exit(1)
    sys.exit(0)


def remove_locks(msys_path):
    print_msg("Suppression des fichiers lock...")
    lock_paths = [
        os.path.join(msys_path, "var", "lib", "pacman", "db.lck"),
        os.path.join(msys_path, "var", "cache", "pacman", "pkg", ".pacman.lck")
    ]
    for lock_file in lock_paths:
        print_msg(f"Vérification de {lock_file}")
        if os.path.exists(lock_file):
            try:
                os.remove(lock_file)
                print_msg(f"Fichier lock supprimé : {lock_file}")
            except PermissionError:
                print_msg(f"Permission refusée pour supprimer {lock_file}, redémarrage en mode administrateur demandé.")
                if not is_admin():
                    relaunch_as_admin()
                else:
                    print_msg("Le script est déjà en mode administrateur mais ne peut pas supprimer le lock.")
            except Exception as e:
                print_msg(f"Erreur suppression lock {lock_file} : {e}")
        else:
            print_msg(f"Le fichier {lock_file} n'existe pas.")


def pause_exit(code=0, pause_if_no_tty=False):
    try:
        if pause_if_no_tty and sys.stdin.isatty():
            input("Appuyez sur Entrée pour fermer...")
        elif not pause_if_no_tty:
            input("Appuyez sur Entrée pour fermer...")
    except Exception:
        pass
    sys.exit(code)


def run_command(cmd, shell=False, check=True, env=None):
    if isinstance(cmd, list):
        print(f"> {' '.join(cmd)}")
    else:
        print(f"> {cmd}")
    try:
        completed = subprocess.run(cmd, shell=shell, check=check, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        print(completed.stdout)
        return completed.returncode
    except subprocess.CalledProcessError as e:
        print(f"[ERREUR] Commande échouée avec code {e.returncode}: {cmd}")
        print(e.output)
        return e.returncode


def select_directory(title="Sélectionnez un dossier"):
    if not tk:
        return input(f"{title} (chemin complet) : ")
    root = tk.Tk()
    root.withdraw()
    path = filedialog.askdirectory(title=title)
    root.destroy()
    return path


# --- Configuration MSYS2 ---

def load_msys2_config(config_path):
    if os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                conf = json.load(f)
                msys_path = conf.get("MSYS2Path", "")
                msys2_exe = os.path.join(msys_path, "msys2.exe")
                if os.path.isfile(msys2_exe):
                    print_msg(f"Configuration MSYS2 chargée : {msys_path}")
                    return msys_path
        except Exception as e:
            print_msg(f"Erreur chargement config MSYS2: {e}")
    return None


def save_msys2_config(config_path, msys_path):
    obj = {
        "MSYS2Path": msys_path,
        "LastUpdated": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        print_msg("Configuration MSYS2 sauvegardée.")
    except Exception as e:
        print_msg(f"Erreur sauvegarde config MSYS2: {e}")


def select_msys2_path():
    print_msg("Veuillez sélectionner le dossier MSYS2 via la fenêtre de dialogue.")
    path = select_directory("Sélectionnez le dossier MSYS2 (ex: C:\\msys64)")
    if path and os.path.isdir(path) and os.path.isfile(os.path.join(path, "msys2.exe")):
        return path
    else:
        print_msg("Chemin MSYS2 invalide ou msys2.exe introuvable.")
        return None


def get_msys2_path(config_path):
    msys_path = load_msys2_config(config_path)
    if msys_path:
        return msys_path

    # Recherche dans chemins standards
    defaults = [
        r"C:\msys64",
        os.path.join(os.environ.get("ProgramFiles", ""), "msys64"),
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "msys64"),
    ]
    for d in defaults:
        if os.path.isfile(os.path.join(d, "msys2.exe")):
            print_msg(f"MSYS2 détecté dans : {d}")
            save_msys2_config(config_path, d)
            return d

    # Demander à l'utilisateur
    msys_path = select_msys2_path()
    if msys_path:
        save_msys2_config(config_path, msys_path)
        return msys_path
    return None


# --- MSYS2 mirror backup et changement ---

def backup_and_change_mirrors(msys_path):
    mirror_msys = os.path.join(msys_path, "etc", "pacman.d", "mirrorlist.msys")
    mirror_mingw64 = os.path.join(msys_path, "etc", "pacman.d", "mirrorlist.mingw64")
    backup_msys = mirror_msys + ".bak"
    backup_mingw64 = mirror_mingw64 + ".bak"

    if not os.path.isfile(backup_msys) and os.path.isfile(mirror_msys):
        shutil.copy2(mirror_msys, backup_msys)
        print_msg("Backup mirrorlist.msys créé.")
    if not os.path.isfile(backup_mingw64) and os.path.isfile(mirror_mingw64):
        shutil.copy2(mirror_mingw64, backup_mingw64)
        print_msg("Backup mirrorlist.mingw64 créé.")

    new_msys = "Server = https://mirror.msys2.org/msys/x86_64\n"
    new_mingw64 = "Server = https://mirror.msys2.org/mingw/x86_64\n"

    with open(mirror_msys, "w", encoding="ascii") as f:
        f.write(new_msys)
    with open(mirror_mingw64, "w", encoding="ascii") as f:
        f.write(new_mingw64)
    print_msg("Miroirs MSYS2 mis à jour.")


# --- Conversion chemins Windows -> MSYS2 ---

def convert_to_msys_path(win_path):
    win_path = win_path.replace("\\", "/")
    if len(win_path) > 1 and win_path[1] == ":":
        drive = win_path[0].lower()
        rest = win_path[2:]
        if not rest.startswith("/"):
            rest = "/" + rest
        return f"/{drive}{rest}"
    return win_path


# --- Vérifications / Installations ---

def ensure_python_installed(bash_exe):
    print_msg("Vérification de Python MSYS et MinGW64...")
    ret = run_command([bash_exe, "-lc", "pacman -Qs python | grep '^local/python '"])
    if ret != 0:
        print_msg("Installation Python MSYS...")
        ret = run_command([bash_exe, "-lc", "pacman -S --needed --noconfirm python python-pip python-setuptools"])
        if ret != 0:
            print_msg("Échec installation Python MSYS.")
            pause_exit(1)
    else:
        print_msg("Python MSYS déjà installé.")

    ret = run_command([bash_exe, "-lc", "pacman -Qs mingw-w64-x86_64-python"])
    if ret != 0:
        print_msg("Installation Python MinGW64...")
        ret = run_command([bash_exe, "-lc",
                           "pacman -S --needed --noconfirm mingw-w64-x86_64-python mingw-w64-x86_64-python-pip mingw-w64-x86_64-python-setuptools mingw-w64-x86_64-python-wheel"])
        if ret != 0:
            print_msg("Échec installation Python MinGW64.")
            pause_exit(1)
    else:
        print_msg("Python MinGW64 déjà installé.")


def ensure_pyinstaller_installed(python_exe):
    print_msg("Vérification de PyInstaller dans Python natif Windows...")
    ret = run_command([python_exe, "-m", "pip", "show", "pyinstaller"])
    if ret != 0:
        print_msg("PyInstaller non trouvé, installation via pip...")
        ret = run_command([python_exe, "-m", "pip", "install", "--upgrade", "pip"])
        if ret != 0:
            print_msg("Erreur mise à jour pip.")
            pause_exit(1)
        ret = run_command([python_exe, "-m", "pip", "install", "pyinstaller"])
        if ret != 0:
            print_msg("Erreur installation PyInstaller.")
            pause_exit(1)
    else:
        print_msg("PyInstaller déjà installé.")


def update_msys2_packages(bash_exe):
    max_retries = 3
    for i in range(1, max_retries + 1):
        print_msg(f"Tentative {i} : mise à jour base paquets...")
        ret = run_command([bash_exe, "-lc", "pacman -Sy --noconfirm"])
        if ret == 0:
            break
        elif i < max_retries:
            print_msg("Erreur lors de la synchronisation, attente 5 secondes...")
            time.sleep(5)
        else:
            print_msg("Échec synchronisation après plusieurs tentatives.")
            pause_exit(1)
    print_msg("Mise à jour complète des paquets...")
    ret = run_command([bash_exe, "-lc", "pacman -Su --noconfirm"])
    if ret != 0:
        print_msg("Erreur mise à jour complète des paquets.")
        pause_exit(1)


def install_mingw64_packages(bash_exe):
    env = os.environ.copy()
    env["PATH"] = "/mingw64/bin:" + env.get("PATH", "")
    env["MSYSTEM"] = "MINGW64"

    packages = [
        "mingw-w64-x86_64-python",
        "mingw-w64-x86_64-python-setuptools",
        "mingw-w64-x86_64-python-wheel",
        "mingw-w64-x86_64-toolchain",
        "mingw-w64-x86_64-gcc",
        "mingw-w64-x86_64-cmake",
        "make",
        "zip",
        "git",
    ]
    for pkg in packages:
        print_msg(f"Installation du paquet : {pkg}")
        ret = run_command([bash_exe, "-lc", f"pacman -S --needed --noconfirm {pkg}"], env=env)
        if ret != 0:
            print_msg(f"Échec installation du paquet {pkg}")
            pause_exit(1)


def configure_msys2_environment(msys_path):
    bashrc = os.path.join(os.environ.get("USERPROFILE", ""), ".bashrc")
    lines_to_add = [
        "export PATH=/mingw64/bin:$PATH",
        "alias python=python3",
        '[[ $MSYSTEM != "MINGW64" ]] && exec bash --login -i -c "MSYSTEM=MINGW64 bash"',
        'export PATH=$PATH:"/c/Program Files/Pandoc"',
        "export MSYSTEM=MINGW64",
    ]

    if not os.path.isfile(bashrc):
        with open(bashrc, "w", encoding="utf-8") as f:
            pass
        print_msg(".bashrc créé.")

    with open(bashrc, "r", encoding="utf-8") as f:
        content = f.read()

    with open(bashrc, "a", encoding="utf-8") as f:
        for line in lines_to_add:
            if line not in content:
                f.write(line + "\n")
                print_msg(f"Ajouté à .bashrc : {line}")
            else:
                print_msg(f"Déjà présent dans .bashrc : {line}")


def install_pandoc_if_missing():
    pandoc_path = os.path.join(os.environ.get("ProgramFiles", ""), "Pandoc", "pandoc.exe")
    if not os.path.isfile(pandoc_path):
        print_msg("Pandoc non trouvé, téléchargement...")
        import urllib.request
        url = "https://github.com/jgm/pandoc/releases/latest/download/pandoc-3.2.0-windows-x86_64.msi"
        msi_file = "pandoc-installer.msi"
        try:
            urllib.request.urlretrieve(url, msi_file)
            ret = run_command(["msiexec.exe", "/i", msi_file, "/quiet", "/norestart"])
            os.remove(msi_file)
            if ret == 0:
                print_msg("Pandoc installé.")
            else:
                print_msg("Échec installation Pandoc.")
                pause_exit(1)
        except Exception as e:
            print_msg(f"Erreur téléchargement/install Pandoc : {e}")
            pause_exit(1)
    else:
        print_msg("Pandoc déjà installé.")


# --- Git ---

def clone_or_update_git_repo(repo_url, dest_dir):
    if not os.path.isdir(dest_dir):
        print_msg(f"Clonage du repo {repo_url} dans {dest_dir} ...")
        ret = run_command(["git", "clone", "--recursive", repo_url, dest_dir])
        if ret != 0:
            print_msg("Échec clonage git.")
            pause_exit(1)
    else:
        print_msg(f"Mise à jour du repo dans {dest_dir} ...")
        ret = run_command(["git", "-C", dest_dir, "pull"])
        if ret != 0:
            print_msg("Échec mise à jour git.")
            pause_exit(1)


# --- Installation setup.py et make ---

def run_python_setup_install(bash_exe, source_dir):
    msys_path = convert_to_msys_path(source_dir)
    cmd = f"cd '{msys_path}' && python3 setup.py install"
    print_msg(f"Installation python setup.py install dans {source_dir} ...")
    ret = run_command([bash_exe, "-lc", cmd])
    if ret != 0:
        print_msg("Erreur lors de python setup.py install.")
        pause_exit(1)


def run_make_install_if_makefile(bash_exe, source_dir):
    makefile = os.path.join(source_dir, "Makefile")
    if os.path.isfile(makefile):
        msys_path = convert_to_msys_path(source_dir)
        pandoc_path = "/c/Program Files/Pandoc"
        cmd = (
            f'export MSYSTEM=MINGW64 && '
            f'export PATH="{pandoc_path}:$PATH" && '
            f'cd "{msys_path}" && '
            f'make install'
        )
        print_msg(f"Lancement de make install dans {source_dir} ...")
        ret = run_command([bash_exe, "-lc", cmd])
        if ret != 0:
            print_msg("Erreur lors de make install.")
            pause_exit(1)
    else:
        print_msg("Pas de Makefile trouvé, étape make install ignorée.")


# --- PyInstaller compilation ---

def pyinstaller_compile_with_cmd(python_exe, source_dir, main_py):
    """
    Lance PyInstaller avec python.exe Windows natif (pas venv),
    on suppose que python_exe est python MinGW64.exe accessible en Windows (chemin complet)
    """

    main_dir = os.path.dirname(main_py)
    dist_dir = os.path.join(source_dir, "dist")
    build_dir = os.path.join(source_dir, "build")
    spec_file = os.path.join(source_dir, "youtube_dl.spec")

    # Nettoyer les anciens fichiers/dossiers
    targets = [
        os.path.join(dist_dir, "youtube_dl.exe"),
        build_dir,
        spec_file,
    ]
    for path in targets:
        if os.path.exists(path):
            try:
                if os.path.isfile(path):
                    os.remove(path)
                else:
                    shutil.rmtree(path)
                print_msg(f"Supprimé : {path}")
            except Exception as e:
                print_msg(f"Erreur suppression {path} : {e}")

    # Construire la commande PyInstaller (Windows)
    cmd = [
        python_exe,
        "-m",
        "PyInstaller",
        "--clean",
        "-y",
        "--onefile",
        "--name", "youtube_dl",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        f"--specpath={source_dir}",
        main_py
    ]

    print_msg(f"Lancement PyInstaller : {' '.join(cmd)}")

    ret = run_command(cmd, shell=False)
    if ret != 0:
        print_msg("Erreur lors de la compilation PyInstaller.")
        pause_exit(1)

    print_msg("Compilation PyInstaller terminée.")



# --- MAIN ---

def main():
    if os.name != "nt":
        print_msg("Ce script est conçu pour Windows uniquement.")
        pause_exit(1)

    # Relance admin si nécessaire
    if not is_admin():
        relaunch_as_admin()

    # ** MODIFICATION PyInstaller :**
    if getattr(sys, 'frozen', False):
        current_dir = os.path.dirname(sys.executable)
    else:
        current_dir = os.path.dirname(os.path.abspath(__file__))

    config_path = os.path.join(current_dir, "msys2_config.json")

    msys_path = get_msys2_path(config_path)
    if not msys_path:
        print_msg("MSYS2 requis mais introuvable. Fin du script.")
        pause_exit(1)

    bash_exe = os.path.join(msys_path, "usr", "bin", "bash.exe")
    mingw64_exe = os.path.join(msys_path, "mingw64.exe")

    if not os.path.isfile(bash_exe) or not os.path.isfile(mingw64_exe):
        print_msg("bash.exe ou mingw64.exe introuvable dans MSYS2.")
        pause_exit(1)

    print_msg(f"MSYS2 détecté : {msys_path}")

    config_info = None
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config_info = json.load(f)
    except Exception:
        pass

    do_full_setup = True
    if config_info:
        last_update_str = config_info.get("LastUpdated", "")
        try:
            last_update = time.strptime(last_update_str, "%Y-%m-%d %H:%M:%S")
            last_update_epoch = time.mktime(last_update)
            if (time.time() - last_update_epoch) < 24 * 3600:
                do_full_setup = False
                print_msg("Configuration récente détectée, étapes lourdes sautées pour accélérer.")
        except Exception:
            pass

    if do_full_setup:
        backup_and_change_mirrors(msys_path)
        remove_locks(msys_path)
        update_msys2_packages(bash_exe)
        ensure_python_installed(bash_exe)
        install_mingw64_packages(bash_exe)
        configure_msys2_environment(msys_path)
        install_pandoc_if_missing()
        save_msys2_config(config_path, msys_path)
    else:
        print_msg("Passage rapide : pas de mise à jour des miroirs, paquets, ni config bash.")

    source_dir = os.path.join(current_dir, "youtube-dl")

    clone_or_update_git_repo("https://github.com/ytdl-org/youtube-dl.git", source_dir)

    run_python_setup_install(bash_exe, source_dir)
    run_make_install_if_makefile(bash_exe, source_dir)

    python_exe = os.path.join(msys_path, "mingw64", "bin", "python.exe")
    if not os.path.isfile(python_exe):
        print_msg(f"Python MinGW64 introuvable à {python_exe}")
        pause_exit(1)

    print_msg(f"Python MinGW64 détecté : {python_exe}")

    print_msg("Installation de PyInstaller via pip MinGW64...")
    ret = run_command([python_exe, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
    if ret != 0:
        print_msg("Erreur mise à jour pip/setuptools/wheel.")
        pause_exit(1)

    ret = run_command([python_exe, "-m", "pip", "install", "pyinstaller"])
    if ret != 0:
        print_msg("Erreur installation mise à jour PyInstaller.")
        pause_exit(1)

    target_dir_r = os.path.join(source_dir, "youtube_dl")
    print_msg(f"Je vais dans le dossier : {target_dir_r}")
    if not os.path.isdir(target_dir_r):
        print_msg("Dossier youtube_dl introuvable.")
        pause_exit(1)

    main_py = None
    for root, dirs, files in os.walk(target_dir_r):
        for f in files:
            if f in ("__main__.py", "main.py"):
                main_py = os.path.join(root, f)
                break
        if main_py:
            break

    if not main_py:
        print_msg("Fichier __main__.py ou main.py introuvable dans youtube_dl.")
        pause_exit(1)

    pyinstaller_compile_with_cmd(python_exe, source_dir, main_py)

    dist_path = os.path.join(source_dir, "dist")
    print_msg(f"Compilation terminée. Exécutable disponible dans : {dist_path}")

    dist_dir = os.path.join(target_dir_r, "dist")
    exe_path = os.path.join(dist_dir, "youtube_dl.exe")
    if os.path.isfile(exe_path):
        print_msg(f"Compilation réussie. Exécutable généré : {exe_path}")
    else:
        pause_exit(1)

    pause_exit(0, pause_if_no_tty=True)


if __name__ == "__main__":
    main()
