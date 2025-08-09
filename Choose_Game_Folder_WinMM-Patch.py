import os
import urllib.request
import zipfile
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox

DLL_URL = "https://github.com/3xploitch3ats/Thunder-Menu/raw/refs/heads/ScriptHookV/WINMM.dll"
ZIP_URL = "https://github.com/3xploitch3ats/Thunder-Menu/raw/refs/heads/ScriptHookV/FSL.zip"

def download_and_install():
    print("Démarrage de l'installation...")
    game_folder = filedialog.askdirectory(title="Sélectionnez le dossier du jeu")
    if not game_folder:
        print("⚠ Aucun dossier sélectionné. Installation annulée.")
        messagebox.showwarning("Annulé", "Aucun dossier sélectionné.")
        return

    try:
        # Téléchargement WINMM.dll
        dll_path = os.path.join(game_folder, "WINMM.dll")
        print(f"⬇ Téléchargement de WINMM.dll dans {dll_path}...")
        urllib.request.urlretrieve(DLL_URL, dll_path)
        print("✅ WINMM.dll téléchargé et remplacé s'il existait.")

        # Téléchargement FSL.zip dans TEMP
        zip_path = os.path.join(os.getenv("TEMP"), "FSL.zip")
        print(f"⬇ Téléchargement de FSL.zip dans {zip_path}...")
        urllib.request.urlretrieve(ZIP_URL, zip_path)
        print("✅ FSL.zip téléchargé.")

        # Extraction dans %APPDATA% (pas dans un sous-dossier)
        appdata_folder = os.getenv("APPDATA")
        print(f"📂 Extraction de FSL.zip dans {appdata_folder}...")
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(appdata_folder)
        print("✅ Extraction terminée.")

        print("Installation terminée avec succès.")
        messagebox.showinfo("Succès", "Installation terminée avec succès.")
    except Exception as e:
        print(f"❌ Une erreur est survenue : {e}")
        messagebox.showerror("Erreur", f"Une erreur est survenue :\n{e}")

def uninstall():
    print("Démarrage de la désinstallation...")
    game_folder = filedialog.askdirectory(title="Sélectionnez le dossier du jeu")
    if not game_folder:
        print("⚠ Aucun dossier sélectionné. Désinstallation annulée.")
        messagebox.showwarning("Annulé", "Aucun dossier sélectionné.")
        return

    try:
        # Suppression WINMM.dll dans le dossier du jeu
        dll_path = os.path.join(game_folder, "WINMM.dll")
        if os.path.isfile(dll_path):
            print(f"🗑 Suppression de {dll_path}...")
            os.remove(dll_path)
            print("✅ WINMM.dll supprimé.")
        else:
            print("⚠ WINMM.dll non trouvé, rien à supprimer.")

        # Suppression dossier FSL dans %APPDATA%
        appdata_folder = os.getenv("APPDATA")
        fsl_folder = os.path.join(appdata_folder, "FSL")
        if os.path.isdir(fsl_folder):
            print(f"🗑 Suppression du dossier {fsl_folder}...")
            shutil.rmtree(fsl_folder)
            print("✅ Dossier FSL supprimé.")
        else:
            print("⚠ Dossier FSL non trouvé, rien à supprimer.")

        print("Désinstallation terminée avec succès.")
        messagebox.showinfo("Succès", "Désinstallation terminée avec succès.")
    except Exception as e:
        print(f"❌ Une erreur est survenue : {e}")
        messagebox.showerror("Erreur", f"Une erreur est survenue :\n{e}")

root = tk.Tk()
root.title("Installateur WINMM / FSL")

install_btn = tk.Button(root, text="Install", width=20, command=download_and_install)
install_btn.pack(pady=10)

uninstall_btn = tk.Button(root, text="Uninstall", width=20, command=uninstall)
uninstall_btn.pack(pady=10)

root.mainloop()
