import os
import urllib.request
import zipfile
import tkinter as tk
from tkinter import filedialog

# URL des fichiers à télécharger
DLL_URL = "https://github.com/3xploitch3ats/Thunder-Menu/raw/refs/heads/ScriptHookV/WINMM.dll"
ZIP_URL = "https://github.com/3xploitch3ats/Thunder-Menu/raw/refs/heads/ScriptHookV/FSL.zip"

# Boîte de dialogue pour sélectionner le dossier du jeu
root = tk.Tk()
root.withdraw()
game_folder = filedialog.askdirectory(title="Sélectionnez le dossier du jeu")

if not game_folder:
    input("❌ Aucun dossier sélectionné. Appuyez sur Entrée pour quitter...")
    exit()

# Téléchargement de WINMM.dll
dll_path = os.path.join(game_folder, "WINMM.dll")
print(f"⬇ Téléchargement de WINMM.dll dans {dll_path}...")
urllib.request.urlretrieve(DLL_URL, dll_path)
print("✅ WINMM.dll téléchargé et remplacé s'il existait.")

# Téléchargement de FSL.zip
zip_path = os.path.join(os.getenv("TEMP"), "FSL.zip")
print(f"⬇ Téléchargement de FSL.zip dans {zip_path}...")
urllib.request.urlretrieve(ZIP_URL, zip_path)
print("✅ FSL.zip téléchargé.")

# Extraction dans %APPDATA%
appdata_folder = os.getenv("APPDATA")
print(f"📂 Extraction de FSL.zip dans {appdata_folder}...")
with zipfile.ZipFile(zip_path, "r") as zip_ref:
    zip_ref.extractall(appdata_folder)
print("✅ Extraction terminée.")

input("🎯 Tout est bien effectué ! Appuyez sur Entrée pour fermer...")
