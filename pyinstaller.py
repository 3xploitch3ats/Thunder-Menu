import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox

def check_and_install_pyinstaller():
    try:
        import PyInstaller
    except ImportError:
        print("[INFO] PyInstaller n'est pas installé. Installation...")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"])
        if result.returncode != 0:
            messagebox.showerror("Erreur", "Échec de l'installation de pyinstaller.")
            sys.exit(1)
        print("[✅] PyInstaller installé avec succès.")

def select_and_compile():
    root = tk.Tk()
    root.withdraw()

    file_path = filedialog.askopenfilename(
        title="Sélectionne un fichier Python",
        filetypes=[("Fichiers Python", "*.py")]
    )

    if not file_path:
        messagebox.showinfo("Annulé", "Aucun fichier sélectionné.")
        return

    script_dir = os.path.dirname(file_path)
    script_name = os.path.basename(file_path)
    exe_name = os.path.splitext(script_name)[0] + ".exe"

    command = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--distpath", script_dir,
        "--workpath", os.path.join(script_dir, "build"),
        "--specpath", script_dir,
        file_path
    ]

    print(f"[INFO] Compilation de : {script_name}")
    print(f"[CMD] {' '.join(command)}")

    try:
        subprocess.run(command, check=True)
        print(f"[✅] Fichier compilé : {os.path.join(script_dir, exe_name)}")
        messagebox.showinfo("Succès", f"Compilation réussie :\n{exe_name}")
    except subprocess.CalledProcessError:
        messagebox.showerror("Erreur", "Échec de la compilation.")

if __name__ == "__main__":
    check_and_install_pyinstaller()
    select_and_compile()
