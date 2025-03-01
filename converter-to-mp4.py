import tkinter as tk
from tkinter import filedialog, messagebox
import json
import subprocess
import os

# Chemin de FFmpeg
FFMPEG_PATH = ".\\Ffmpeg\\Ffmpeg\\ffmpeg.exe"
CONFIG_PATH = "config.json"

# Vérifier si FFmpeg est accessible
if not os.path.exists(FFMPEG_PATH):
    messagebox.showerror("Erreur", "Le chemin vers FFmpeg est incorrect ou FFmpeg n'est pas trouvé.")
    exit()

# Fonction pour sélectionner un dossier
def ajouter_dossier():
    dossier = filedialog.askdirectory(title="Sélectionner un dossier")
    if dossier:
        # Récupérer tous les fichiers .vob et .m2ts dans le dossier
        fichiers_vob_m2ts = [os.path.join(dossier, f) for f in os.listdir(dossier) if f.lower().endswith((".vob", ".m2ts"))]
        if fichiers_vob_m2ts:
            for fichier in fichiers_vob_m2ts:
                liste_fichiers.insert(tk.END, fichier)
        else:
            messagebox.showwarning("Avertissement", "Aucun fichier .vob ou .m2ts trouvé dans ce dossier.")

# Fonction pour sélectionner le dossier de sortie
def choisir_dossier_sortie():
    return filedialog.askdirectory(title="Sélectionner le dossier de sortie")

# Fonction de conversion vidéo
def convertir():
    if liste_fichiers.size() == 0:
        messagebox.showwarning("Avertissement", "Aucun fichier sélectionné.")
        return

    resolution = combo_resolution.get()
    scale = {
        "4K (3840x2160)": "scale=3840:2160",
        "1080p (1920x1080)": "scale=1920:1080",
        "720p (1280x720)": "scale=1280:720"
    }.get(resolution, "")

    # Sélectionner un dossier de sortie
    dossier_sortie = choisir_dossier_sortie()
    if not dossier_sortie:
        messagebox.showwarning("Avertissement", "Aucun dossier de sortie sélectionné.")
        return

    for i in range(liste_fichiers.size()):
        fichier = liste_fichiers.get(i)
        nom_fichier = os.path.splitext(os.path.basename(fichier))[0]
        output_file = os.path.join(dossier_sortie, nom_fichier + "_converted.mp4")
        
        # Commande FFmpeg
        cmd = [FFMPEG_PATH, "-i", fichier, "-vf", scale, "-c:v", "libx264", "-crf", "23", "-preset", "fast", output_file]
        
        try:
            subprocess.run(cmd, check=True, shell=True)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Erreur", f"Erreur de conversion pour le fichier: {fichier}\n{e}")
            return

    messagebox.showinfo("Succès", "Conversion terminée !")

# Fonction pour sauvegarder la configuration
def sauvegarder_config():
    config = {"resolution": combo_resolution.get()}
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f)
    messagebox.showinfo("Sauvegarde", "Configuration enregistrée.")

# Fonction pour charger la configuration
def charger_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
        combo_resolution.set(config.get("resolution", "1080p (1920x1080)"))
        messagebox.showinfo("Chargement", "Configuration chargée.")
    else:
        messagebox.showwarning("Avertissement", "Aucune configuration trouvée.")

# Création de la fenêtre
fenetre = tk.Tk()
fenetre.title("Convertisseur Vidéo")
fenetre.geometry("600x400")

# Bouton pour ajouter un dossier contenant des fichiers .vob ou .m2ts
btn_ajouter_dossier = tk.Button(fenetre, text="Ajouter un dossier", command=ajouter_dossier)
btn_ajouter_dossier.pack(pady=10)

# Liste des fichiers sélectionnés
liste_fichiers = tk.Listbox(fenetre, width=80, height=10)
liste_fichiers.pack(pady=10)

# Sélection de la résolution
tk.Label(fenetre, text="Résolution:").pack()
resolutions = ["4K (3840x2160)", "1080p (1920x1080)", "720p (1280x720)"]
combo_resolution = tk.StringVar()
combo_resolution.set("1080p (1920x1080)")
menu_resolution = tk.OptionMenu(fenetre, combo_resolution, *resolutions)
menu_resolution.pack()

# Boutons de conversion et gestion
btn_convertir = tk.Button(fenetre, text="Convertir", command=convertir)
btn_convertir.pack(pady=5)

btn_sauvegarde = tk.Button(fenetre, text="Sauvegarder Config", command=sauvegarder_config)
btn_sauvegarde.pack(pady=5)

btn_charger = tk.Button(fenetre, text="Charger Config", command=charger_config)
btn_charger.pack(pady=5)

# Lancer la fenêtre
fenetre.mainloop()
