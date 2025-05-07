import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
import os

# Fonction principale
def convertir_video():
    # Sélection du fichier d'entrée
    root = tk.Tk()
    root.withdraw()  # Cache la fenêtre principale
    fichier_entree = filedialog.askopenfilename(title="Sélectionnez un fichier vidéo", filetypes=[("Tous les fichiers", "*.*")])

    if not fichier_entree:
        messagebox.showinfo("Annulé", "Aucun fichier sélectionné.")
        return

    # Chemin vers FFmpeg
    ffmpeg_path = "./ffmpeg/ffmpeg/ffmpeg.exe"  # Modifiez si nécessaire

    # Fichier de sortie
    dossier = os.path.dirname(fichier_entree)
    nom_sortie = os.path.splitext(os.path.basename(fichier_entree))[0] + "Original_Contrast_4k.mp4"
    fichier_sortie = os.path.join(dossier, nom_sortie)

    # Construction de la commande FFmpeg
    filtre = (
        "format=gbrp,"
        "scale=3840:2160,"
        "frei0r=cartoon,"
        "curves=all='0/0.2 0.3/0.5 0.7/0.5 1/1',"
        "lutrgb=r='if(gt(val,120),val+50,val-50)':"
        "g='if(gt(val,120),val+50,val-50)':"
        "b='if(gt(val,120),val+50,val-50)'"
    )

    commande = [
        ffmpeg_path,
        "-i", fichier_entree,
        "-vf", filtre,
        "-c:v", "libx264",
        "-crf", "18",
        "-preset", "slow",
        "-c:a", "copy",
        fichier_sortie
    ]

    # Exécution de la commande
    try:
        subprocess.run(commande, check=True)
        messagebox.showinfo("Succès", f"✅ Conversion terminée :\n{fichier_sortie}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Erreur", f"❌ Erreur lors de la conversion :\n{e}")
    except FileNotFoundError:
        messagebox.showerror("Erreur", "❌ FFmpeg non trouvé. Vérifiez le chemin.")

# Lancer la fonction si le script est exécuté directement
if __name__ == "__main__":
    convertir_video()
