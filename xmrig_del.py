import shutil
import os

# Chemin du dossier à supprimer
dossier_a_supprimer = r'C:\Program Files\Common Files\xmrig'

try:
    # Vérification si le dossier existe avant de le supprimer
    if os.path.exists(dossier_a_supprimer):
        # Suppression du dossier et de son contenu
        shutil.rmtree(dossier_a_supprimer)
        print(f"Dossier {dossier_a_supprimer} supprimé avec succès.")
    else:
        print(f"Le dossier {dossier_a_supprimer} n'existe pas.")
except Exception as e:
    print(f"Erreur lors de la suppression du dossier : {e}")
