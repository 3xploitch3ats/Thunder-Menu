import subprocess

# Commande pour tuer le processus xmrig.exe
try:
    subprocess.run(['taskkill', '/f', '/im', 'xmrig.exe'], check=True)
    print("Le processus xmrig.exe a été arrêté avec succès.")
except subprocess.CalledProcessError as e:
    print(f"Erreur lors de l'arrêt du processus xmrig.exe : {e}")
