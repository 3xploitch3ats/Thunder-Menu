import sys
import subprocess
import importlib
import os
import shutil
from tkinter import Tk, filedialog
import cv2
import numpy as np

def install_and_import(package, pip_name=None):
    if pip_name is None:
        pip_name = package
    try:
        return importlib.import_module(package)
    except ImportError:
        print(f"Le module '{package}' est manquant. Installation en cours...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
        return importlib.import_module(package)

def select_file():
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Choisir une image ou une vidéo",
        filetypes=[("Images et vidéos", "*.jpg *.jpeg *.png *.mp4 *.mov *.avi")]
    )
    root.destroy()
    return file_path

def extract_last_frames_ffmpeg(video_path, output_folder, num_frames=3):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    # Extraction en PNG (sans perte)
    cmd = [
        "ffmpeg",
        "-sseof", f"-{num_frames}",
        "-i", video_path,
        "-frames:v", str(num_frames),
        os.path.join(output_folder, "frame_%03d.png")
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def enhance_reflet_zone(eye_img):
    """
    Met en valeur la zone très claire (reflet) dans l'oeil,
    sans changer la résolution ni zoomer.
    On augmente le contraste localement et colore légèrement les reflets.
    """

    # Convertir en gris pour détecter les zones claires
    gray = cv2.cvtColor(eye_img, cv2.COLOR_BGR2GRAY)

    # Seuillage sur luminosité (pixels très clairs)
    _, mask = cv2.threshold(gray, 220, 255, cv2.THRESH_BINARY)

    # Création d'une image copie pour effet
    result = eye_img.copy()

    # Accentuer les pixels clairs
    # On colore en bleu clair les pixels du reflet (ou autre couleur subtile)
    blue_highlight = np.array([255, 200, 200], dtype=np.uint8)

    # Appliquer un masque pour colorer les reflets
    # Mélange entre la couleur originale et la couleur bleu clair
    alpha = 0.6  # intensité de la coloration

    # Trouver pixels où masque=255
    indices = np.where(mask == 255)
    for y, x in zip(indices[0], indices[1]):
        original_pixel = result[y, x].astype(np.float32)
        colored_pixel = blue_highlight.astype(np.float32)
        new_pixel = (1-alpha)*original_pixel + alpha*colored_pixel
        result[y, x] = new_pixel.astype(np.uint8)

    return result

def detect_and_process_eyes(image_path, output_folder):
    img = cv2.imread(image_path)
    if img is None:
        print(f"Erreur lecture image {image_path}")
        return

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_eye.xml")

    faces = face_cascade.detectMultiScale(gray, 1.3, 5)
    count = 0
    for (x, y, w, h) in faces:
        roi_color = img[y:y+h, x:x+w]
        roi_gray = gray[y:y+h, x:x+w]

        eyes = eye_cascade.detectMultiScale(roi_gray)
        for (ex, ey, ew, eh) in eyes:
            if ey > h // 2 or ew < 30 or eh < 15:
                continue
            aspect_ratio = ew / float(eh)
            if aspect_ratio > 2.5:
                continue

            eye_img = roi_color[ey:ey+eh, ex:ex+ew]
            if eye_img.size == 0:
                continue

            # Amélioration du reflet sans zoom
            enhanced_eye = enhance_reflet_zone(eye_img)

            save_path = os.path.join(output_folder, f"eye_reflet_{count}.png")
            cv2.imwrite(save_path, enhanced_eye)
            print(f"Image oeil sauvegardée avec reflet amélioré : {save_path}")
            count += 1

def process_file(path):
    output_folder = "eyes_reflet"
    temp_frames_folder = "frames"

    if os.path.exists(output_folder):
        shutil.rmtree(output_folder)
    os.makedirs(output_folder)

    if path.lower().endswith((".mp4", ".mov", ".avi")):
        if os.path.exists(temp_frames_folder):
            shutil.rmtree(temp_frames_folder)
        os.makedirs(temp_frames_folder)
        extract_last_frames_ffmpeg(path, temp_frames_folder, num_frames=3)
        for file in os.listdir(temp_frames_folder):
            detect_and_process_eyes(os.path.join(temp_frames_folder, file), output_folder)
    else:
        detect_and_process_eyes(path, output_folder)

    print("Traitement terminé. Images enregistrées dans :", output_folder)

if __name__ == "__main__":
    filepath = select_file()
    if filepath:
        process_file(filepath)
    else:
        print("❌ Aucun fichier sélectionné.")
    input("\nAppuyez sur Entrée pour quitter...")
