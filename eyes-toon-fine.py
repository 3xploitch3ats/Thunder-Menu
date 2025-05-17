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

def cartoon_effect_soft(img):
    # Convertir en gris
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    # Lissage doux
    gray_blur = cv2.GaussianBlur(gray, (5,5), 0)
    # Seuillage adaptatif plus doux
    edges = cv2.adaptiveThreshold(
        gray_blur, 255,
        cv2.ADAPTIVE_THRESH_MEAN_C,
        cv2.THRESH_BINARY,
        blockSize=11,
        C=5
    )
    # Réduction des couleurs (quantification) légère
    data = np.float32(img).reshape((-1, 3))
    criteria = (cv2.TERM_CRITERIA_EPS + cv2.TERM_CRITERIA_MAX_ITER, 15, 0.01)
    K = 6  # nombre de couleurs (moins = plus cartoon)
    _, label, center = cv2.kmeans(data, K, None, criteria, 10, cv2.KMEANS_RANDOM_CENTERS)
    center = np.uint8(center)
    quantized = center[label.flatten()]
    quantized = quantized.reshape(img.shape)

    # Estomper un peu les contours pour ne pas écraser les détails
    edges_blur = cv2.GaussianBlur(edges, (7,7), 2)
    edges_blur = cv2.normalize(edges_blur, None, 0, 255, cv2.NORM_MINMAX)

    # Créer masque flottant entre 0 et 1
    mask = edges_blur.astype(float)/255

    # Mélanger image quantifiée et originale selon le masque
    cartoon_soft = np.zeros_like(img, dtype=np.uint8)
    for c in range(3):
        cartoon_soft[:,:,c] = (quantized[:,:,c].astype(float)*mask + img[:,:,c].astype(float)*(1-mask)).astype(np.uint8)

    return cartoon_soft

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
            # Filtrage des yeux trop bas ou trop petits ou avec mauvais ratio
            if ey > h // 2 or ew < 30 or eh < 15:
                continue
            aspect_ratio = ew / float(eh)
            if aspect_ratio > 2.5:
                continue

            eye_img = roi_color[ey:ey+eh, ex:ex+ew]
            if eye_img.size == 0:
                continue

            # Appliquer effet cartoon doux
            cartoon_eye = cartoon_effect_soft(eye_img)

            save_path = os.path.join(output_folder, f"eye_cartoon_{count}.png")
            cv2.imwrite(save_path, cartoon_eye)
            print(f"Image œil cartoon sauvegardée : {save_path}")
            count += 1

def process_file(path):
    output_folder = "eyes_cartoon"
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

    print("\n🎉 Traitement terminé. Images enregistrées dans :", output_folder)

if __name__ == "__main__":
    filepath = select_file()
    if filepath:
        process_file(filepath)
    else:
        print("❌ Aucun fichier sélectionné.")
    input("\nAppuyez sur Entrée pour quitter...")
