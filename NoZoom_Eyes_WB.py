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

def apply_black_white_eye_vision(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Emboss effect (relief)
    kernel = np.array([[ -2, -1,  0],
                       [ -1,  1,  1],
                       [  0,  1,  2]])
    embossed = cv2.filter2D(gray, -1, kernel)

    # Courbes de contraste simulées (augmentation contraste)
    # Mappe les tons sombres et clairs pour créer un effet plus dramatique
    table = np.interp(np.arange(256), [0, 76, 179, 255], [25, 70, 200, 255]).astype(np.uint8)
    curved = cv2.LUT(embossed, table)

    # Seuil pour effet "vision robotique"
    _, thresholded = cv2.threshold(curved, 120, 255, cv2.THRESH_BINARY)

    return thresholded

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

            # Remplace ici le reflet par vision noir et blanc
            processed_eye = apply_black_white_eye_vision(eye_img)

            # Convertir en BGR pour sauvegarde propre
            processed_eye_bgr = cv2.cvtColor(processed_eye, cv2.COLOR_GRAY2BGR)

            save_path = os.path.join(output_folder, f"eye_scene_bw_{count}.png")
            cv2.imwrite(save_path, processed_eye_bgr)
            print(f"Image oeil avec scène noir et blanc sauvegardée : {save_path}")
            count += 1

def process_file(path):
    output_folder = "eye_scene_output"
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

def extract_last_frames_ffmpeg(video_path, output_folder, num_frames=3):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    cmd = [
        "ffmpeg",
        "-sseof", f"-{num_frames}",
        "-i", video_path,
        "-frames:v", str(num_frames),
        os.path.join(output_folder, "frame_%03d.png")
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    filepath = select_file()
    if filepath:
        process_file(filepath)
    else:
        print("❌ Aucun fichier sélectionné.")
    input("\nAppuyez sur Entrée pour quitter...")
