import sys
import subprocess
import importlib

def install_and_import(package, pip_name=None):
    if pip_name is None:
        pip_name = package
    try:
        return importlib.import_module(package)
    except ImportError:
        print(f"Le module '{package}' est manquant. Installation en cours...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
        return importlib.import_module(package)

# Ici, package=module Python, pip_name=nom pip
cv2 = install_and_import("cv2", "opencv-python")
numpy = install_and_import("numpy")  # numpy s'installe avec son nom pip habituel
tkinter = install_and_import("tkinter")  # tkinter est normalement déjà là

import os
from tkinter import Tk, filedialog
import shutil

# Le reste de ton script inchangé
def select_file():
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Choisir une image ou une vidéo",
        filetypes=[("Images et vidéos", "*.jpg *.jpeg *.png *.mp4 *.mov *.avi")]
    )
    root.destroy()
    return file_path

def extract_last_frames(video_path, output_folder, num_frames=3):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    cmd = [
        "ffmpeg",
        "-sseof", f"-{num_frames}",
        "-i", video_path,
        "-vf", "fps=1",
        os.path.join(output_folder, "frame_%03d.jpg")
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def detect_and_zoom_eyes(image_path, output_folder):
    img = cv2.imread(image_path)
    if img is None:
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

            zoomed = cv2.resize(eye_img, None, fx=10, fy=10, interpolation=cv2.INTER_CUBIC)
            cv2.imwrite(os.path.join(output_folder, f"zoom_eye_{count}.jpg"), zoomed)
            count += 1

def process_file(path):
    output_folder = "eyes_zoomed"
    temp_frames_folder = "frames"

    if os.path.exists(output_folder):
        shutil.rmtree(output_folder)
    os.makedirs(output_folder)

    if path.lower().endswith((".mp4", ".mov", ".avi")):
        if os.path.exists(temp_frames_folder):
            shutil.rmtree(temp_frames_folder)
        os.makedirs(temp_frames_folder)
        extract_last_frames(path, temp_frames_folder, num_frames=3)
        for file in os.listdir(temp_frames_folder):
            detect_and_zoom_eyes(os.path.join(temp_frames_folder, file), output_folder)
    else:
        detect_and_zoom_eyes(path, output_folder)

    print("Terminé. Résultats enregistrés dans :", output_folder)

if __name__ == "__main__":
    filepath = select_file()
    if filepath:
        process_file(filepath)
    else:
        print("❌ Aucun fichier sélectionné.")
    input("\nAppuyez sur Entrée pour quitter...")
