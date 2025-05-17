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

def apply_cartoon_effect(img):
    # 1. Réduction du bruit
    color = cv2.bilateralFilter(img, d=9, sigmaColor=75, sigmaSpace=75)

    # 2. Détection des bords
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    edges = cv2.adaptiveThreshold(
        cv2.medianBlur(gray, 7), 255,
        cv2.ADAPTIVE_THRESH_MEAN_C, cv2.THRESH_BINARY, 9, 2
    )
    edges_colored = cv2.cvtColor(edges, cv2.COLOR_GRAY2BGR)

    # 3. Fusion cartoon
    cartoon = cv2.bitwise_and(color, edges_colored)

    return cartoon

def apply_contrast_curve(img):
    original = np.arange(256)
    curve = np.interp(original, [0, 76, 179, 255], [50, 127, 127, 255]).astype(np.uint8)
    return cv2.LUT(img, curve)

def apply_lutrgb_like(img):
    def custom_lut(channel):
        lut = np.array([min(255, max(0, v + 50 if v > 120 else v - 50)) for v in range(256)], dtype=np.uint8)
        return cv2.LUT(channel, lut)

    b, g, r = cv2.split(img)
    b = custom_lut(b)
    g = custom_lut(g)
    r = custom_lut(r)
    return cv2.merge((b, g, r))

def cartoonize_and_save(img_path, output_folder, index=0):
    img = cv2.imread(img_path)
    if img is None:
        print(f"Erreur lecture image : {img_path}")
        return

    cartoon = apply_cartoon_effect(img)
    contrast = apply_contrast_curve(cartoon)
    final = apply_lutrgb_like(contrast)

    save_path = os.path.join(output_folder, f"cartoon_{index}.png")
    cv2.imwrite(save_path, final)
    print(f"✅ Image cartoon sauvegardée : {save_path}")

def process_file(path):
    output_folder = "cartoon_output"
    temp_frames_folder = "frames"

    if os.path.exists(output_folder):
        shutil.rmtree(output_folder)
    os.makedirs(output_folder)

    if path.lower().endswith((".mp4", ".mov", ".avi")):
        if os.path.exists(temp_frames_folder):
            shutil.rmtree(temp_frames_folder)
        os.makedirs(temp_frames_folder)
        extract_last_frames_ffmpeg(path, temp_frames_folder, num_frames=3)
        for idx, file in enumerate(os.listdir(temp_frames_folder)):
            cartoonize_and_save(os.path.join(temp_frames_folder, file), output_folder, idx)
    else:
        cartoonize_and_save(path, output_folder)

    print("\n🎉 Traitement terminé. Images enregistrées dans :", output_folder)

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
