import json
import os
import sys
from PIL import Image
from tkinter import filedialog, Tk, Label, Entry, Scale, Checkbutton, Button, IntVar, HORIZONTAL, StringVar

HISTORY_JSON = "conversion_history.json"

def save_json_unique(image_path, width, height, output_file):
    data = {
        "image_path": image_path,
        "width": width,
        "height": height,
        "output_file": output_file
    }
    try:
        with open(HISTORY_JSON, "w", encoding="utf-8") as f:
            json.dump([data], f, indent=4, ensure_ascii=False)
        print(f"✅ {HISTORY_JSON} écrasé avec une nouvelle entrée.")
    except Exception as e:
        print(f"⚠️ Impossible d'écrire {HISTORY_JSON} : {e}")

def image_to_html(image_path, output_file, width, height, autosize):
    try:
        img = Image.open(image_path).convert("RGB")
    except Exception as e:
        print(f"❌ Erreur de chargement de l'image : {e}")
        return

    if autosize:
        width, height = img.size

    img = img.resize((width, height))

    html = [
        '<html><head><meta charset="utf-8">',
        '<style>body{background:#000}pre{font-size:9px;font-weight:bold;line-height:9px;}</style>',
        '</head><body><pre>'
    ]

    for y in range(height):
        line = ""
        for x in range(width):
            r, g, b = img.getpixel((x, y))
            hex_color = f"#{r:02X}{g:02X}{b:02X}"
            brightness = (r + g + b) // 3
            char = '1' if brightness < 128 else '0'
            line += f'<b style="color:{hex_color}">{char}</b>'
        html.append(line)

    html.append('</pre></body></html>')

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write('\n'.join(html))
        print(f"✅ Image convertie avec succès : {output_file}")
        os.system(f'start "" "{output_file}"')  # Ouvre automatiquement sous Windows
    except Exception as e:
        print(f"❌ Erreur d’écriture du fichier HTML : {e}")

def launch_gui():
    root = Tk()
    root.title("Image vers HTML")
    root.geometry("400x360")

    selected_image = StringVar()
    output_name = StringVar(value="output.html")
    autosize_var = IntVar(value=0)
    image_dimensions = {"width": 100, "height": 100}

    def choose_image():
        path = filedialog.askopenfilename(
            title="Sélectionner une image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.gif")]
        )
        if path:
            selected_image.set(path)
            image_label.config(text=os.path.basename(path))
            try:
                img = Image.open(path)
                w, h = img.size
                image_dimensions["width"] = w
                image_dimensions["height"] = h

                if not autosize_var.get():
                    width_slider.set(w)
                    height_slider.set(h)
            except Exception:
                print("❌ Erreur de chargement de l'image.")

    def on_autosize_toggle():
        if autosize_var.get():
            width_slider.config(state="disabled")
            height_slider.config(state="disabled")
        else:
            width_slider.config(state="normal")
            height_slider.config(state="normal")
            if selected_image.get():
                width_slider.set(image_dimensions["width"])
                height_slider.set(image_dimensions["height"])

    def on_ok():
        path = selected_image.get()
        if not path:
            print("❌ Aucune image sélectionnée.")
            return

        width = width_slider.get()
        height = height_slider.get()
        output_file = output_name.get().strip()
        if not output_file.lower().endswith(".html"):
            output_file += ".html"

        save_json_unique(path, width, height, output_file)
        image_to_html(path, output_file, width, height, autosize_var.get())

    Button(root, text="Add Image", command=choose_image).pack(pady=5)
    image_label = Label(root, text="Aucune image sélectionnée.")
    image_label.pack()

    Checkbutton(root, text="Auto Size (taille réelle de l’image)", variable=autosize_var, command=on_autosize_toggle).pack(pady=5)

    Label(root, text="Largeur (Width)").pack()
    width_slider = Scale(root, from_=10, to=1000, orient=HORIZONTAL)
    width_slider.set(100)
    width_slider.pack()

    Label(root, text="Hauteur (Height)").pack()
    height_slider = Scale(root, from_=10, to=1000, orient=HORIZONTAL)
    height_slider.set(100)
    height_slider.pack()

    Label(root, text="Nom du fichier HTML").pack()
    Entry(root, textvariable=output_name).pack(pady=5)

    Button(root, text="OK", command=on_ok).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    if len(sys.argv) == 5:
        image_path = sys.argv[1]
        try:
            width = int(sys.argv[2])
            height = int(sys.argv[3])
        except ValueError:
            print("❌ Width et height doivent être des entiers.")
            sys.exit(1)
        output_file = sys.argv[4]
        if not output_file.lower().endswith(".html"):
            output_file += ".html"

        # Sauvegarde JSON
        save_json_unique(image_path, width, height, output_file)
        # Conversion
        image_to_html(image_path, output_file, width, height, autosize=False)

    elif len(sys.argv) == 1:
        launch_gui()

    else:
        print("Usage: python script.py \"chemin/image.png\" width height output.html")
        sys.exit(1)

# ImageHtml1.py "LOGO-BAYLIFE1.bmp" 200 200 result.html
