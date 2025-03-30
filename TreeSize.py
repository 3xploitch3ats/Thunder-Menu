import os
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path


# Créer la fenêtre principale
root = tk.Tk()
root.title("Explorateur de Fichiers et Dossiers")
root.geometry("1000x700")

# Variables globales
current_path = os.getcwd()
clipboard = {"action": "", "items": []}
sort_column = None
sort_reverse = False


# Fonction pour mettre à jour la liste des fichiers/dossiers
def update_listview(path):
    global current_path
    listview.delete(*listview.get_children())
    path_entry.delete(0, tk.END)
    path_entry.insert(0, path)
    current_path = path

    try:
        # Ajouter l'option ".." pour remonter d'un niveau
        if os.path.dirname(path):
            listview.insert("", "end", values=("..", "Dossier", "", ""), tags=("folder",))

        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            item_type = "Dossier" if os.path.isdir(item_path) else "Fichier"
            size = calculate_size(item_path) if os.path.exists(item_path) else "Erreur"
            listview.insert("", "end", values=(item, item_type, size, ""), tags=("folder" if item_type == "Dossier" else "file",))
    except PermissionError:
        messagebox.showerror("Erreur", f"Accès refusé à {path}")


# Calculer la taille des fichiers et dossiers
def calculate_size(path):
    try:
        if os.path.isfile(path):
            size = os.path.getsize(path) / (1024 * 1024)  # Taille en Mo
            return round(size, 2)
        elif os.path.isdir(path):
            total_size = 0
            for root_dir, _, files in os.walk(path, followlinks=False):
                for file in files:
                    try:
                        file_path = os.path.join(root_dir, file)
                        total_size += os.path.getsize(file_path)
                    except (PermissionError, FileNotFoundError):
                        continue
            return round(total_size / (1024 * 1024), 2)  # Taille des dossiers en Mo
        else:
            return 0
    except Exception as e:
        return "Erreur"


# Double-clic pour naviguer dans les dossiers
def on_item_double_click(event):
    selected_item = listview.selection()
    if not selected_item:
        return

    item_text = listview.item(selected_item, "values")[0]

    if item_text == "..":
        new_path = os.path.dirname(current_path)
    else:
        new_path = os.path.join(current_path, item_text)

    if os.path.isdir(new_path):
        update_listview(new_path)
    elif os.path.isfile(new_path):
        os.startfile(new_path)


# Copier ou couper les fichiers
def copy_or_cut(action):
    selected_items = listview.selection()
    clipboard["action"] = action
    clipboard["items"] = [os.path.join(current_path, listview.item(item, "values")[0]) for item in selected_items]


# Coller les fichiers/dossiers
def paste_items():
    for item in clipboard["items"]:
        dest = os.path.join(current_path, os.path.basename(item))
        try:
            if clipboard["action"] == "Copy":
                if os.path.isdir(item):
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)
            elif clipboard["action"] == "Cut":
                shutil.move(item, dest)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du collage : {e}")
    update_listview(current_path)


# Supprimer les fichiers/dossiers
def delete_items():
    selected_items = listview.selection()
    for item in selected_items:
        item_path = os.path.join(current_path, listview.item(item, "values")[0])
        try:
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la suppression : {e}")
    update_listview(current_path)


# Tri des colonnes
def sort_column_data(column_index):
    global sort_column, sort_reverse

    items = [(listview.item(item, "values"), item) for item in listview.get_children()]
    if column_index == 2:  # Tri par taille
        try:
            items.sort(key=lambda x: float(x[0][2]) if x[0][2] != "Accès Refusé" and x[0][2] != "" else 0.0, reverse=sort_reverse)
        except ValueError:
            items.sort(reverse=sort_reverse)
    else:  # Tri par nom ou type
        items.sort(key=lambda x: x[0][column_index], reverse=sort_reverse)

    for index, (values, item) in enumerate(items):
        listview.move(item, "", index)

    # Inverser l'ordre pour le prochain clic
    sort_reverse = not sort_reverse
    sort_column = column_index


# Gestion de la sélection multiple avec la souris
def on_mouse_drag(event):
    item = listview.identify_row(event.y)
    if item:
        listview.selection_add(item)
    auto_scroll(event)


# Défilement automatique lors de la sélection multiple avec la souris
def auto_scroll(event):
    y_mouse = event.y
    height = listview.winfo_height()

    if y_mouse < 20:  # Défilement vers le haut
        listview.yview_scroll(-1, "units")
    elif y_mouse > height - 20:  # Défilement vers le bas
        listview.yview_scroll(1, "units")


# Interface utilisateur
frame_top = tk.Frame(root)
frame_top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

# Sélection du lecteur
label_drive = tk.Label(frame_top, text="Sélectionnez un lecteur :")
label_drive.grid(row=0, column=0, sticky="w")

combo_drive = ttk.Combobox(frame_top, width=10)
combo_drive.grid(row=0, column=1, padx=5)
combo_drive["values"] = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
combo_drive.current(0)

# Bouton Scan
button_scan = tk.Button(frame_top, text="Scan", command=lambda: update_listview(combo_drive.get()))
button_scan.grid(row=0, column=2, padx=5)

# Chemin actuel
path_entry = tk.Entry(frame_top, width=80)
path_entry.grid(row=1, column=0, columnspan=3, sticky="we", pady=5)

# Conteneur avec Scrollbar pour ListView
frame_list = tk.Frame(root)
frame_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

# Ajout d'une barre de défilement verticale
scrollbar_y = ttk.Scrollbar(frame_list, orient="vertical")
scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

# ListView pour les fichiers/dossiers
columns = ("Nom", "Type", "Taille (Mo)", "")  # Ajout d'une colonne vide
listview = ttk.Treeview(frame_list, columns=columns, show="headings", height=25, yscrollcommand=scrollbar_y.set, selectmode="extended")
listview.heading("Nom", text="Nom", anchor="w", command=lambda: sort_column_data(0))
listview.heading("Type", text="Type", anchor="w", command=lambda: sort_column_data(1))
listview.heading("Taille (Mo)", text="Taille (Mo)", anchor="e", command=lambda: sort_column_data(2))
listview.heading("", text="", anchor="w")  # Colonne vide pour éviter la sélection après

# Largeur des colonnes
listview.column("Nom", width=400, anchor="w")
listview.column("Type", width=100, anchor="w")
listview.column("Taille (Mo)", width=100, anchor="e")
listview.column("", width=10, anchor="w")  # Colonne vide pour empêcher la sélection

listview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Lier la scrollbar à la ListView
scrollbar_y.config(command=listview.yview)

# Événements
listview.bind("<Double-1>", on_item_double_click)
listview.bind("<B1-Motion>", on_mouse_drag)

# Menu contextuel
context_menu = tk.Menu(root, tearoff=0)
context_menu.add_command(label="Copier", command=lambda: copy_or_cut("Copy"))
context_menu.add_command(label="Couper", command=lambda: copy_or_cut("Cut"))
context_menu.add_command(label="Coller", command=paste_items)
context_menu.add_separator()
context_menu.add_command(label="Supprimer", command=delete_items)

listview.bind("<Button-3>", lambda event: context_menu.post(event.x_root, event.y_root))

# Initialiser la vue
update_listview(current_path)

root.mainloop()
