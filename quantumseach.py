import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
from concurrent.futures import ThreadPoolExecutor

class QuantumSearchApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Recherche quantique de texte dans des fichiers")
        self.root.geometry("800x500")

        self.search_results = []

        tk.Label(root, text="Entrez le texte à rechercher:").pack(pady=5)
        self.search_entry = tk.Entry(root, width=50)
        self.search_entry.pack(pady=5)

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="Ouvrir le dossier", command=self.open_folder).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Sauvegarder les résultats", command=self.save_results).pack(side=tk.LEFT, padx=5)

        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=25)
        self.output.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    def search_in_file(self, file_path, search_text):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if search_text in content:
                    return file_path
        except Exception:
            pass
        return None

    def open_folder(self):
        folder = filedialog.askdirectory()
        search_text = self.search_entry.get().strip()

        if not folder or not search_text:
            messagebox.showwarning("Erreur", "Veuillez choisir un dossier et entrer du texte.")
            return

        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, "Recherche quantique en cours...\n")
        self.search_results = []

        files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.search_in_file, f, search_text) for f in files]
            for future in futures:
                result = future.result()
                if result:
                    self.search_results.append(result)

        if self.search_results:
            self.output.insert(tk.END, f"Fichiers trouvés :\n" + "\n".join(self.search_results))
        else:
            self.output.insert(tk.END, "Aucun fichier trouvé contenant le texte.")

    def save_results(self):
        if not self.search_results:
            messagebox.showinfo("Info", "Aucun résultat à sauvegarder.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Fichiers texte", "*.txt")])
        if not file_path:
            return

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(self.search_results))
            messagebox.showinfo("Succès", "Résultats sauvegardés avec succès.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la sauvegarde : {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = QuantumSearchApp(root)
    root.mainloop()
