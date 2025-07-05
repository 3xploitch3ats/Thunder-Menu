import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime

def create_scheduled_task(task_name, executable_path, days, hours, minutes):
    # Supprimer l'ancienne tâche si elle existe
    subprocess.run(["schtasks", "/Delete", "/TN", task_name, "/F"], stderr=subprocess.DEVNULL)

    # Heure actuelle comme début
    start_time = datetime.now().strftime("%H:%M")

    # Créer la commande
    command = [
        "schtasks", "/create",
        "/tn", task_name,
        "/tr", executable_path,
        "/sc", "minute",
        "/mo", str(minutes),
        "/st", start_time
    ]

    # Exécuter la commande
    subprocess.run(command)
    messagebox.showinfo("Tâche créée", f"La tâche '{task_name}' s'exécutera toutes les {minutes} minutes.")

def main_gui():
    # Étape 1 : sélectionner un fichier .exe
    file_path = filedialog.askopenfilename(
        title="Sélectionnez un exécutable",
        filetypes=[("Executable Files", "*.exe"), ("Tous les fichiers", "*.*")]
    )

    if not file_path:
        messagebox.showinfo("Annulé", "Aucun fichier sélectionné.")
        return

    # Étape 2 : créer la fenêtre avec le formulaire
    window = tk.Tk()
    window.title("Créer une tâche planifiée")
    window.geometry("400x300")
    window.resizable(False, False)

    tk.Label(window, text="Nom de la tâche:").pack(anchor="w", padx=10, pady=(10, 0))
    entry_name = tk.Entry(window, width=40)
    entry_name.pack(padx=10, pady=(0, 10))

    frame = tk.Frame(window)
    frame.pack()

    # Jours
    tk.Label(frame, text="Jours (0-30):").grid(row=0, column=0)
    combo_days = ttk.Combobox(frame, values=list(range(0, 31)), width=5, state="readonly")
    combo_days.current(0)
    combo_days.grid(row=1, column=0, padx=5)

    # Heures
    tk.Label(frame, text="Heures (0-24):").grid(row=0, column=1)
    combo_hours = ttk.Combobox(frame, values=list(range(0, 25)), width=5, state="readonly")
    combo_hours.current(0)
    combo_hours.grid(row=1, column=1, padx=5)

    # Minutes
    tk.Label(frame, text="Minutes (1-60):").grid(row=0, column=2)
    combo_minutes = ttk.Combobox(frame, values=list(range(1, 61)), width=5, state="readonly")
    combo_minutes.current(4)  # par défaut 5 minutes
    combo_minutes.grid(row=1, column=2, padx=5)

    # Bouton OK
    def on_ok():
        task_name = entry_name.get().strip()
        if not task_name:
            messagebox.showwarning("Erreur", "Veuillez entrer un nom de tâche.")
            return
        create_scheduled_task(
            task_name,
            file_path,
            int(combo_days.get()),
            int(combo_hours.get()),
            int(combo_minutes.get())
        )
        window.destroy()

    ok_btn = tk.Button(window, text="Créer la tâche", command=on_ok)
    ok_btn.pack(pady=20)

    window.mainloop()

if __name__ == "__main__":
    if len(sys.argv) == 6:
        _, task_name, executable_path, days, hours, minutes = sys.argv
        create_scheduled_task(task_name, executable_path, int(days), int(hours), int(minutes))
    else:
        main_gui()

#python schedule.py "MyTask" "C:\path\to\your.exe" 0 0 5
