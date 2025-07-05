import os
import sys
import ctypes
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def relaunch_as_admin():
    if not is_admin():
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec de l'exécution en admin: {str(e)}")
            sys.exit(1)

def run_command_safely(command):
    """Exécute une commande avec gestion robuste de l'encodage"""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            shell=True,
            text=False,  # Nous gérons nous-mêmes le décodage
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.decode('cp1252', errors='replace') if result.stderr else "Erreur inconnue"
            raise Exception(f"Commande échouée (code {result.returncode}): {error_msg}")
            
        # Essayer plusieurs encodages courants sous Windows
        encodings = ['cp1252', 'utf-8', 'latin-1']
        for encoding in encodings:
            try:
                return result.stdout.decode(encoding)
            except UnicodeDecodeError:
                continue
                
        # Si aucun encodage ne fonctionne, retourner le texte avec remplacement des erreurs
        return result.stdout.decode('cp1252', errors='replace')
        
    except Exception as e:
        raise Exception(f"Erreur d'exécution: {str(e)}")

def get_task_names():
    """Récupère les noms des tâches sans les chemins et les trie alphabétiquement"""
    try:
        # Essayer d'abord avec le format CSV
        output = run_command_safely('schtasks /query /fo CSV')
        if output:
            lines = output.splitlines()
            if len(lines) > 1:
                task_names = []
                for line in lines[1:]:  # Ignorer l'en-tête
                    if line.strip():
                        parts = line.split(',', 1)
                        if parts and parts[0]:
                            full_name = parts[0].strip('"')
                            task_names.append(full_name.split('\\')[-1])
                if task_names:
                    return sorted(task_names, key=lambda x: x.lower())  # Tri insensible à la casse
        
        # Si CSV échoue ou ne retourne rien, essayer avec LIST
        output = run_command_safely('schtasks /query /fo LIST')
        if output:
            task_names = []
            for line in output.splitlines():
                if line.strip().startswith('TaskName:'):
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        full_name = parts[1].strip()
                        task_names.append(full_name.split('\\')[-1])
            if task_names:
                return sorted(task_names, key=lambda x: x.lower())  # Tri insensible à la casse
        
        raise Exception("Aucune tâche trouvée dans la sortie de schtasks")
        
    except Exception as e:
        messagebox.showerror("Erreur", f"Échec de la récupération des tâches: {str(e)}")
        return []

class SimpleTaskManager:
    def __init__(self, root):
        self.root = root
        self.setup_ui()
        self.load_tasks()
        
    def setup_ui(self):
        self.root.title("Gestionnaire de Tâches Planifiées")
        self.root.geometry("800x600")
        
        # Frame principale
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill='both', expand=True)
        
        # Treeview avec barre de défilement
        self.tree = ttk.Treeview(main_frame, columns=("Nom",), show='headings', height=25)
        self.tree.heading("Nom", text="Nom de la tâche (tri alphabétique)")
        self.tree.column("Nom", width=700)
        
        scrollbar = ttk.Scrollbar(main_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Placement
        self.tree.grid(row=0, column=0, sticky='nsew')
        scrollbar.grid(row=0, column=1, sticky='ns')
        
        # Configuration du redimensionnement
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
        
        # Frame pour les boutons
        btn_frame = ttk.Frame(self.root, padding="10")
        btn_frame.pack(fill='x')
        
        ttk.Button(
            btn_frame, 
            text="Supprimer la tâche sélectionnée",
            command=self.delete_task
        ).pack(side='left', padx=5)
        
        ttk.Button(
            btn_frame,
            text="Actualiser",
            command=self.load_tasks
        ).pack(side='left', padx=5)

    def load_tasks(self):
        """Charge les tâches triées dans l'interface"""
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        task_names = get_task_names()
        
        if not task_names:
            messagebox.showinfo("Info", "Aucune tâche planifiée trouvée")
            return
            
        for name in task_names:
            self.tree.insert('', 'end', values=(name,))

    def delete_task(self):
        """Supprime la tâche sélectionnée"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Avertissement", "Veuillez sélectionner une tâche")
            return
            
        task_name = self.tree.item(selected[0], 'values')[0]
        
        if not messagebox.askyesno("Confirmation", f"Supprimer la tâche '{task_name}' ?"):
            return
            
        try:
            # On doit trouver le nom complet avec le chemin
            full_name = self.find_full_task_name(task_name)
            if not full_name:
                raise Exception("Impossible de trouver le nom complet de la tâche")
                
            # Exécuter la suppression
            result = run_command_safely(f'schtasks /delete /tn "{full_name}" /f')
            messagebox.showinfo("Succès", f"Tâche '{task_name}' supprimée avec succès")
            self.load_tasks()
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec de la suppression: {str(e)}")

    def find_full_task_name(self, short_name):
        """Trouve le nom complet de la tâche à partir du nom court"""
        try:
            # Essayer avec le format LIST d'abord
            output = run_command_safely('schtasks /query /fo LIST')
            if output:
                for line in output.splitlines():
                    if line.strip().startswith('TaskName:'):
                        parts = line.split(':', 1)
                        if len(parts) > 1 and short_name in parts[1].strip():
                            full_name = parts[1].strip()
                            if full_name.endswith(short_name):
                                return full_name
            
            # Si LIST ne fonctionne pas, essayer CSV
            output = run_command_safely('schtasks /query /fo CSV')
            if output:
                for line in output.splitlines()[1:]:  # Ignorer l'en-tête
                    if line.strip():
                        parts = line.split(',', 1)
                        if parts and parts[0] and short_name in parts[0]:
                            full_name = parts[0].strip('"')
                            if full_name.endswith(short_name):
                                return full_name
                                
            return None
        except:
            return None

def main():
    relaunch_as_admin()
    root = tk.Tk()
    app = SimpleTaskManager(root)
    root.mainloop()

if __name__ == "__main__":
    main()