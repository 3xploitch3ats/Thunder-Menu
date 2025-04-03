import os
import re
import tkinter as tk
from tkinter import scrolledtext, ttk
import urllib.request
from tkinter import messagebox

# Définition du fichier local
fichier_local = os.path.join(os.getcwd(), "freemode.c")
fichier_url = "https://raw.githubusercontent.com/PlayboyPrime/GTAV-Decompiled-Scripts/main/scripts/freemode.c"

# Fonction pour télécharger le fichier si nécessaire
def telecharger_fichier():
    if not os.path.exists(fichier_local):
        try:
            update_progress(20)
            urllib.request.urlretrieve(fichier_url, fichier_local)
            update_progress(50)
            return True
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec du téléchargement : {e}")
            return False
    return True

# Fonction pour mettre à jour la progressbar
def update_progress(value):
    progress_bar["value"] = value
    root.update_idletasks()

# Fonction pour charger et afficher le fichier par morceaux
def charger_fichier():
    if not telecharger_fichier():
        return
        
    update_progress(10)
    try:
        with open(fichier_local, "r", encoding="utf-8") as file:
            text_area_full.delete("1.0", tk.END)
            chunk_size = 10 * 1024 * 1024  # 10 MB par morceau
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                text_area_full.insert(tk.END, chunk)
                root.update_idletasks()
        update_progress(100)
    except Exception as e:
        text_area_full.delete("1.0", tk.END)
        text_area_full.insert(tk.END, f"Erreur de lecture : {e}")

# Fonction pour rechercher la fonction contenant "cashondeadbody" avec lecture par morceaux
def rechercher_fonction():
    btn_rechercher.config(state=tk.DISABLED)
    update_progress(10)
    
    chunk_size = 10 * 1024 * 1024  # 10 MB par morceau
    try:
        with open(fichier_local, "r", encoding="utf-8") as file:
            # Variables pour reconstituer le contenu entre morceaux
            remaining_content = ""
            function_code = ""
            found_function = False
            cashondeadbody_pos = -1
            post_cash_text = ""  # Pour accumuler le texte après cashondeadbody
            
            while True:
                chunk = file.read(chunk_size)
                if not chunk and not remaining_content:
                    break
                
                full_content = remaining_content + chunk
                
                if not found_function:
                    # Recherche de la fonction contenant cashondeadbody
                    void_positions = [m.start() for m in re.finditer(r"\bvoid\b", full_content)]
                    cash_positions = [m.start() for m in re.finditer(r"cashondeadbody", full_content)]
                    
                    for cash_pos in cash_positions:
                        void_before = [pos for pos in void_positions if pos < cash_pos]
                        if not void_before:
                            continue
                        
                        start_pos = void_before[-1]
                        start_brace = full_content.find("{", start_pos)
                        if start_brace == -1:
                            remaining_content = full_content[start_pos:]
                            continue
                        
                        brace_count = 1
                        end_pos = start_brace + 1
                        
                        while end_pos < len(full_content) and brace_count > 0:
                            if full_content[end_pos] == "{":
                                brace_count += 1
                            elif full_content[end_pos] == "}":
                                brace_count -= 1
                            end_pos += 1
                        
                        if brace_count == 0:
                            function_code = full_content[start_pos:end_pos]
                            found_function = True
                            cashondeadbody_pos = cash_pos
                            # On commence à accumuler le texte après cashondeadbody
                            post_cash_text = full_content[cash_pos:]
                            break
                
                # Si la fonction est trouvée, on continue à accumuler le texte suivant
                if found_function:
                    post_cash_text += chunk
                
                # On sort de la boucle seulement si on a trouvé la fonction ET assez de texte après
                if found_function and len(post_cash_text) > 100000:  # On lit 100KB après cashondeadbody
                    break
                
                remaining_content = full_content[-1000:] if len(full_content) > 1000 else full_content
                update_progress(min(90, progress_bar["value"] + 5))
            
            if not function_code:
                text_area_function.delete("1.0", tk.END)
                text_area_function.insert(tk.END, "Fonction contenant cashondeadbody non trouvée")
                return
            
            # Afficher la fonction trouvée
            text_area_function.delete("1.0", tk.END)
            text_area_function.insert(tk.END, function_code)
            
            # Recherche de IS_BIT_SET
            is_bit_set_match = re.search(r"IS_BIT_SET\s*\(\s*&?(Global_\d+)", function_code)
            first_global = is_bit_set_match.group(1) if is_bit_set_match else "Non trouvé"
            
            # Recherche du dernier ELSE
            last_else_matches = re.findall(r"else\s*{[^}]*?Global_\d+[^}]*}", function_code)
            last_else = last_else_matches[-1] if last_else_matches else "Non trouvé"
            
            # Dernière accolade fermante
            last_end = function_code.rfind("}")

            # Extraire le dernier Global_ du bloc ELSE trouvé
            if last_else != "Non trouvé":
                all_globals = re.findall(r"(Global_\d+)", last_else)
                last_global = all_globals[-1] if all_globals else "Aucun Global_ trouvé"
            else:
                last_global = "Non trouvé"
            
            # RECHERCHE DU GLOBAL_ APRÈS SERVICE_EARN DANS LE TEXTE ACCUMULÉ
            service_earn_global = "Non trouvé"
            if cashondeadbody_pos != -1:
                # Recherche plus robuste avec différentes orthographes possibles
                service_earn_match = re.search(
                    r"SERVICE_EARN_COLLECTABLE_COMPLETED_COLLECTION\b.*?(\bGlobal_\d+\b)", 
                    post_cash_text,
                    re.DOTALL
                )
                
                # Essai avec une orthographe alternative si non trouvé
                if not service_earn_match:
                    service_earn_match = re.search(
                        r"SERVICE_EARN_COLLECTABLE_COMPLETED_COLLECTION\b.*?(\bGlobal_\d+\b)", 
                        post_cash_text,
                        re.DOTALL
                    )
                
                if service_earn_match:
                    service_earn_global = service_earn_match.group(1)
            
            # Affichage des résultats
            text_area_first_global.delete("1.0", tk.END)
            text_area_first_global.insert(tk.END, first_global)
            
            text_area_last_else.delete("1.0", tk.END)
            text_area_last_else.insert(tk.END, last_global)
            text_area_last_else.insert(tk.END, f"\n\nDernière accolade fermante à la position : {last_end}")
            
            # Affichage dans le 5ème textarea avec informations de débogage
            text_area_service_earn.delete("1.0", tk.END)
            text_area_service_earn.insert(tk.END, f"Global_ après SERVICE_EARN: {service_earn_global}")
            
            if service_earn_global == "Non trouvé":
                text_area_service_earn.insert(tk.END, "\n\nDEBUG: Texte analysé (100 premiers caractères):")
                text_area_service_earn.insert(tk.END, f"\n{post_cash_text[:100]}...")
            
            update_progress(100)
            btn_rechercher.config(state=tk.NORMAL)
    
    except Exception as e:
        text_area_function.delete("1.0", tk.END)
        text_area_function.insert(tk.END, f"Erreur : {e}")
        btn_rechercher.config(state=tk.NORMAL)

# Interface graphique (avec ajout du 5ème textarea)
root = tk.Tk()
root.title("Analyse de cashondeadbody")
root.geometry("1100x950")  # Fenêtre légèrement agrandie

# Boutons
btn_load = tk.Button(root, text="Charger le fichier", command=charger_fichier)
btn_load.pack(pady=10)

btn_rechercher = tk.Button(root, text="Rechercher", command=rechercher_fonction)
btn_rechercher.pack(pady=10)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)

# Zones de texte
text_area_full = scrolledtext.ScrolledText(root, height=20, width=140, wrap=tk.WORD)
text_area_full.pack(pady=10)

text_area_function = scrolledtext.ScrolledText(root, height=15, width=140, wrap=tk.WORD)
text_area_function.pack(pady=10)

text_area_first_global = scrolledtext.ScrolledText(root, height=5, width=140, wrap=tk.WORD)
text_area_first_global.pack(pady=10)

text_area_last_else = scrolledtext.ScrolledText(root, height=5, width=140, wrap=tk.WORD)
text_area_last_else.pack(pady=10)

# NOUVEAU 5ème TEXTAREA
text_area_service_earn = scrolledtext.ScrolledText(root, height=5, width=140, wrap=tk.WORD)
text_area_service_earn.pack(pady=10)

root.mainloop()