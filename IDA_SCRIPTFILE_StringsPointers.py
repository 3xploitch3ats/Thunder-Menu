import idautils
import idaapi
import ida_bytes
import ida_nalt

def extract_strings_pointers():
    # Récupérer l'adresse de base de l'image
    image_base = idaapi.get_imagebase()

    # Ouvrir le fichier pour écrire les résultats
    with open("strings.txt", "w") as file:
        # Parcourir toutes les sections
        for seg in idautils.Segments():
            seg_ea = idaapi.getseg(seg).start_ea
            seg_end_ea = idaapi.getseg(seg).end_ea
            # Ne traiter que les sections de données
            if idaapi.getseg(seg).type == idaapi.SEG_DATA:
                # Parcourir toutes les adresses de la section
                for head in idautils.Heads(seg_ea, seg_end_ea):
                    # Vérifier si l'adresse contient une chaîne de caractères
                    if ida_bytes.is_strlit(ida_bytes.get_flags(head)):
                        # Obtenir la chaîne de caractères à partir de l'adresse
                        string = ida_bytes.get_strlit_contents(head, ida_bytes.get_max_strlit_length(head, ida_nalt.STRTYPE_C), ida_nalt.STRTYPE_C)

                        # Écrire l'adresse et la chaîne de caractères dans le fichier
                        file.write("Adresse normale : 0x{:X} -- Adresse ImageBase : 0x{:X} -- String : {}\n".format(head, head - image_base, string))

# Appeler la fonction pour extraire les adresses des chaînes de caractères et des pointeurs
extract_strings_pointers()
