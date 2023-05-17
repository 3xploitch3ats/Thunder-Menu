import idautils
import idaapi

# Chemin du fichier texte de sortie
output_file = "result.txt"

# Liste des encodages à essayer
encodings = ["utf-8", "latin-1", "utf-16", "utf-16le", "utf-16be"]

# Fonction de recherche des chaînes de caractères
def find_strings():
    with open(output_file, "w") as file:
        # Parcourir toutes les adresses dans le désassemblage
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            seg_name = idaapi.get_segm_name(seg)
            if seg_name == ".data":
                # Parcourir toutes les adresses dans le segment .data
                for head in idautils.Heads(seg.start_ea, seg.end_ea):
                    # Vérifier si l'instruction est une donnée de 8 octets
                    if idaapi.get_item_size(head) == 8:
                        # Récupérer la valeur de la donnée
                        value = idaapi.get_qword(head)

                        # Vérifier si la valeur correspond au format de 16 chiffres hexadécimaux
                        if value >= 0x1000000000000000 and value <= 0xFFFFFFFFFFFFFFFF:
                            # Récupérer l'adresse et l'adresse - imagebase
                            address = head
                            imagebase = idaapi.get_imagebase()
                            address_offset = address - imagebase

                            # Récupérer le string associé à l'adresse
                            string = idaapi.get_strlit_contents(address, idaapi.get_item_size(head), idaapi.STRTYPE_C)

                            # Essayer de décoder le string en utilisant différents encodages
                            decoded_string = None
                            for encoding in encodings:
                                try:
                                    decoded_string = string.decode(encoding)
                                    break
                                except UnicodeDecodeError:
                                    continue

                            # Vérifier si le décodage a réussi
                            if decoded_string is not None:
                                # Supprimer les caractères non imprimables
                                filtered_string = "".join(c for c in decoded_string if c.isprintable())

                                # Écrire les résultats dans le fichier texte
                                file.write("Address: {}\n".format(hex(address)))
                                file.write("Address - Imagebase: {}\n".format(hex(address_offset)))
                                file.write("Value: {}\n".format(hex(value)))
                                file.write("String: {}\n".format(filtered_string))
                                file.write("\n")

# Appeler la fonction de recherche des chaînes de caractères
find_strings()
