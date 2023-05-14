import idaapi
import idc

def extract_function_addresses():
    # Récupérer l'adresse de base de l'image
    image_base = idaapi.get_imagebase()

    # Ouvrir le fichier de sortie en mode écriture
    with open("function_addresses.txt", "w") as f:
        # Récupérer toutes les adresses de fonctions
        func_eas = list(idautils.Functions())

        # Pour chaque adresse de fonction, écrire son adresse relative et normale à l'image de base dans le fichier
        for func_ea in func_eas:
            func_name = idc.get_func_name(func_ea)

            # Vérifier si la fonction contient la chaîne "lea /Script/"
            if "/Script/" in idc.get_func_cmt(func_ea, 0):
                # Écrire l'adresse normale et relative à l'image de base de la fonction dans le fichier
                f.write(f"0x{func_ea:X} - 0x{func_ea-image_base:X}\n")

def extract_class_and_struct_addresses():
    # Récupérer l'adresse de base de l'image
    image_base = idaapi.get_imagebase()

    # Ouvrir le fichier de sortie en mode écriture
    with open("class_and_struct_addresses.txt", "w") as f:
        # Récupérer l'adresse de début du segment .data
        seg_ea = idaapi.get_segm_by_name(".data").start_ea

        # Parcourir toutes les structures et classes définies dans le segment .data
        while seg_ea != idc.BADADDR:
            s_name = idc.get_struc_name(seg_ea)
            if s_name:
                # Écrire le nom de la structure ou de la classe et son adresse relative et normale à l'image de base dans le fichier
                f.write(f"{s_name} @ 0x{seg_ea:X} - 0x{seg_ea-image_base:X}\n")

                s_size = idc.get_struc_size(seg_ea)
                for member_offset in range(0, s_size, 4):
                    m_name = idc.get_member_name(seg_ea, member_offset)
                    if m_name:
                        # Écrire le nom du membre et son adresse relative et normale à l'image de base dans le fichier
                        f.write(f"    {m_name} @ 0x{seg_ea+member_offset:X} - 0x{seg_ea+member_offset-image_base:X}\n")
            seg_ea = idc.next_head(seg_ea)

# Appeler les fonctions pour extraire les informations
extract_function_addresses()
extract_class_and_struct_addresses()
