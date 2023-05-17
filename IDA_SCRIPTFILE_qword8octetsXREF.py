import idautils
import idaapi

# Chemin du fichier texte de sortie
output_file = "result.txt"

# Fonction de recherche des chaînes de caractères
def find_strings():
    with open(output_file, "w") as file:
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            seg_name = idaapi.get_segm_name(seg)
            if seg_name == ".data":
                for head in idautils.Heads(seg.start_ea, seg.end_ea):
                    if idaapi.get_item_size(head) == 8:
                        value = idaapi.get_qword(head)
                        if value >= 0x1000000000000000 and value <= 0xFFFFFFFFFFFFFFFF:
                            address = head
                            imagebase = idaapi.get_imagebase()
                            address_offset = address - imagebase
                            string = idaapi.get_strlit_contents(address, idaapi.get_item_size(head), idaapi.STRTYPE_C)
                            decoded_string = string.decode("utf-8", "ignore").strip()
                            filtered_string = "".join(c for c in decoded_string if c.isprintable())
                            if filtered_string:
                                file.write("Address: {}\n".format(hex(address)))
                                file.write("Address - Imagebase: {}\n".format(hex(address_offset)))
                                file.write("Value: {}\n".format(hex(value)))
                                file.write("String: {}\n".format(filtered_string))
                                file.write("\n")

                                # Trouver le premier xref à l'adresse
                                xrefs = idautils.XrefsTo(address, 0)
                                xref = next(xrefs, None)
                                if xref:
                                    xref_address = xref.frm
                                    pseudocode = idaapi.decompile(xref_address)
                                    if pseudocode:
                                        pseudocode_lines = pseudocode.get_pseudocode()
                                        if pseudocode_lines:
                                            first_line = pseudocode_lines[0]
                                            filtered_function = "".join(c for c in first_line.line if c.isprintable())
                                            file.write("Xref Address: {}\n".format(hex(xref_address)))
                                            file.write("Xref Address - Imagebase: {}\n".format(hex(xref_address - imagebase)))
                                            file.write("Function: {}\n".format(filtered_function))
                                            file.write("\n")

# Appeler la fonction de recherche des chaînes de caractères
find_strings()
