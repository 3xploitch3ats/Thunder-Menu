import idautils
import idaapi
import idc

def main():
    f = open("leas.txt", "w", encoding="utf-8")
    image_base = idaapi.get_imagebase()
    for seg_ea in idautils.Segments():
        if idc.get_segm_name(seg_ea) == ".text":
            seg_start = idc.get_segm_start(seg_ea)
            seg_end = idc.get_segm_end(seg_ea)
            for head in idautils.Heads(seg_start, seg_end):
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, head):
                    if insn.itype == idaapi.NN_lea:
                        opnd1 = insn.Op1
                        opnd2 = insn.Op2
                        if opnd2.type == idaapi.o_mem:
                            string_address_absolute = opnd2.addr
                            string_address_relative = string_address_absolute - image_base
                            string_size = idaapi.get_item_size(string_address_absolute)
                            string = idc.get_bytes(string_address_absolute, string_size)
                            if string and b'"' in string:
                                try:
                                    string = string.decode('utf-16')
                                except UnicodeDecodeError:
                                    string = string.decode('latin-1', 'replace')
                                lea_string = idc.GetDisasm(head)
                                f.write("String address: 0x{:X}\n".format(string_address_absolute))
                                f.write("LEA (normal): '{}'\n".format(lea_string))
                                f.write("String address relative to image base: {}\n".format(abs(string_address_relative)))
                                f.write("Instruction address relative to image base: 0x{:X}\n".format(abs(head - image_base)))
                                f.write("Instruction address (normal): 0x{:X}\n\n".format(head))
                            else:
                                lea_string = idc.GetDisasm(head)
                                f.write("LEA (normal): '{}'\n".format(lea_string))
                                f.write("Instruction address relative to image base: 0x{:X}\n".format(abs(head - image_base)))
                                f.write("Instruction address (normal): 0x{:X}\n\n".format(head))
    f.close()

if __name__ == "__main__":
    main()
