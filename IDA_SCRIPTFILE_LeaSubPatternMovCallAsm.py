import idautils
import idc
import idaapi

output_file = "result.txt"

def find_mov_instructions():
    with open(output_file, "w") as file:
        imagebase = idaapi.get_imagebase()
        lea_address = None
        call_address = None
        for seg_ea in idautils.Segments():
            seg_name = idc.get_segm_name(seg_ea)
            if seg_name == ".text":
                for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                    mnem = idc.print_insn_mnem(head)
                    if mnem == "lea":
                        opnd_type = idc.get_operand_type(head, 1)
                        if opnd_type == idc.o_mem:
                            opnd = idc.get_operand_value(head, 1)
                            if idc.get_segm_name(opnd) == ".text" and idc.print_insn_mnem(opnd) == "sub":
                                lea_address = head
                                lea_hex_view = get_hex_view(lea_address)
                                sub_address = opnd
                                sub_hex_view = get_hex_view(sub_address)
                                mov_address = None
                                mov_value_hex = None
                                asm = None
                    elif mnem == "call":
                        call_address = head
                    elif mnem == "mov":
                        if lea_address and call_address and not mov_address:
                            mov_address = head
                            mov_value_hex = get_mov_value_hex(mov_address)
                            if is_valid_mov_value(mov_value_hex):
                                asm = idc.GetDisasm(mov_address)
                                if "[" not in asm and "00000" not in mov_value_hex:
                                    file.write("lea Address: {}\n".format(hex(lea_address)))
                                    file.write("lea Address - Imagebase: {}\n".format(hex(lea_address - imagebase)))
                                    file.write("lea sub Hex View: {}\n".format(sub_hex_view))
                                    file.write("mov Address: {}\n".format(hex(mov_address)))
                                    file.write("mov value: {}\n".format(mov_value_hex))
                                    file.write("call Address: {}\n".format(hex(call_address)))
                                    file.write("mov ASM: {}\n".format(asm))
                                    file.write("\n")
                                    file.write("\n")
                    else:
                        lea_address = None
                        call_address = None

def get_hex_view(address):
    bytes_str = ""
    bytes = idc.get_bytes(address, 16)
    for byte in bytes:
        bytes_str += "{:02X} ".format(byte)
    return bytes_str.strip()

def get_mov_value_hex(address):
    mov_value = idc.get_operand_value(address, 1)
    mov_value_hex = "{:016X}".format(mov_value)
    return mov_value_hex

def is_valid_mov_value(mov_value_hex):
    return len(mov_value_hex) == 16 and "00000" not in mov_value_hex

find_mov_instructions()
