import idautils
import idaapi
import idc


def main():
    f = open("strings.txt", "w")
    image_base = idaapi.get_imagebase()
    for head in idautils.Heads():
        insn = idautils.DecodeInstruction(head)
        if insn is not None and insn.itype == idaapi.NN_call:
            called_func = insn.Op1.addr
            if idc.get_func_name(called_func).startswith("sub_"):
                lea_address = idc.prev_head(head)
                lea_insn = idautils.DecodeInstruction(lea_address)
                if lea_insn is not None and lea_insn.itype == idaapi.NN_lea:
                    string = idc.print_operand(lea_address, 1)
                    string_address_relative = lea_insn.Op2.addr - image_base
                    string_address_absolute = lea_insn.Op2.addr
                    lea_string = idc.GetDisasm(lea_address)
                    next_insn = idc.next_head(head)
                    next_insn_insn = idautils.DecodeInstruction(next_insn)
                    if next_insn_insn is not None and next_insn_insn.itype == idaapi.NN_call:
                        called_func = next_insn_insn.Op1.addr
                        call_address_relative = next_insn - image_base
                        f.write("String address: 0x{:X}, String: '{}', LEA: '{}'\n".format(string_address_absolute, string, lea_string))
                        f.write("String address relative to image base: {:#x}\n".format(abs(string_address_relative)))
                        f.write("Call address relative to image base: {:#x}\n\n".format(abs(call_address_relative)))

    f.close()


if __name__ == "__main__":
    main()
