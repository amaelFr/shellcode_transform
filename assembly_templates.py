#!/usr/bin/python3

from utils import error

template_start = """
global _start
_start:"""

tempalte_decode = """
decode_{}:{}
    loop decode_{}
"""

template_xor_last_byte = """
        mov {}, [{} + ecx -1 ]          ; use for last byte eax, ebx, edx; second param """

template_xor = """
        xor byte [{} + ecx], {}     ; xor with single byte value need or last byte => register al, bl, dl; operation with shellcode len need -1"""

template_sub_add_rotation = """
        {} BYTE [{} + ecx], {} ; byte sub or add or rotation; -1 if shellcode len"""

tempalte_short_jmp = """
    jmp short encoded_shellcode     ; do the thing"""

template_end = """
get_address:
    call decoder
    encoded_shellcode: db """

def ecx_len(counter, opti: bool = True) -> str:
    if counter >= 2**(8*4):
        error("Shell code length to high for basic 32 bit functionement")
    if counter < 2**7 and opti:
        set_ecx_string = "push {}\n    pop ecx".format(counter)
    else:
        set_ecx_string = "xor ecx,ecx\n    "
        if counter < 2 ** 8:
            set_ecx_string += "mov cl, {}".format(counter)
        elif counter < 2 ** 16:
            set_ecx_string += "mov cx, {}".format(counter)
        else:
            set_ecx_string += "mov ecx, {}".format(counter)
    return set_ecx_string
