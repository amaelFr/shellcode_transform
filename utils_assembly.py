#!/usr/bin/python3

from utils import error

from math import ceil, log10

from random import getrandbits
from pathlib import Path
from os.path import join
from tempfile import TemporaryDirectory
from subprocess import PIPE, run



def print_shellcode(shellcode: bytes):
    print("ASM shellcode:\n{}".format(','.join(hex(x) for x in shellcode)))
    print("\n\nshellcode:\n{}".format(''.join( '\\x%02x' % x for x in shellcode)))
    print_shellcode_table(shellcode)

def print_shellcode_table(shellcode: bytes):

    size_identifiant_line = int(log10(ceil(len(shellcode)/10)))+1

    print("\n\n{}  \033[31m{}\033[0m".format( " " * size_identifiant_line, "\033[0m-\033[31m".join("%02d" % i for i in range(0, 10))))
    for i, line in enumerate([shellcode[x:x+10] for x in range(0, len(shellcode), 10)]):
        print("\n\033[31m{}\033[0m {}".format( ( "%0{}d0".format(size_identifiant_line) ) % i ," ".join( (line[j]).to_bytes(1, byteorder='little').hex().upper() if line[j] != 0 and line[j] != 255 else "\033[{}m{}\033[0m".format("33" if line[j]==0 else "34", (line[j]).to_bytes(1, byteorder='little').hex().upper()) for j in range(0, len(line)))))



def get_shellcode_nasm(assembly: str) -> bytes:
    try:
        with TemporaryDirectory() as tmpdirpath:
            exe_file = join(tmpdirpath, "assembly")
            
            fingerprint_bytes = bytes([getrandbits(8) for _ in range(0, 512)])

            try:
                with open("{}.asm".format(exe_file), "w") as asm_fd:
                    asm_fd.write(assembly+','.join(hex(x) for x in fingerprint_bytes))
            except:
                error("While writing assembly file")            
            
            try:
                result = run(["/usr/bin/nasm", "-f", "elf32", "{}.asm".format(exe_file)], stdout=PIPE, stderr=PIPE, universal_newlines=True)
                
                if result.returncode != 0 or result.stdout != '' or result.stderr != '':
                    error("While nasm:\n; nasm -f elf32 shellcode.s && ld -m elf_i386 shellcode.o -o shellcode && rm -rf shellcode.o\n{}".format(assembly))
                
                result = run(["/usr/bin/ld", "-m", "elf_i386", "{}.o".format(exe_file), '-o', exe_file ], stdout=PIPE, stderr=PIPE, universal_newlines=True)
                
                if result.returncode != 0 or result.stdout != '' or result.stderr != '':
                    error("While linking")

            except:
                error("While nasm && ld")
                

            try:
                full_shc = Path(exe_file).read_bytes()[4096:]
                
                start_shellcode = -1
                for i in [i for i in range(len(full_shc)) if full_shc[i]==fingerprint_bytes[0]]:
                    if full_shc[i:i+512] == fingerprint_bytes:
                        start_shellcode = i
                
                if start_shellcode < 0  :
                    error("Can't get full assembly")

                return full_shc[:start_shellcode]

            except:
                error("While reading assembly file")
    except:
        error("While creating temporary directory")


def gen_assembly(shellcode: bytes, encode_list, opti: bool = True) -> str:
    
    ## 1 call
    ## 2 follow
    ## 3 methode on same loop

    for encode_type, start, end in encode_list:
        print(encode_type)


    return ""
