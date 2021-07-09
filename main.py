#!/usr/bin/python3

import argparse
from os.path import isfile
from pathlib import Path
from re import compile, findall, split as re_split, sub, search, match

from utils import error


def parse_buffer(encode_detail_buffer, shellcode, numberbefore=0, numberafter=0):
    """
    parse le buffer et renvoie un tuple comme suit :
        ("Type Encode", start, end, param option)
    :param encode_detail_buffer:
    :param shellcode:
    :param numberbefore:
    :param numberafter:
    :return:
    """
    print(encode_detail_buffer)
    print(shellcode)
    print(numberafter)
    print(numberbefore)
    to_ret = None
    try:
        if encode_detail_buffer == ")":
            to_ret = None
            pass
        elif len(encode_detail_buffer) == 1:
            ## Param Only char (X|x|L|l|R|r|\+|-)
            if numberbefore != 0:
                begin = numberbefore
            else:
                begin = 0

            if numberafter != 0:
                end = numberafter
            else:
                end = len(shellcode) - 1
            to_ret = (encode_detail_buffer, begin, end, 1)
            #print("({},{},{},{})".format(encode_detail_buffer, begin, end, 1))
        elif ":" in encode_detail_buffer:
            ## Gestion des ranges (ex 9:13X)
            tmp = encode_detail_buffer[:-1].split(":")
            if not encode_detail_buffer[-1].isdigit():
                ## Gestion des ranges ne terminant pas par un chiffre (ex: 9:13X)
                to_ret = (encode_detail_buffer[-1], tmp[0], tmp[1], 1)
                #print("({},{},{},{})".format(encode_detail_buffer[-1], tmp[0], tmp[1], 1))
            elif encode_detail_buffer[-1].isdigit():
                ## Gestion des ranges terminant par un chiffre (ex: 9:13X4)
                letter = findall("(" + regex_shellcode_encodage_detail + ")" + regex_entier,
                                 encode_detail_buffer)
                to_ret = (letter[0][0], tmp[0], tmp[1].split(letter[0][0])[0],
                          letter[0][1])
                #print("({},{},{},{})".format(letter[0][0], tmp[0], tmp[1].split(letter[0][0])[0], letter[0][1]))
        elif encode_detail_buffer[0].isdigit() and not encode_detail_buffer[-1].isdigit():
            ## Commence par un chiffre et ne finis pas par un chiffre (ex: 12l)
            to_ret = (encode_detail_buffer[-1], encode_detail_buffer[:-1],
                      encode_detail_buffer[:-1], 1)
            #print("({},{},{},{})".format(encode_detail_buffer[-1], encode_detail_buffer[:-1], encode_detail_buffer[:-1], 1))
        elif not encode_detail_buffer[0].isdigit() and encode_detail_buffer[-1].isdigit():
            ## ne commence pas par un chiffre et finis par un chiffre (ex: r32)
            if numberbefore != 0:
                begin = numberbefore
            else:
                begin = 0

            if numberafter != 0:
                end = numberafter
            else:
                end = len(shellcode) - 1
            to_ret = (encode_detail_buffer[0], begin, end, encode_detail_buffer[1:])
            #print("({},{},{},{})".format(encode_detail_buffer[0], begin, end, encode_detail_buffer[1:]))
        elif encode_detail_buffer[0].isdigit() and encode_detail_buffer[-1].isdigit():
            ## Commence et finis par un chiffre (ex: 422X5)
            before = ""
            after = ""
            letter = ""
            passed_letter = False
            for i in encode_detail_buffer:
                if i.isdigit() and passed_letter == False:
                    before += i
                elif not i.isdigit():
                    letter = i
                    passed_letter = True
                elif i.isdigit() and passed_letter == True:
                    after += i
            to_ret = (letter, before, before, after)
            # rint(to_ret)
            print("({},{},{},{})".format(letter, before, before, after))
    except IndexError as er:
        print(er)
        to_ret = None
        pass
    finally:
        return to_ret


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--file', '--infile', dest='infile',
                        help='file to encode, expects filetype of data i.e. msfvenom ... -f raw or echo -ne "........"',
                        required=True)
    parser.add_argument('-e', '--enocde', '--encode-list', dest='encodelist',
                        help='list of encodage to use in suite X=xor +=+1 -=-1 add payload behind to get it inside,   X,-,2,X,+3,+')
    parser.add_argument('-o', '--out', '--outfile', dest='outfile', help='write assembly to file (default: STDOUT)')
    # parser.add_argument('-d', dest='decode', default=False, action='store_true', help='Decode what is passed via -f or -s')

    args = parser.parse_args()

    if not isfile(args.infile):
        error("No such file: {}".format(args.infile))

    try:
        shellcode = Path(args.infile).read_bytes()
    except:
        error("While reading input shellcode file")

    if args.encodelist:

        regex_entier = r"([0-9]+)"
        regex_shellcode_section = r"(" + regex_entier + r"?:)?" + regex_entier + r"?"
        regex_shellcode_encodage_simple = r"\*|<|>"
        regex_shellcode_encodage_detail = r"X|x|L|l|R|r|\+|-"
        regex_shellcode_encodage_list = r"(" + regex_shellcode_encodage_detail + r"|" + regex_shellcode_encodage_simple + r")"

        for sub_encode_list in args.encodelist.split('|'):

            if search(
                    r"(" + regex_shellcode_encodage_detail + r")" + regex_entier + r"(\(|:|" + regex_shellcode_encodage_list + r")",
                    sub_encode_list):
                print(search(
                    r"(" + regex_shellcode_encodage_detail + r")" + regex_entier + r"(\(|:|" + regex_shellcode_encodage_list + r")",
                    sub_encode_list))
                error(
                    "invalid encode list add ; between encodage that need details and all encode sort " + regex_shellcode_encodage_detail + " and of course before : if need")

            if search(r"\([^\)]*:[^\)]*\)", sub_encode_list):
                error("invalid encode list, you cant put positionnal detail inside brackets")

            if search(r"(\([^\)]*\()|(\)[^\(]*\))", sub_encode_list):
                error("invalid choice, you can't get a encode list with imbrick parenthesis")

            # sub_encode_list = sub( r"(" + regex_shellcode_encodage_detail + r"|" + regex_shellcode_encodage_simple + r"|\))(" + regex_shellcode_encodage_detail + r"|" + regex_shellcode_encodage_simple + r"|\()", r"\1;\2", sub_encode_list)
            sub_encode_list = sub(
                regex_shellcode_encodage_list + r"(" + regex_shellcode_encodage_detail + r"|" + regex_shellcode_encodage_simple + r"|:|\(|\))",
                r"\1,\2", sub_encode_list)
            sub_encode_list = sub(
                regex_shellcode_encodage_list + r"(" + regex_shellcode_encodage_detail + r"|" + regex_shellcode_encodage_simple + r"|:|\(|\))",
                r"\1,\2", sub_encode_list)
            sub_encode_list = sub(r"\);", r")", sub_encode_list)

            encode_detail_buffer = ""
            tab_tupl = []
            sub_encode_list += ",a"
            for encode_detail in sub_encode_list:
                # print('schema all : {}'.format(repr(encode_detail)))
                if encode_detail == "," and "(" not in encode_detail_buffer or encode_detail == ")":
                    encode_detail = encode_detail.replace(',', '')
                    print(encode_detail_buffer)
                    # tab_tupl.append((param1, param2, param3 , param4))
                    if encode_detail_buffer == ")":
                        pass
                    elif "(" in encode_detail_buffer or ")" in encode_detail_buffer:
                        ## Gestion des parenthèses
                        start_number = findall("(.*)\((.*)", encode_detail_buffer)
                        start = start_number[0][0]
                        if ":" in start:
                            ## Range dans parentheses
                            tmp = start.split(":")
                            print(len(start.split(":")))
                            start = tmp[0]
                            end = tmp[1]
                        else:
                            ## no range in parenthese
                            end = 0
                        param = start_number[0][1]
                        for spl in param.split(','):
                            ret = parse_buffer(spl, shellcode, start, end)
                            if ret != None:
                                tab_tupl.append(ret)
                    else:
                        ret = parse_buffer(encode_detail_buffer, shellcode)
                        if ret != None:
                            tab_tupl.append(ret)
                    encode_detail_buffer = ""

                encode_detail_buffer += encode_detail

    print(tab_tupl)
    # print(encode_detail_buffer)

    # regex_encode_type_ba = r"((([0-9]*):)?([0-9]*))?\((((X|x|L|l|R|r|\+|-)([0-9]*))

    # regex_encode_type_base = r"((([0-9]*):([0-9]*))?((\*|<|>)|((X|x|L|l|R|r|\+|-)([0-9]*)));)"

    # regex_split = compile(r"\(|\)")

    # regex_sub_encode_type = compile(regex_encode_type_base)

    # for sub_encode_list in args.encodelist.split('|'):

    # regex_encode_type=compile( regex_encode_type_base + r"\(" + regex_encode_type_base + r"\)?" + regex_encode_type_base + r"?" )

    # for sub_encode_list in args.encodelist.split('|'):
    #     sub_encode_list_parsed = []
    #     for encode in findall(regex_encode_type, sub_encode_list) :
    #         offset = 1 if encode[4]=='' else int(encode[4])
    #         encode_type=encode[1]+encode[3]
    #         sub_encode_list_parsed.append((offset, encode_type))

    #     for encode in sub_encode_list_parsed:
    #         print(encode)

    # for encode in findall(regex_encode_type, args.encodelist) :

    #     encode_type=encode[1]+encode[3]
    #     offset = 1 if encode[4]=='' else int(encode[4])

    #     if encode_type == "X" or encode_type == "x":
    #         print("Running XOR encoder")

    #         shellcode = rolling_xor(shellcode)
    #         shellcode = nasm( template_XOR.format(ecx_len(len(shellcode) - 1))) + shellcode

    #         # ','.join(hex(x) for x in shellcode)

    #     elif encode_type == "L" or encode_type == "l" or encode_type == "R" or encode_type == "r":
    #         print("Running right or left bit shifting encoder")

    #         shellcode = right_left_rotation_bit(shellcode, encode_type == "R" or encode_type == "r", offset)

    #         shellcode=nasm( template_rotation.format( ecx_len(len(shellcode)), 'rol' if encode_type == "R" or encode_type == "r" else 'ror', offset)) + shellcode

    #     elif encode_type == "+" or encode_type == "-":
    #         print("Running + or - encoder")
    #         shellcode = add_sub(shellcode, add_or_sub=(encode_type=='+'), to_num=offset)

    #         shellcode = nasm( template_sub_add.format(ecx_len(len(shellcode)), 'sub' if encode_type=='+' else 'add', offset)) + shellcode
    #     else:
    #         error("The input encoding action {} is not valid".format(encode_type))

    if 0 in shellcode:
        print("\033[31mIt looks like your shellcode will not be valid, there is a 00 byte\033[0m")

    # print_shellcode(shellcode)
