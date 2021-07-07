#!/usr/bin/python3


def add_sub(shellcode: bytes, add_or_sub: bool=True, to_num: int=1, decode: bool=False) -> bytes:
    """Perform a add or sub encoding scheme on `shellcode`.

    :return: bytes object
    """
    shellcode = bytearray(shellcode)
    encoded_payload = bytearray()

    calculated_num = (int(add_or_sub)*2-1) * to_num*(int(decode)*-2+1)

    for byte in shellcode:
        encoded_payload.append(byte + calculated_num)

    return bytes(encoded_payload)

def right_left_rotation_bit(shellcode: bytes, right_or_left: bool=True, n: int=1) -> bytes:
    # print(bin(byte<<n>>8<<8), bin(byte<<n), bin((byte<<n)-(byte<<n>>8<<8)), bin(byte>>8-n), bin((byte<<n)-(byte<<n>>8<<8) + (byte>>(8-n))))
    # print(bin(byte), bin(byte<<(8-n)), bin(byte>>n<<8),  bin(byte>>n), bin((byte<<(8-n)) - (byte>>n<<8) + (byte>>n)))
    shellcode = bytearray(shellcode)
    encoded_payload = bytearray()

    for byte in shellcode:
        if right_or_left:
            encoded_payload.append((byte<<(8-n)) - (byte>>n<<8) + (byte>>n))
            ## right
        else:
            ## left
            encoded_payload.append((byte<<n)-(byte<<n>>8<<8) + (byte>>(8-n)))

    return bytes(encoded_payload)

def rolling_rotation(shellcode: bytes, right_or_left: bool=True, decode: bool=False) -> bytes:
    """ Perform a rolling xor encoding scheme on `shellcode`.

    :param shellcode: bytes object; data to be [en,de]coded
    :param decode: boolean, decrypt previously xor'd data
    :return: bytes object
    """
    shellcode = bytearray(shellcode)

    if decode:
        shellcode.reverse()
        encoded_payload = bytearray()

        for i, byte in enumerate(shellcode):
            if i == len(shellcode) - 1:
                encoded_payload.append(shellcode[i])  # last byte doesn't need xor'd, common to system call Ox80 generally
            else:
                encoded_payload.append(shellcode[i] ^ shellcode[i + 1])

        encoded_payload.reverse()
    else:
        encoded_payload = bytearray([shellcode.pop(0)])  # first byte left as is in the ciphertext

        for i, byte in enumerate(shellcode):
                encoded_payload+=bytearray(right_left_rotation_bit( bytes(byte), right_or_left, int(encoded_payload[i])%8))

    return bytes(encoded_payload)

def rolling_xor(shellcode: bytes, decode: bool=False) -> bytes:
    """ Perform a rolling xor encoding scheme on `shellcode`.

    :param shellcode: bytes object; data to be [en,de]coded
    :param decode: boolean, decrypt previously xor'd data
    :return: bytes object
    """
    shellcode = bytearray(shellcode)

    if decode:
        shellcode.reverse()
        encoded_payload = bytearray()

        for i, byte in enumerate(shellcode):
            if i == len(shellcode) - 1:
                encoded_payload.append(shellcode[i])  # last byte doesn't need xor'd, common to system call Ox80 generally
            else:
                encoded_payload.append(shellcode[i] ^ shellcode[i + 1])

        encoded_payload.reverse()
    else:
        encoded_payload = bytearray([shellcode.pop(0)])  # first byte left as is in the ciphertext

        for i, byte in enumerate(shellcode):
            encoded_payload.append(byte ^ encoded_payload[i])

    return bytes(encoded_payload)

