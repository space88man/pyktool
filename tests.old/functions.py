import binascii

def u_hex(x):
    return binascii.hexlify(x).decode('ascii')
