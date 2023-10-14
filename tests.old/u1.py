from __future__ import print_function
import bks.util, bks.jks2
import sys
import binascii, itertools

source = b'\x00' * 57
password = 'abcd12349999AA'
iv = "ivm\x00\0xf3ivm\x00\0xf3ivm\x00\0xf3ivm\x00\0xf3ivm\x00\0xf3ivm\x00\0xf3"
b_password = b'abcd12349999AA'
b_iv = b"ivm\x00\0xf3ivm\x00\0xf3ivm\x00\0xf3ivm\x00\0xf3ivm\x00\0xf3ivm\x00\0xf3"
salt = b'\xb0~\xf1}\xa9\xc1\x98\xa8\xa6*]\nR\xd6i\xb3\xef\xf0\x94\x92'
count = 0xeb6

def test_u1():
    print("testing bks.util._pbe_encrypt ", end="")
    dout = bks.util._pbe_encrypt(source, password, salt, count)

    model =  b'\x00\x00\x00\x14\xb0~\xf1}\xa9\xc1\x98\xa8\xa6*]\nR\xd6i\xb3\xef\xf0\x94\x92\x00\x00\x0e\xb6\xc8\x93\xda\xac\xeb\xd0\tc\xce\xf4\x8di\x18\xc3\x18c \xa7\xf5\\\xc6\xdb\xd5l\xb3\x97\xf0\x15\xa9\xec\xac\x9fx\xbf-=\xb5\xf6\xd4}\x95\xfbNC\x99\xd7\xb91\x12\x1fx\xe4$\x00\xf3\xf2\xdd$z\xc8X\xe8%x'

    assert dout == model
    print("** PASSED **")

def test_u2():
    print("testing bks.util._pbe_decrypt ", end="")
    model =  b'\x00\x00\x00\x14\xb0~\xf1}\xa9\xc1\x98\xa8\xa6*]\nR\xd6i\xb3\xef\xf0\x94\x92\x00\x00\x0e\xb6\xc8\x93\xda\xac\xeb\xd0\tc\xce\xf4\x8di\x18\xc3\x18c \xa7\xf5\\\xc6\xdb\xd5l\xb3\x97\xf0\x15\xa9\xec\xac\x9fx\xbf-=\xb5\xf6\xd4}\x95\xfbNC\x99\xd7\xb91\x12\x1fx\xe4$\x00\xf3\xf2\xdd$z\xc8X\xe8%x'

    dout = bks.util._pbe_decrypt(model, password)

    assert dout == source
    print("** PASSED **")

def test_u3():
    print("testing bks.util._twofish_encrypt ", end="")
    dout = bks.util._twofish_encrypt(source, password, salt, count)

    model = b'p\x1e\x03\x90\xe4\xbd\x86/\xabTf}\xfa\x06uB\x80:*\xd0R\xa4p\x9d\x0e\x1b\xbe\xb1{\xd1\xdc\xac\x15\xd6d\xf3\xf6\xdb`\r\xeb\xb9v\x16P\xfa\xa2\x9eH\xf1\xd4\xc5\xf4}\x11\x92]\xe4\xf7\x8c\x97\x82\xf7W'

    assert model == dout
    print("** PASSED **")

    print("testing bks.util._twofish_decrypt ", end="")
    din =  bks.util._twofish_decrypt(dout, password, salt, count)

    assert source == din
    print("** PASSED **")

def test_u4():
    print("testing _jks_keystream ", end="")


    gen = bks.jks2._jks_keystream(b_iv,b_password)

    myarr = []
    for k in range(128):
        myarr.append(next(gen))

    if sys.version_info < (3,0):
        dout = b''.join(myarr)
    else:
        dout = bytes(myarr)

    model = b'\xb0\xf4\xb0\xe3#4\x01\xae\xd3\x13\x0f\x1a\x13\xb0ccX<u\xf7\xc0\x14\x86j\x04\xce\xed\xb9\x914\xe8\x16\xcavI&\xc0\x1a\xa3\xf7\xf2\xd3fP=\xdb\xc9\xc0\xd8\x10\x89\xd3\xde\xa9\x1d\xbc\xf5\x9e\xe4\xa2\x0f\xaej\x04\x97\xe4\xf6\x08\x8fq\xd9\xd7 %\rQ\n\xc0d\rI\xa8J\xdbd-\x06\xab[\xf4\xbee\x01\xc8\x0f"\xa7ni\xe47\xffc>\xcf\xd3\x98\x97\x93\xe7:\xe4\x972\xe1\xb7\x04y\xd3\x8c\x0c<\x00R\xbf\x1c\xee\xb3'
    assert dout == model
    print("** PASSED **")




def test_data():
    test_u1()
    test_u2()
    test_u3()
    test_u4()



if __name__ == "__main__":

    if sys.argv[1] == "test":
        test_data()



