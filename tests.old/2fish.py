from functions import *
from PBKDF_PKCS12 import PBKDF_PKCS12v1

password = b'\x00a\x00b\x00c\x00d\x00\x00'
salt = b'plaintext123'
count = 1000


key = PBKDF_PKCS12v1(count, password, salt, 32, id=1)
iv =  PBKDF_PKCS12v1(count, password, salt, 16, id=2)

print("key = {0}".format(u_hex(key)))
print(" iv = {0}".format(u_hex(iv)))


if (iv,key) ==(b'h\xbc\xd3\xe8\x02S4\xc8\x89\xb2\xf7\x1c\x1cc6v', b'\xca\xfc\xed\xf0\xe5\x87\xad\x9a\xd7\x1a\x1d\t\x15\x90M\xad\x8d4\x15\xab`\x16\x80\x1fu\x87m\xa8-\xff\x0cp'):
    print('PASSED')
else:
    print('FAILED')
