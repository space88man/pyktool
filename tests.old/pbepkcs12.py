# Password-Based Key Derivation from PKCS#12

# Copyright (C) 2014-2018 koha <kkoha@msn.com>

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


import hashlib
from functions import *
from  PBKDF_PKCS12 import PBKDF_PKCS12v1

password_ascii = "helloworld_thequickbrownfox"
salt = "3591dca5b6e30d65958b873e57599119030eea37".decode("hex")
count = 2048

def TestPBKDF12():
    key = "56084bf15bb8abd2bf539f5391ec28d1074649b23f634d926cfd147c01cb0def"
    iv = "18f96e017d16e1baa7fe3a1717d9fc9107108875e4fa027c07ad282aedeb42ec"
    mac_key = "f3218aacfc768fc20596ef7380e66b2f2139432e9712ab7f53b263c73572c8bf"

    password = (password_ascii + "\0").encode('utf-16be')
    assert PBKDF_PKCS12v1(count, password, salt, 32, id=1) == key.decode("hex")
    assert  PBKDF_PKCS12v1(count, password, salt, 32, id=2) == iv.decode("hex")
    assert PBKDF_PKCS12v1(count, password, salt, 32, id=3) == mac_key.decode("hex")
    print "TestPBKCF12: PASSED"

if __name__ == '__main__':
    TestPBKDF12()
