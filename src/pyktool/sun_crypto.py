import hashlib
import os
import asn1crypto.algos as algos
import asn1crypto.core as core

sun_jks_id = algos.EncryptionAlgorithm()
sun_jks_id["algorithm"] = "1.3.6.1.4.1.42.2.17.1.1"

# SUN_JKS_ALGO_ID = (1,3,6,1,4,1,42,2,17,1,1) # JavaSoft proprietary key-protection algorithm
# SUN_JCE_ALGO_ID = (1,3,6,1,4,1,42,2,19,1)   # PBE_WITH_MD5_AND_DES3_CBC_OID

SUN_JKS_ALGO_ID = algos.EncryptionAlgorithmId("1.3.6.1.4.1.42.2.17.1.1")
# SUN_JKS_ALGO_ID.set('1.3.6.1.4.1.42.2.17.1.1')

SUN_JCE_ALGO_ID = algos.EncryptionAlgorithmId("1.3.6.1.4.1.42.2.19.1")
# SUN_JCE_ALGO_ID.set('1.3.6.1.4.1.42.2.19.1')


class SunCipher:
    algo_id = sun_jks_id

    def __init__(self, password):
        self.password = password

    def encrypt(self, pdata):
        return jks_pkey_encrypt(pdata, self.password)

    def decrypt(self, cdata):
        return jks_pkey_decrypt(cdata, self.password)


def jks_pkey_encrypt(data, password):
    "implements private key crypto algorithm used by JKS files"
    # password = ''.join([b'\0'+c.encode('latin-1') for c in password])
    # the JKS algorithm uses a regular Java UTF16-BE string for the password, so insert 0 bytes

    data = bytearray(data)

    password = password.encode("utf-16be")
    iv = os.urandom(20)
    xoring = zip(data, _jks_keystream(iv, password))
    key = bytearray([(a ^ b) for a, b in xoring])
    check = hashlib.sha1(password + data).digest()
    # note: check is over plaintext

    return iv + key + check


def jks_pkey_decrypt(data, password):
    "implements private key crypto algorithm used by JKS files"
    # password = ''.join([b'\0'+c.encode('latin-1') for c in password])
    # the JKS algorithm uses a regular Java UTF16-BE string for the password, so insert 0 bytes

    data = bytearray(data)

    password = password.encode("utf-16be")
    iv, data, check = data[:20], data[20:-20], data[-20:]
    xoring = zip(data, _jks_keystream(iv, password))
    key = bytearray([(a ^ b) for a, b in xoring])
    if hashlib.sha1(password + key).digest() != check:
        raise ValueError("bad hash check on private key")
    return bytes(key)


def _jks_keystream(iv, password):
    "helper generator for _sun_pkey_decrypt"
    cur = iv
    while 1:
        xhash = hashlib.sha1(bytes(password + cur))
        cur = bytearray(xhash.digest())
        for byte in cur:
            yield byte


def jce_pbe_decrypt(data, password, salt, iteration_count):
    key, iv = _jce_pbe_derive_key_and_iv(password, salt, iteration_count)

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend

    des3 = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = des3.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()

    unpadder = padding.PKCS7(64).unpadder()
    result = unpadder.update(padded) + unpadder.finalize()
    return result


def _jce_pbe_derive_key_and_iv(password, salt, iteration_count):
    """
    PKCS#8-formatted private key with a proprietary password-based encryption algorithm.
    It is based on password-based encryption as defined by the PKCS #5 standard, except that is uses triple DES instead of DES.
    Here's how this algorithm works:
      1. Create random salt and split it in two halves. If the two halves are identical, invert one of them.
      2. Concatenate password with each of the halves.
      3. Digest each concatenation with c iterations, where c is the iterationCount. Concatenate the output from each digest round with the password,
         and use the result as the input to the next digest operation. The digest algorithm is MD5.
      4. After c iterations, use the 2 resulting digests as follows: The 16 bytes of the first digest and the 1st 8 bytes of the 2nd digest
         form the triple DES key, and the last 8 bytes of the 2nd digest form the IV.
    See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b27/com/sun/crypto/provider/PBECipherCore.java#PBECipherCore.deriveCipherKey%28java.security.Key%29
    """
    # Note: unlike JKS, the JCE algorithm uses an ASCII string for the password, not a regular Java/UTF-16BE string; no need to double up on the password bytes
    if len(salt) != 8:
        raise ValueError(
            "Expected 8-byte salt for JCE private key encryption algorithm (OID %s), found %d bytes"
            % (".".join(str(i) for i in SUN_JCE_ALGO_ID), len(salt))
        )

    salt_halves = [salt[0:4], salt[4:8]]
    if salt_halves[0] == salt_halves[1]:
        salt_halves[0] = _jce_invert_salt_half(salt_halves[0])

    derived = ""
    for i in range(2):
        to_be_hashed = salt_halves[i]
        for k in range(iteration_count):
            to_be_hashed = hashlib.md5(to_be_hashed + password).digest()
        derived += to_be_hashed

    key = derived[:-8]  # = 24 bytes
    iv = derived[-8:]
    return key, iv


def _jce_invert_salt_half(salt_half):
    """
    JCE's proprietary PBEWithMD5AndTripleDES algorithm as described in the OpenJDK sources calls for inverting the first salt half if the two halves are equal.
    However, there appears to be a bug in the original JCE implementation of com.sun.crypto.provider.PBECipherCore causing it to perform a different operation:
      for (i=0; i<2; i++) {
          byte tmp = salt[i];
          salt[i] = salt[3-i];
          salt[3-1] = tmp;     // <-- typo '1' instead of 'i'
      }
    The result is transforming [a,b,c,d] into [d,a,b,d] instead of [d,c,b,a] (verified going back to the original JCE 1.2.2 release for JDK 1.2).
    See source (or bytecode) of com.sun.crypto.provider.PBECipherCore (JRE <= 7) and com.sun.crypto.provider.PBES1Core (JRE 8+):
    """
    salt = bytearray(salt_half)
    salt[2] = salt[1]
    salt[1] = salt[0]
    salt[0] = salt[3]
    return bytes(salt)
