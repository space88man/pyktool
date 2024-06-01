# ciphers: ARC4, AES-CBC, 3DES-CBC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

from .legacy.pkcs12_kdf import pkcs12_kdf

from .asn1_helper import (
    id_pbeWithSha1AndRC4_128,
    id_pbeWithSha1AndRC4_40,
    id_pbeWithSha1AndDESede,
    id_pbeWithSha1And2DES,
    id_pbeWithSha1AndRC2_128,
    id_pbeWithSha1AndRC2_40,
    id_aes128cbc,
    id_aes192cbc,
    id_aes256cbc,
    id_des3cbc,
    id_aes256ccm,
    id_sha1,
    id_sha256,
    id_sha384,
    id_sha512,
    id_sha224,
    id_PBES2,
)


from .asn1_util import pbe_pkcs12_algo_id, pbes2_algo_id, PBES2_oids
from . import legacy

import logging
import sys
import binascii

LOG = logging.getLogger(__name__)

PKCS12_oids = {
    # OpenSSL NIDs for PKCS12 PBE
    id_pbeWithSha1AndRC4_128.dotted: 144,
    id_pbeWithSha1AndRC4_40.dotted: 145,
    id_pbeWithSha1AndDESede.dotted: 146,
    id_pbeWithSha1And2DES.dotted: 147,
    id_pbeWithSha1AndRC2_128.dotted: 148,
    id_pbeWithSha1AndRC2_40.dotted: 149,
}

v2_prf_dict = {
    id_sha1.dotted: hashes.SHA1(),
    id_sha256.dotted: hashes.SHA256(),
    id_sha384.dotted: hashes.SHA384(),
    id_sha512.dotted: hashes.SHA512(),
    id_sha224.dotted: hashes.SHA224(),
}


def _encode_hex(y):
    """Hexlify bytes.
    Works for both Python 2, 3
    :param y: byte array
    :return: hex string of input
    :rtype: string
    """

    tmp = binascii.hexlify(y)
    if sys.version_info >= (3, 0):
        return binascii.hexlify(y).decode("ascii")

    return tmp


def colonify(y, encode=True):
    if encode:
        x = _encode_hex(y)
    return ":".join(x[i : i + 2] for i in range(0, len(x), 2)).upper()


def pretty_hex(x):
    return colonify(x.asOctets())


def _algo(oid):
    if isinstance(oid, str):
        return PBES2_oids[oid][1:]
    else:
        return PBES2_oids[oid.dotted][1:]


class AlgorithmError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# SWIG module to perform legacy pkcs12 KDF:
# the last index is a key to a table of hash functions
# inside SWIG
hash_module = {
    "1.3.14.3.2.26": (20, hashes.SHA1(), "sha1"),
    "2.16.840.1.101.3.4.2.1": (32, hashes.SHA256(), "sha256"),
    "2.16.840.1.101.3.4.2.2": (48, hashes.SHA384(), "sha384"),
    "2.16.840.1.101.3.4.2.3": (64, hashes.SHA512(), "sha512"),
    "2.16.840.1.101.3.4.2.4": (28, hashes.SHA224(), "sha224"),
}


def hmac_pkcs12_pbkdf(password, salt, count, data, mac_data=None, legacy=False):
    """
    Computes the PKCS12_PBKDF HMAC

    :param password: HMAC password
    :param salt: PKCS12_PBKDF salt
    :param count: PKCS12_PBKDF iteration count
    :param data: data to be digested
    :param macData: if present, extract salt and count from here; ignores positional parameters
    :return: HMAC
    """

    if legacy:
        dotted = "1.3.14.3.2.26"
    else:
        dotted = "2.16.840.1.101.3.4.2.1"  # match Java 17+ defaults
    if mac_data:
        salt = mac_data["mac_salt"].native
        count = mac_data["iterations"].native
        dotted = mac_data["mac"]["digest_algorithm"]["algorithm"].dotted

    hash_len, hash_mod, idx = hash_module[dotted]
    if isinstance(password, str):
        password = password.encode("ascii")
    hmac_key = pkcs12_kdf(idx, password, salt, count, hash_len, 3)
    hm = HMAC(hmac_key, hash_mod, backend=default_backend())
    hm.update(data)
    return hm.finalize()


# PKCS7 unpadder decorator
def remove_padding(fn):
    def new_fn(self, data):
        unpadder = padding.PKCS7(self.block_size).unpadder()
        plain = fn(self, data)

        return unpadder.update(plain) + unpadder.finalize()

    return new_fn


# PKCS7 padder decorator
def add_padding(fn):
    def new_fn(self, data):
        padder = padding.PKCS7(self.block_size).padder()
        data = padder.update(data) + padder.finalize()
        return fn(self, data)

    return new_fn


class PKCS5CBCPad1:
    """Wrapper class for one-shot operations with padding for CBC mode.

    Works on cryptography objects.
    Encryption: adds PKCS7 padding to plain text
    Decryption: removes PKCS7 padding from decrypted cipher text
    """

    def __init__(self, cipher):
        self.cipher = cipher
        self.decryptor = cipher.decryptor()
        self.encryptor = cipher.encryptor()
        self.block_size = cipher.algorithm.block_size

    @add_padding
    def encrypt(self, data):
        return self.encryptor.update(data) + self.encryptor.finalize()

    @remove_padding
    def decrypt(self, data):
        return self.decryptor.update(data) + self.decryptor.finalize()


class CCMNoPad:
    """Wrapper class for CBC padding.

    Works for pycrypto-like symmetric ciphers
    Encryption: uses PKCS7 padding on plaintext
    Decryption: removes PKCS7 padding from decrypted ciphertext
    """

    def __init__(self, cipher, nonce):
        self._cipher = cipher
        self._nonce = nonce

    def encrypt(self, data):
        return self._cipher.encrypt(self._nonce, data, b"")

    def decrypt(self, data):
        return self._cipher.decrypt(self._nonce, data, b"")


# PKCS12 PBE with twofish: non-standard algorithm used by
# UBER keystores


def pkcs12_password(password):
    if isinstance(password, bytes):
        password = password.decode("ascii")

    return password.encode("utf-16be") + b"\x00\x00"


def kdf_tuple(kdf_params):
    salt = kdf_params["salt"].native
    count = kdf_params["iteration_count"].native
    if "prf" not in kdf_params:
        v2_prf = hashes.SHA1()
    else:
        v2_prf = v2_prf_dict[kdf_params["prf"]["algorithm"].dotted]
        LOG.debug("PBES2 hash %s", kdf_params["prf"]["algorithm"].native)

    return salt, count, v2_prf


def pbkdf2(password, key_length, salt=b"", count=0, prf=hashes.SHA1(), params=None):
    """Derives key using PBKDF2.

    :param password: root key
    :param key_length: desired length of key
    ;param salt: salt
    :param count: iteration count
    :parm prf: the hash function
    :return: the derived key
    """

    if isinstance(password, str):
        password = password.encode("ascii")

    print(params)
    if params:
        salt, count, prf = kdf_tuple(params)
        LOG.debug("%d %d %s", len(salt), count, prf)

    kdf = PBKDF2HMAC(
        algorithm=prf,
        length=key_length,
        salt=salt,
        iterations=count,
        backend=default_backend(),
    )
    return kdf.derive(password)


# monkey patch
# algos.KdfAlgorithm._oid_specs['1.2.840.113549.1.5.12']  =  algos.Pbkdf2Params


# legacy PKCS12 ciphers as implemented in oscrypto
# as one-shot encryptors/decryptors
class Legacy:
    def __init__(self, nid, password, salt, count):
        self._password = password
        self._salt = salt
        self._count = count
        self._nid = nid

    def encrypt(self, data):
        return legacy.pkcs12_pbe_crypt(
            self._nid, self._password, self._salt, self._count, data, 1
        )[1]

    def decrypt(self, data):
        return legacy.pkcs12_pbe_crypt(
            self._nid, self._password, self._salt, self._count, data, 0
        )


class PBECipher:
    @classmethod
    def new_v1(cls, password, oid, salt, count):
        algo_id = pbe_pkcs12_algo_id(oid, salt, count)
        return cls(password, algo_id=algo_id)

    @classmethod
    def new_v2(cls, password, enc_oid, enc_iv, salt, count, hash_oid=None, **kwargs):
        algo_id = pbes2_algo_id(enc_oid, enc_iv, salt, count, hash_oid, **kwargs)
        return cls(password, algo_id=algo_id)

    def __init__(self, password, algo_id, algo_alt=None, **kwargs):
        """
        PBECipher constructor

        :param password: the password
        :param algo_id: rfc2459.AlgorithmIdentifier() - PBES2 or PBE_PKCS12
        """
        self.algo_id = algo_id
        oid = algo_id["algorithm"]
        params = algo_id["parameters"]
        LOG.debug("PBE cipher OID %s", oid.native)

        # PKCS5 PBES2
        if oid == id_PBES2:
            kdf = params["key_derivation_func"]
            kdf_params = kdf["parameters"]

            enc = params["encryption_scheme"]
            LOG.debug("PBES2 algorihtm %s", enc["algorithm"].native)
            module, keylen = _algo(enc["algorithm"])
            if module != "CCM":
                self._key = pbkdf2(password, keylen, params=kdf_params)
                self._iv = enc["parameters"].native
                self._fn = PKCS5CBCPad1(
                    Cipher(
                        module(self._key),
                        modes.CBC(self._iv),
                        backend=default_backend(),
                    )
                )
                self._type = "PBES2"
                return
            else:
                self._key = pbkdf2(password, keylen, params=kdf_params)
                self._nonce = enc["parameters"]["aes_nonce"].native
                self._taglen = enc["parameters"]["aes_ICVlen"].native
                self._fn = CCMNoPad(
                    AESCCM(self._key, tag_length=self._taglen), self._nonce
                )
                self._type = "PBES2"
                return

        # PKCS12 PBE

        self._nid = PKCS12_oids[oid.dotted]
        self._salt = params["salt"].native
        self._count = params["iterations"].native
        self._password = password
        self._type = "PKCS12"

        if isinstance(self._password, str):
            self._password = self._password.encode("ascii")

        self._fn = Legacy(self._nid, self._password, self._salt, self._count)

    def decrypt(self, data):
        """One-shot decryption.

        :param data: ciphertext
        :return: plaintext
        """

        return self._fn.decrypt(data)

    def encrypt(self, data):
        """One-shot encryption.

        :param data: plaintext
        :return: ciphertext
        """

        return self._fn.encrypt(data)
