# -*- python-indent: 4 -*-
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from asn1crypto import keys
from asn1crypto.pem import unarmor, armor

from .pbe import PBECipher
from .util import load_der_private_key

BACKEND = default_backend()


def pkcs8_wrap(pdata, cipher, dump=True):
    data = cipher.encrypt(pdata)

    ekey = keys.EncryptedPrivateKeyInfo()
    ekey[0] = cipher.algo_id
    ekey[1] = data

    if dump:
        return ekey.dump()
    else:
        return ekey


def pkcs8_unwrap(p8, password):
    cipher = PBECipher(password, p8["encryption_algorithm"])
    data = p8["encrypted_data"].native
    pt = cipher.decrypt(data)
    return pt


def pkcs8_der_from_pem(pem, password, encoding=serialization.Encoding.DER):
    # breakpoint()
    if isinstance(password, str):
        password = password.encode("ascii")

    m0 = re.search(r"^-----BEGIN (RSA|EC) PRIVATE KEY", pem)

    m1 = re.search("^-----BEGIN ENCRYPTED PRIVATE KEY", pem)
    if m1 is not None:
        data = unarmor(pem.encode("ascii"))[2]
        epkey = keys.EncryptedPrivateKeyInfo.load(data)
        pem = armor("PRIVATE KEY", pkcs8_unwrap(epkey, password)).decode("ascii")
        password = None

    m2 = re.search("\nDEK-Info:", pem)
    if m2 is None:
        password = None

    pem = pem.encode("ascii")

    if password or m0:
        key = serialization.load_pem_private_key(pem, password, backend=BACKEND)

        return key, key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        data = unarmor(pem)[2]
        if encoding == serialization.Encoding.DER:
            output = data
        else:
            output = pem

        return load_der_private_key(data), output


def pkcs8_pem_from_pem(pem, password):
    return pkcs8_der_from_pem(pem, password, encoding=serialization.Encoding.PEM)


def keytype(private_key):
    key = keys.PrivateKeyInfo.load(private_key.pkey)

    alg = key[1]["algorithm"].native
    if alg == "ec":
        return "EC"
    elif alg.startswith("rsa"):
        return "RSA"
    elif alg.startswith("dsa"):
        return "DSA"
    else:
        return "UNKNOWN"
