# vim: set et ai ts=4 sts=4 sw=4:
from __future__ import print_function
import binascii
import struct
import base64
import sys
from asn1crypto import keys, x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import typing

BACKEND = default_backend()


def u_hex(data):
    return binascii.hexlify(data).upper()


b1 = struct.Struct(">B")
b2 = struct.Struct(">H")
b4 = struct.Struct(">L")
b8 = struct.Struct(">Q")


def uread_data(data, pos):
    size = b4.unpack_from(data, pos)[0]
    pos += 4
    return data[pos : pos + size], pos + size, size


def _read_direct(data, pos, size):
    return data[pos : pos + size], pos + size


def uread_int(data, pos):
    size = b4.unpack_from(data, pos)[0]
    pos += 4
    return size, pos


def uread_int1(data, pos):
    size = b1.unpack_from(data, pos)[0]
    pos += 1
    return size, pos


def uread_utf(data, pos):
    size = b2.unpack_from(data, pos)[0]
    pos += 2
    return data[pos : pos + size].decode(), pos + size


def uwrite_utf(data):
    raw = data.encode("utf-8")
    return b2.pack(len(raw)) + raw


def uwrite_data(data):
    return b4.pack(len(data)) + data


def _string(data):
    if sys.version_info[0] == 3:
        return data.decode("utf-8")
    return data


def serialize(data, file):
    fout = open(file, "w+")
    fout.write(data)
    fout.close()


def envelope(tag, data, encode=False):
    envelope = "-----BEGIN {0}-----\n{1}-----END {0}-----\n"
    if encode:
        output = envelope.format(tag, _string(base64.encodebytes(data)))
    else:
        output = envelope.format(tag, data)
    return output


def load_cert_public_key(data: bytes):
    """Wrapper extract public key from certificate
    der bytes."""

    return load_der_public_key(x509.Certificate.load(data).public_key)


def load_der_public_key(
    data: typing.Union[bytes, keys.PublicKeyInfo]
) -> rsa.RSAPublicKey:
    """Wrapper to load a public key; workaround
    RSASSA-PSS keys.

    Args:
        data: public key representation

    Returns:
        RSAPublicKey
    """

    pubkey = keys.PublicKeyInfo.load(data) if isinstance(data, bytes) else data.copy()

    if (
        pubkey[0]["algorithm"].native == "rsassa_pss"
        or pubkey[0]["algorithm"].native == "rsaes_oaep"
    ):
        pubkey[0] = {"algorithm": "rsa"}

    return serialization.load_der_public_key(pubkey.dump(), BACKEND)


def load_der_private_key(
    data: typing.Union[bytes, keys.PrivateKeyInfo]
) -> rsa.RSAPrivateKey:
    """Wrapper to load a public key; workaround
    RSASSA-PSS keys.

    Args:
        data (bytes/PrivateKeyInfo): ...

    Returns:
        RSAPrivateKey
    """

    prvkey = keys.PrivateKeyInfo.load(data) if isinstance(data, bytes) else data.copy()

    if (
        prvkey[1]["algorithm"].native == "rsassa_pss"
        or prvkey[1]["algorithm"].native == "rsaes_oaep"
    ):
        prvkey[1] = {"algorithm": "rsa"}

    return serialization.load_der_private_key(prvkey.dump(), None, BACKEND)
