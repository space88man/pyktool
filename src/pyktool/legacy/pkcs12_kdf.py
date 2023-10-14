from typing import Callable, Tuple
import hashlib
from math import ceil
import os
import random


def hash_factory(hash_algo: Callable) -> Tuple[Callable[[bytes], bytes], int]:
    """Returns a one-shot hasher based on hash_algo and block_size
    as a tuple.
    """

    def fn(data: bytes) -> bytes:
        m = hash_algo()
        m.update(data)
        return m.digest()

    return fn, hash_algo().block_size


def pkcs12_kdf(
    hash_algorithm: str, password: bytes, salt: bytes, count: int, wanted: int, id_: int
):
    """PKCS12 KDF with the same API as oscrypto.kdf pkcs12_kdf"""

    if hasattr(hashlib, hash_algorithm):
        hasher, v_len = hash_factory(getattr(hashlib, hash_algorithm))
    else:
        assert False, f"Unsupported hash algorithm: {hash_algorithm}"

    password = (password.decode("ascii") + "\0").encode("utf-16be")

    def expand(data: bytes) -> bytes:
        if len(data) >= v_len:
            ext_data = (data + data)[: v_len * ceil(len(data) / v_len)]
        else:
            ext_data = (data * ceil(v_len / len(data)))[:v_len]

        return ext_data

    ext_password = expand(password)
    if not salt:
        ext_salt = b""
    else:
        ext_salt = expand(salt)

    assert len(ext_password) % v_len == 0 and len(ext_salt) % v_len == 0

    D = v_len * bytes((id_,))

    I = ext_salt + ext_password

    MAX_OVERFLOW = int.from_bytes(v_len * b"\xff", "big")

    def process():
        I_in = I
        r_key = b""
        while len(r_key) < wanted:
            B = b""
            A_i = D + I_in
            for k in range(0, count):
                A_i = hasher(A_i)
            while len(B) < v_len:
                B += A_i
            B = B[:v_len]

            I_out = b""
            for k in range(0, len(I_in) // v_len):
                I0 = (
                    int.from_bytes(I_in[k * v_len : (k + 1) * v_len], "big")
                    + int.from_bytes(B, "big")
                    + 1
                )
                if I0 > MAX_OVERFLOW:
                    I0 -= MAX_OVERFLOW + 1
                I_out += I0.to_bytes(v_len, "big")
            I_in = I_out

            r_key += A_i

        return r_key[:wanted]

    return process()


ascii_set = list(range(33, 127))


def test_kdf():
    from oscrypto.kdf import pkcs12_kdf as oscrypto_kdf

    _password = bytes(random.choices(ascii_set, k=27))
    _salt = os.urandom(21)

    assert pkcs12_kdf("sha1", _password, b"", 2000, 57, 1) == oscrypto_kdf(
        "sha1", _password, b"", 2000, 57, 1
    )

    assert pkcs12_kdf("sha1", _password, _salt, 2000, 16, 1) == oscrypto_kdf(
        "sha1", _password, _salt, 2000, 16, 1
    )

    assert pkcs12_kdf("sha1", _password, _salt, 2000, 80, 1) == oscrypto_kdf(
        "sha1", _password, _salt, 2000, 80, 1
    )

    assert pkcs12_kdf("sha1", _password, _salt, 2000, 17, 2) == oscrypto_kdf(
        "sha1", _password, _salt, 2000, 17, 2
    )

    assert pkcs12_kdf("sha1", _password, _salt, 2000, 123, 2) == oscrypto_kdf(
        "sha1", _password, _salt, 2000, 123, 2
    )


def test_kdf2():
    from oscrypto.kdf import pkcs12_kdf as oscrypto_kdf

    _password = bytes(random.choices(ascii_set, k=615))
    _salt = os.urandom(555)

    assert pkcs12_kdf("sha1", _password, _salt, 2000, 16, 1) == oscrypto_kdf(
        "sha1", _password, _salt, 2000, 16, 1
    )

    assert pkcs12_kdf("sha1", _password, _salt, 2000, 83, 1) == oscrypto_kdf(
        "sha1", _password, _salt, 2000, 83, 1
    )

    assert pkcs12_kdf("sha1", _password, _salt, 2000, 11, 2) == oscrypto_kdf(
        "sha1", _password, _salt, 2000, 11, 2
    )

    assert pkcs12_kdf("sha1", _password, _salt, 2000, 121, 2) == oscrypto_kdf(
        "sha1", _password, _salt, 2000, 121, 2
    )


def test_kdf3():
    from oscrypto.kdf import pkcs12_kdf as oscrypto_kdf

    _password = bytes(random.choices(ascii_set, k=615))
    _salt = os.urandom(555)

    assert pkcs12_kdf("sha224", _password, _salt, 2000, 221, 1) == oscrypto_kdf(
        "sha224", _password, _salt, 2000, 221, 1
    )

    assert pkcs12_kdf("sha256", _password, _salt, 2000, 221, 1) == oscrypto_kdf(
        "sha256", _password, _salt, 2000, 221, 1
    )

    assert pkcs12_kdf("sha384", _password, _salt, 2000, 221, 1) == oscrypto_kdf(
        "sha384", _password, _salt, 2000, 221, 1
    )

    assert pkcs12_kdf("sha512", _password, _salt, 2000, 221, 1) == oscrypto_kdf(
        "sha512", _password, _salt, 2000, 221, 1
    )


if __name__ == "__main__":
    test_kdf()
    test_kdf2()
    test_kdf3()
