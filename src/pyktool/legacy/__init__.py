from .pkcs12_kdf import pkcs12_kdf as kdf_
from .twofish import Twofish
from Crypto.Cipher import ARC2, ARC4, DES3
from Crypto.Util.Padding import pad, unpad


class LegacyError(Exception):
    pass


_hash_alg = {0: "sha1", 1: "sha256", 2: "sha384", 3: "sha512", 4: "sha224"}
_length = {144: 16, 145: 5, 146: 24, 147: 16, 148: 16, 149: 5, 900: 32}


# We used to use oscrypto here but Fedora 37 builds OpenSSL 3.0.x without ARC2, ARC4.
# A workaround is to force oscrypto to use OpenSSL 1.1.1
# import oscrypto
# oscrypto.use_openssl("/usr/lib64/libcrypto.so.1.1.1", "/usr/lib64/libssl.so.1.1.1")
# This has to be done in pbe.py as that loads oscrypto before this module


def _rc2_cbc_pkcs5_encrypt(key, data, iv):

    cipher = ARC2.new(key, ARC2.MODE_CBC, iv=iv, effective_keylen=8 * len(key))
    output = iv, cipher.encrypt(pad(data, ARC2.block_size))

    return output


def _rc2_cbc_pkcs5_decrypt(key, data, iv):

    cipher = ARC2.new(key, ARC2.MODE_CBC, iv=iv, effective_keylen=8 * len(key))
    return unpad(cipher.decrypt(data), ARC2.block_size)


def _des3_cbc_pkcs5_encrypt(key, data, iv):

    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    output = iv, cipher.encrypt(pad(data, DES3.block_size))

    return output


def _des3_cbc_pkcs5_decrypt(key, data, iv):

    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(data), DES3.block_size)


def _rc4_encrypt(key, data):
    nonce = b""
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


def _rc4_decrypt(key, data):
    nonce = b""
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def pkcs12_pbe_crypt(nid, password, salt, count, data, encrypt=1):

    key = kdf_("sha1", password, salt, count, _length[nid], 1)
    iv = (
        kdf_("sha1", password, salt, count, 8, 2)
        if nid != 900
        else kdf_("sha1", password, salt, count, 16, 2)
    )

    # key, iv = PKCS12KDF(password, salt, count, "sha1", _length[nid]*8).generate_key_and_iv()

    if encrypt:
        if nid == 144 or nid == 145:
            return (b"", _rc4_encrypt(key, data))
        elif nid == 146 or nid == 147:
            return _des3_cbc_pkcs5_encrypt(key, data, iv)
        elif nid == 148 or nid == 149:
            return _rc2_cbc_pkcs5_encrypt(key, data, iv)
        elif nid == 900:
            return twofish_cbc_pkcs5_encrypt(key, data, iv)
        else:
            raise LegacyError(f"Unknown NID: {nid}")
    else:
        if nid == 144 or nid == 145:
            return _rc4_decrypt(key, data)
        elif nid == 146 or nid == 147:
            return _des3_cbc_pkcs5_decrypt(key, data, iv)
        elif nid == 148 or nid == 149:
            return _rc2_cbc_pkcs5_decrypt(key, data, iv)
        elif nid == 900:
            return twofish_cbc_pkcs5_decrypt(key, data, iv)
        else:
            raise LegacyError(f"Unknown NID: {nid}")


def twofish_cbc_pkcs5_encrypt(key, data, iv):

    state = iv
    fish = Twofish(key)

    cipher = b""
    l_data = len(data) % 16
    pad = (16 - l_data) if l_data else 16
    data += bytes((pad,) * pad)

    for x in range(0, len(data) // 16):
        blk_in = bytes([x ^ y for x, y in zip(state, data[16 * x : 16 * x + 16])])
        state = fish.encrypt(blk_in)
        cipher += state

    return iv, cipher


def twofish_cbc_pkcs5_decrypt(key, data, iv):

    fish = Twofish(key)
    plain = b""
    assert len(data) % 16 == 0

    state = iv
    for x in range(0, len(data) // 16):
        blk_out = fish.decrypt(data[16 * x : 16 * x + 16])
        plain += bytes([x ^ y for x, y in zip(state, blk_out)])
        state = data[16 * x : 16 * x + 16]

    assert 1 <= plain[-1] <= 16
    return plain[: -plain[-1]]
