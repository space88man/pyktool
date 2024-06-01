import os
import random
import hashlib

from .util import uread_data, uread_int, uread_int1, uread_utf
from .util import uwrite_utf, uwrite_data
from .util import b1, b4, b8

from .jks import KeyStore, PEMMixin
from .pbe import hmac_pkcs12_pbkdf, PBECipher, Legacy
from .asn1_helper import id_pbeWithSha1AndDESede as DES3, map_oid_alg
from .pkcs8 import keytype

import logging

LOG = logging.getLogger(__name__)


KEY_PRIVATE = 0
KEY_PUBLIC = 1
KEY_SECRET = 2


BKS_NULL = 0
BKS_CERTIFICATE = 1
BKS_KEY = 2
BKS_SECRET = 3
BKS_SEALED = 4

MAGIC_NUMBER_BKS = b4.pack(0x00000002)
MAGIC_NUMBER_V0 = b4.pack(0x00000000)
MAGIC_NUMBER_V1 = b4.pack(0x00000001)

SHA_LENGTH = 20

# fake NID for Twofish, implemented in legacy
NID_TWOFISH = 900


def _pbe_decrypt(data, password):
    pos = 0
    salt, pos, size = uread_data(data, pos)
    count, pos = uread_int(data, pos)

    return PBECipher.new_v1(password, DES3, salt, count).decrypt(data[pos:])


def _pbe_encrypt(data, password, salt=None, count=None):
    if salt is None:
        salt = os.urandom(20)
    if count is None:
        count = random.randint(2000, 4000)

    ciphertext = PBECipher.new_v1(password, DES3, salt, count).encrypt(data)

    out = uwrite_data(salt)
    out += b4.pack(count)

    return out + ciphertext


class BKS(KeyStore):
    def load_s(self, data, password):
        self.filetype = None
        magic_number = data[:4]

        if magic_number == MAGIC_NUMBER_BKS:
            self.filetype = "bks"
        elif magic_number == MAGIC_NUMBER_V0 or magic_number == MAGIC_NUMBER_V1:
            self.filetype = "uber"
        else:
            raise ValueError("Not a BKS or UBER keystore")

        ks = self

        pos = 0
        ks._version, pos = uread_int(data, pos)
        salt, pos, salt_length = uread_data(data, pos)
        ks._salt = salt
        iteration_count, pos = uread_int(data, pos)
        ks._iteration_count = iteration_count
        m_pos = pos

        if ks._version == 1:
            cipher = Legacy(
                NID_TWOFISH, password.encode("ascii"), salt, iteration_count
            )
            data = cipher.decrypt(data[m_pos:])
            m_pos = pos = 0

        ks._load(data[pos:], password)

        file_hmac = data[-SHA_LENGTH:]

        if ks._version == 2:
            # BKS uses hmac checksum
            compute_hmac = hmac_pkcs12_pbkdf(
                password, salt, iteration_count, data[m_pos:-SHA_LENGTH],
                legacy=True
            )

        if ks._version == 1:
            # UBER uses sha1 checksum
            compute_hmac = hashlib.sha1(data[m_pos:-SHA_LENGTH]).digest()

        if file_hmac != compute_hmac:
            raise ValueError("Hash mismatch; incorrect password or data corrupted")

        return self

    def _load(self, data, password):
        pos = 0

        type, pos = uread_int1(data, pos)

        count = 0
        while type > 0:
            count += 1

            entry = storeEntry.new(type)
            alias, pos = uread_utf(data, pos)
            entry.alias = alias

            entry.timestamp = b8.unpack_from(data, pos)[0]
            pos += 8

            entry.cert_chain = []
            cert_count, pos = uread_int(data, pos)

            for k in range(cert_count):
                cert_type, pos = uread_utf(data, pos)
                cert, pos, size = uread_data(data, pos)
                entry.cert_chain.append((cert_type, cert))

            pos = entry.load(data, pos, password)

            if type == BKS_SEALED and entry.key_type == KEY_PRIVATE:
                self.add_private_key(entry)
            elif type == BKS_SEALED and entry.key_type == KEY_SECRET:
                self.add_secret_key(entry)
            elif type == BKS_CERTIFICATE:
                self.add_cert(entry)

            type, pos = uread_int1(data, pos)

    def write_f(self, fp, password, uber=False):
        fp.write(self.write_s(password, uber))

    def write_s(self, password, uber=False):
        ks = self
        output = b4.pack(2)  # KS version

        output += b4.pack(20)
        salt = os.urandom(20)
        output += salt

        iteration_count = random.randint(2000, 4000)
        output += b4.pack(iteration_count)

        m_pos = len(output)

        for k in ks.private_keys:
            output += b1.pack(BKS_SEALED)
            output += uwrite_utf(k.alias)

            # output += b8.pack(int(time.time() * 1000))
            output += b8.pack(k.timestamp)

            # output cert chain
            output += b4.pack(len(k.cert_chain))

            for k1 in k.cert_chain:
                output += uwrite_utf(k1[0])
                output += uwrite_data(k1[1])

            # output private key
            data2 = b1.pack(KEY_PRIVATE)
            data2 += uwrite_utf("PKCS#8")
            data2 += uwrite_utf(keytype(k))
            data2 += uwrite_data(k.pkey)

            rawdata = _pbe_encrypt(data2, password)

            output += uwrite_data(rawdata)

        for k in ks.secret_keys:
            output += b1.pack(BKS_SEALED)
            output += uwrite_utf(k.alias)

            # output += b8.pack(int(time.time() * 1000))
            output += b8.pack(k.timestamp)
            output += b4.pack(0)

            # output private key
            data2 = b1.pack(KEY_SECRET)
            data2 += uwrite_utf("RAW")
            data2 += uwrite_utf(k.key_alg)
            data2 += uwrite_data(k.pkey)

            rawdata = _pbe_encrypt(data2, password)

            output += uwrite_data(rawdata)

        for k in ks.certs:
            output += b1.pack(BKS_CERTIFICATE)
            output += uwrite_utf(k.alias)

            # output += b8.pack(int(time.time() * 1000))
            output += b8.pack(k.timestamp)

            output += b4.pack(0)

            output += uwrite_utf(k.type)
            output += uwrite_data(k.cert)

        output += b1.pack(0)

        if uber:
            rawdata = output[m_pos:]
            checksum = hashlib.sha1(rawdata).digest()
            rawdata += checksum

            cipher = Legacy(
                NID_TWOFISH, password.encode("ascii"), salt, iteration_count
            )
            ct = cipher.encrypt(rawdata)

            output = b4.pack(1) + output[4:m_pos] + ct

        else:
            compute_hmac = hmac_pkcs12_pbkdf(
                password, salt, iteration_count, output[m_pos:],
                legacy=True
            )
            output += compute_hmac

        return output


class UBER(BKS):
    def write_f(self, fp, password, uber=False):
        fp.write(self.write_s(password, True))


class storeEntry:
    def __init__(self):
        self.type = BKS_NULL

    @staticmethod
    def new(bks):
        if bks == BKS_CERTIFICATE:
            return certStoreEntry()
        elif bks == BKS_KEY:
            return storeEntry()
        elif bks == BKS_SECRET:
            return storeEntry()
        elif bks == BKS_SEALED:
            return sealedStoreEntry()
        else:
            return None

    def get_alias(self):
        return self.alias

    def get_type(self):
        return self.type


class certStoreEntry(storeEntry, PEMMixin):
    def load(self, data, pos, password=None):
        self.type, pos = uread_utf(data, pos)
        self.cert, pos, seal_size = uread_data(data, pos)
        return pos


OID_EC_PUBLIC_KEY = (1, 2, 840, 10045, 2, 1)
OID_RSA_ENCRYPTION = (1, 2, 840, 113549, 1, 1, 1)


class sealedStoreEntry(storeEntry, PEMMixin):
    def __init__(self):
        self.pkey = None
        self.cert_chain = []

    def load(self, data, pos, password):
        self._rawdata, pos, dummy = uread_data(data, pos)
        data2 = _pbe_decrypt(self._rawdata, password)
        pos2 = 0

        self.key_type, pos2 = uread_int1(data2, pos2)
        self.key_form, pos2 = uread_utf(data2, pos2)
        self.key_alg, pos2 = uread_utf(data2, pos2)
        if self.key_alg in map_oid_alg:
            LOG.warn("replacing %s with %s", self.key_alg, map_oid_alg[self.key_alg])
            self.key_alg = map_oid_alg[self.key_alg]

        if self.key_type == KEY_PRIVATE:
            self.type = self.key_form
        else:
            self.type = "SECRET"  # key_type == 2

        self.pkey, pos2, self._keysize = uread_data(data2, pos2)

        return pos
