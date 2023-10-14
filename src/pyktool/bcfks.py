# vim: et:sts:ts=4:sw=4:
import logging
import time
from datetime import datetime, timezone
import os

from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from asn1crypto.core import OctetString, GeneralizedTime, Sequence
from asn1crypto.algos import (
    HmacAlgorithm,
    KdfAlgorithm,
    AlgorithmIdentifier,
    EncryptionAlgorithm,
    Pbkdf2Params,
)
from asn1crypto.x509 import Certificate
from .pbe import pkcs12_password
from . import pbe, jks
from .pkcs8 import pkcs8_unwrap, pkcs8_wrap
from .bcfks_asn1 import *
from .asn1_helper import id_sha512, id_aes256ccm

LOG = logging.getLogger(__name__)
backend = default_backend()

# private final static BigInteger CERTIFICATE = BigInteger.valueOf(0);
# private final static BigInteger PRIVATE_KEY = BigInteger.valueOf(1);
# private final static BigInteger SECRET_KEY = BigInteger.valueOf(2);
# private final static BigInteger PROTECTED_PRIVATE_KEY = BigInteger.valueOf(3);
# private final static BigInteger PROTECTED_SECRET_KEY = BigInteger.valueOf(4);
type_str = [
    "CERTIFICATE",
    "PRIVATE_KEY",
    "SECRET_KEY",
    "PROTECTED_PRIVATE_KEY",
    "PROTECTED_SECRET_KEY",
]

EncryptionAlgorithm._oid_specs["aes128_ccm"] = CcmParams
EncryptionAlgorithm._oid_specs["aes192_ccm"] = CcmParams
EncryptionAlgorithm._oid_specs["aes256_ccm"] = CcmParams


def _fix_date(obj):
    if not hasattr(obj, "creation_date"):
        obj.creation_date = datetime.fromtimestamp(obj.timestamp / 1000, timezone.utc)
    if not hasattr(obj, "last_modified_date"):
        obj.last_modified_date = obj.creation_date


def cert_handler(self, obj_data):
    ts = obj_data["creation_date"].native
    tmp = jks.Cert(
        obj_data["identifier"].native,
        int(time.mktime(ts.timetuple()) * 1000),
        "X.509",
        obj_data["data"].native,
    )
    tmp.last_modified_date = obj_data["last_modified_date"].native
    tmp.creation_date = ts
    self.add_cert(tmp)


def private_key_handler(self, obj_data):
    password = self._password
    private_key = EncryptedPrivateKeyObjectData().load(obj_data["data"].native)
    pkey = pkcs8_unwrap(
        private_key["encrypted_private_key_info"],
        pkcs12_password(password) + pkcs12_password("PRIVATE_KEY_ENCRYPTION"),
    )
    cert_chain = []
    for k in private_key["certificates"]:
        cert_chain.append(("X.509", k.dump()))

    ts = obj_data["creation_date"].native
    tmp = jks.PrivateKey(
        obj_data["identifier"].native,
        int(time.mktime(ts.timetuple()) * 1000),
        pkey,
        cert_chain,
    )
    tmp.last_modified_date = obj_data["last_modified_date"].native
    tmp.creation_date = ts
    self.add_private_key(tmp)


dispatch = {0: cert_handler, 1: private_key_handler}


class BCFKeyStore(jks.KeyStore):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._version = 1
        self._creation_date = datetime.utcnow()
        self._last_modified_date = datetime.utcnow()

    def _encrypted_data_handler(self, chunk):
        password = self._password
        cipher = pbe.PBECipher(
            pkcs12_password(password) + pkcs12_password("STORE_ENCRYPTION"),
            chunk["encryption_algorithm"],
        )

        self._data_handler(ObjectStoreData().load(cipher.decrypt(chunk[1].native)))

    def _data_handler(self, chunk):
        self._version = chunk["version"].native

        self._integrity_algorithm = chunk["integrity_algorithm"].native
        assert self._integrity_algorithm["algorithm"] == self._outer_mac_algorithm
        LOG.debug("Store and ObjectData mac algorithms are identical: OK")

        self._creation_date = chunk["creation_date"].native
        self._last_modified_date = chunk["last_modified_date"].native
        self._comment = chunk["comment"].native

        for k in chunk["object_data_sequence"]:
            idx = k["type"].native
            dispatch[idx](self, k)

    def load_s(self, fdata, password):
        if isinstance(fdata, str):
            with open(fdata, "rb") as fp:
                fdata = fp.read()

        self._password = password

        ks = BCFKS.load(fdata)

        raw = ks[0].dump()
        chk = ks[1].chosen

        chk_key = pbe.pbkdf2(
            pkcs12_password(password) + pkcs12_password("INTEGRITY_CHECK"),
            64,
            params=chk["pbkd_algorithm"]["parameters"],
        )
        chk_hash = pbe.v2_prf_dict[chk["mac_algorithm"]["algorithm"].dotted]
        self._outer_mac_algorithm = chk["mac_algorithm"]["algorithm"].dotted
        hm = HMAC(chk_key, chk_hash, backend)
        hm.update(raw)
        hm.verify(chk["mac"].native)
        LOG.debug("Outer HMAC verified: OK")

        if len(ks[0]) == 2:
            chunk = EncryptedObjectStoreData().load(raw)
            self._encrypted_data_handler(chunk)
        else:
            chunk = ObjectStoreData().load(raw)
            self._data_handler(chunk)

    def write_s(self, password):
        outer = BCFKS()

        store = ObjectStoreData()
        store["version"] = self._version

        store["integrity_algorithm"] = AlgorithmIdentifier(
            value={"algorithm": id_sha512}
        )
        # store['object_data_sequence'] = ObjectDataSequence()
        store["creation_date"] = self._creation_date
        store["last_modified_date"] = self._last_modified_date

        ods = []
        for k in self.private_keys:
            _fix_date(k)

            obj = ObjectData()

            obj["identifier"] = k.alias
            obj["type"] = 1

            pkey = EncryptedPrivateKeyObjectData()

            certs = []
            for cert in k.cert_chain:
                certs.append(Certificate().load(cert[1]))
            pkey["certificates"] = certs

            cipher = pbe.PBECipher.new_v2(
                pkcs12_password(password) + pkcs12_password("PRIVATE_KEY_ENCRYPTION"),
                id_aes256ccm,
                b"",
                os.urandom(64),
                51200,
                hash_oid=id_sha512,
                aes_nonce=os.urandom(12),
                aes_ICVlen=8,
            )
            pkey["encrypted_private_key_info"] = pkcs8_wrap(k.pkey, cipher, dump=False)

            obj["data"] = pkey.dump()
            obj["last_modified_date"] = GeneralizedTime(k.last_modified_date)
            obj["creation_date"] = GeneralizedTime(k.creation_date)

            ods.append(obj)

        for k in self.certs:
            _fix_date(k)

            obj = ObjectData()

            obj["identifier"] = k.alias
            obj["type"] = 0

            obj["data"] = k.cert
            obj["last_modified_date"] = GeneralizedTime(k.last_modified_date)
            obj["creation_date"] = GeneralizedTime(k.creation_date)

            ods.append(obj)

        store["object_data_sequence"] = ods
        store_cipher = pbe.PBECipher.new_v2(
            pkcs12_password(password) + pkcs12_password("STORE_ENCRYPTION"),
            id_aes256ccm,
            b"",
            os.urandom(64),
            51200,
            hash_oid=id_sha512,
            aes_nonce=os.urandom(12),
            aes_ICVlen=8,
        )

        raw_data = store_cipher.encrypt(store.dump())

        enc_object_store = EncryptedObjectStoreData()

        enc_object_store["encryption_algorithm"] = store_cipher.algo_id
        enc_object_store["encrypted_content"] = raw_data

        raw_store = enc_object_store.dump()

        chk = PbeMacIntegrityCheck()
        kdf_p = Pbkdf2Params()
        kdf_p["salt"] = OctetString(os.urandom(64))
        kdf_p["iteration_count"] = 51200
        kdf_p["key_length"] = 64
        kdf_p["prf"] = HmacAlgorithm(value={"algorithm": "sha512"})

        chk["pbkd_algorithm"] = KdfAlgorithm(
            value={"algorithm": "pbkdf2", "parameters": kdf_p}
        )

        chk["mac_algorithm"] = HmacAlgorithm(value={"algorithm": "sha512"})

        chk_key = pbe.pbkdf2(
            pkcs12_password(password) + pkcs12_password("INTEGRITY_CHECK"),
            64,
            params=chk["pbkd_algorithm"]["parameters"],
        )
        chk_hash = pbe.v2_prf_dict[chk["mac_algorithm"]["algorithm"].dotted]

        hm = HMAC(chk_key, chk_hash, backend)

        hm.update(raw_store)

        chk["mac"] = hm.finalize()

        outer["store_data"] = enc_object_store
        outer["integrity_check"] = chk

        return outer.dump()
