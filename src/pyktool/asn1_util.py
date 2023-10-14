import logging
from cryptography.hazmat.primitives.ciphers import algorithms

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

from .bcfks_asn1 import CcmParams

from asn1crypto import core, algos

LOG = logging.getLogger(__name__)

PBES2_oids = {
    id_aes128cbc.dotted: (
        "cbc",
        algorithms.AES,
        16,
    ),
    id_aes192cbc.dotted: (
        "cbc",
        algorithms.AES,
        24,
    ),
    id_aes256cbc.dotted: (
        "cbc",
        algorithms.AES,
        32,
    ),
    id_des3cbc.dotted: (
        "cbc",
        algorithms.TripleDES,
        24,
    ),
    id_aes256ccm.dotted: ("ccm", "CCM", 32),
}


def pbes2_algo_id(enc_oid, enc_iv, salt, count, hash_oid=None, **kwargs):
    kdf = algos.KdfAlgorithm()
    kdf["algorithm"] = algos.KdfAlgorithmId("1.2.840.113549.1.5.12")

    data = algos.Pbkdf2Params()
    data["salt"] = core.OctetString(salt)
    data["iteration_count"] = count
    if hash_oid:
        data["prf"]["algorithm"] = hash_oid
        data["prf"]["parameters"] = core.Any(core.Null())

    enc = algos.EncryptionAlgorithm()
    enc["algorithm"] = enc_oid
    data["key_length"] = PBES2_oids[enc_oid.dotted][2]
    kdf["parameters"] = data
    if PBES2_oids[enc_oid.dotted][0] == "cbc":
        enc["parameters"] = core.OctetString(enc_iv)
    elif PBES2_oids[enc_oid.dotted][0] == "ccm":
        LOG.debug("writing ccm parameters")
        ccm = CcmParams()
        ccm["aes_nonce"] = kwargs["aes_nonce"]
        ccm["aes_ICVlen"] = kwargs["aes_ICVlen"]
        enc["parameters"] = ccm

    params = algos.Pbes2Params()
    params["key_derivation_func"] = kdf
    params["encryption_scheme"] = enc

    x = algos.EncryptionAlgorithm()
    x["algorithm"] = id_PBES2
    x["parameters"] = params

    return x


def pbe_pkcs12_algo_id(oid, salt, count):
    params = algos.Pbes1Params()
    params["salt"] = salt
    params["iterations"] = count

    x = algos.EncryptionAlgorithm()
    x["algorithm"] = oid
    x["parameters"] = params
    return x
