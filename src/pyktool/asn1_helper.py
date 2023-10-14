from asn1crypto import core, algos, keys

id_pbeWithSha1AndRC4_128 = algos.EncryptionAlgorithmId("pkcs12_sha1_rc4_128")
id_pbeWithSha1AndRC4_40 = algos.EncryptionAlgorithmId("pkcs12_sha1_rc4_40")
id_pbeWithSha1AndDESede = algos.EncryptionAlgorithmId("pkcs12_sha1_tripledes_3key")
id_pbeWithSha1And2DES = algos.EncryptionAlgorithmId("pkcs12_sha1_tripledes_2key")
id_pbeWithSha1AndRC2_128 = algos.EncryptionAlgorithmId("pkcs12_sha1_rc2_128")
id_pbeWithSha1AndRC2_40 = algos.EncryptionAlgorithmId("pkcs12_sha1_rc2_40")

id_aes128cbc = algos.EncryptionAlgorithmId("aes128_cbc")
id_aes192cbc = algos.EncryptionAlgorithmId("aes192_cbc")
id_aes256cbc = algos.EncryptionAlgorithmId("aes256_cbc")
id_des3cbc = algos.EncryptionAlgorithmId("tripledes_3key")
id_aes256ccm = algos.EncryptionAlgorithmId("aes256_ccm")


id_sha1 = algos.HmacAlgorithmId("sha1")
id_sha224 = algos.HmacAlgorithmId("sha224")
id_sha256 = algos.HmacAlgorithmId("sha256")
id_sha384 = algos.HmacAlgorithmId("sha384")
id_sha512 = algos.HmacAlgorithmId("sha512")

id_PBKDF2 = algos.KdfAlgorithmId("pbkdf2")
id_PBES2 = algos.EncryptionAlgorithmId("pbes2")

# PKCS12
id_PKCS8ShroudedKeyBag = core.ObjectIdentifier("1.2.840.113549.1.12.10.1.2")
id_CertBag = core.ObjectIdentifier("1.2.840.113549.1.12.10.1.3")
id_SecretBag = core.ObjectIdentifier("1.2.840.113549.1.12.10.1.5")
id_SafeContentsBag = core.ObjectIdentifier("1.2.840.113549.1.12.10.1.6")

pkcs9FriendlyName = core.ObjectIdentifier("1.2.840.113549.1.9.20")
pkcs9LocalKeyId = core.ObjectIdentifier("1.2.840.113549.1.9.21")
trustedKeyUsage = core.ObjectIdentifier("2.16.840.1.113894.746875.1.1")
anyExtendedKeyUsage = core.ObjectIdentifier("2.5.29.37.0")
x509CertificateId = core.ObjectIdentifier("1.2.840.113549.1.9.22.1")


algos.EncryptionAlgorithmId._map["2.16.840.1.101.3.4.1"] = "aes"
algos.EncryptionAlgorithm._oid_specs["aes"] = core.Null


class SecretKeyInfo(core.Sequence):
    """
    Source: https://tools.ietf.org/html/rfc5208#page-3
    """

    _fields = [
        ("version", core.Integer),
        ("secret_key_algorithm", algos.EncryptionAlgorithm),
        ("secret_key", core.ParsableOctetString),
        ("attributes", keys.Attributes, {"implicit": 0, "optional": True}),
    ]


map_oid_alg = {
    "2.16.840.1.101.3.4.1": "AES",
    "1.3.14.3.2.7": "DES",
    "1.3.14.3.2.17": "DESede",
    "1.2.840.113549.2.7": "HmacSHA1",
    "1.2.840.113549.2.8": "HmacSHA224",
    "1.2.840.113549.2.9": "HmacSHA256",
    "1.2.840.113549.2.10": "HmacSHA384",
    "1.2.840.113549.2.11": "HmacSHA512",
    "1.3.6.1.4.1.3029.1.1.2": "Blowfish",
}


rev_oid_alg = {}
for k in map_oid_alg:
    rev_oid_alg[map_oid_alg[k]] = k
    rev_oid_alg[k] = k


def map_alg_name(oid):
    return map_oid_alg[oid.dotted]
