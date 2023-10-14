from asn1crypto.core import (
    Choice,
    Integer,
    OctetString,
    GeneralizedTime,
    UTF8String,
    SequenceOf,
    Sequence,
)
from asn1crypto.algos import (
    HmacAlgorithm,
    KdfAlgorithm,
    AlgorithmIdentifier,
    EncryptionAlgorithm,
)
from asn1crypto.keys import EncryptedPrivateKeyInfo
from asn1crypto.x509 import Certificate


class CertificateList(SequenceOf):
    _child_spec = Certificate


class EncryptedPrivateKeyObjectData(Sequence):
    _fields = [
        ("encrypted_private_key_info", EncryptedPrivateKeyInfo),
        ("certificates", CertificateList),
    ]


class ObjectData(Sequence):
    _fields = [
        ("type", Integer),
        ("identifier", UTF8String),
        ("creation_date", GeneralizedTime),
        ("last_modified_date", GeneralizedTime),
        ("data", OctetString),
        ("comment", UTF8String, {"optional": True}),
    ]


class ObjectDataSequence(SequenceOf):
    _child_spec = ObjectData


class ObjectStoreData(Sequence):
    _fields = [
        ("version", Integer),
        ("integrity_algorithm", AlgorithmIdentifier),
        ("creation_date", GeneralizedTime),
        ("last_modified_date", GeneralizedTime),
        ("object_data_sequence", ObjectDataSequence),
        ("comment", UTF8String, {"optional": True}),
    ]


class EncryptedObjectStoreData(Sequence):
    _fields = [
        ("encryption_algorithm", EncryptionAlgorithm),
        ("encrypted_content", OctetString),
    ]


class AnyStoreData(Choice):
    _alternatives = [
        ("encrypted_object_data", EncryptedObjectStoreData),
        ("object_data", ObjectStoreData),
    ]


class PbeMacIntegrityCheck(Sequence):
    _fields = [
        ("mac_algorithm", HmacAlgorithm),
        ("pbkd_algorithm", KdfAlgorithm),
        ("mac", OctetString),
    ]


class ObjectStoreIntegrityCheck(Choice):
    _alternatives = [
        ("pbe_mac_integrity_check", PbeMacIntegrityCheck),
    ]


class BCFKS(Sequence):
    # Don't put CHOICE here
    # cannot disambiguate as BCFKS does not use explicit tagging
    # load as Sequence and use heuristics
    # len() == 2 ==> EncryptedObjectStoreData
    _fields = [
        ("store_data", Sequence),
        ("integrity_check", ObjectStoreIntegrityCheck),
    ]


class CcmParams(Sequence):
    _fields = [("aes_nonce", OctetString), ("aes_ICVlen", Integer, {"default": 12})]


EncryptionAlgorithm._oid_specs["aes128_ccm"] = CcmParams
EncryptionAlgorithm._oid_specs["aes192_ccm"] = CcmParams
EncryptionAlgorithm._oid_specs["aes256_ccm"] = CcmParams
