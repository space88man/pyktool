#! /usr/bin/env python

import os
import hashlib
from collections import namedtuple

from asn1crypto import core, algos, pkcs12 as P12, cms, keys
from .asn1_helper import id_pbeWithSha1AndDESede as DES3, id_aes128cbc as AES128
from .asn1_helper import *
from .asn1_util import pbes2_algo_id

from .certutil import cert_get_subject
from .jks import KeyStore
from .bks import sealedStoreEntry, certStoreEntry
from . import pbe, errors
from . import pkcs8
import time
import logging

LOG = logging.getLogger(__name__)


def pretty_hex(x):
    return pbe.colonify(x)


RFC2315 = namedtuple("RFC2315", ["data", "encrypted_data"])
rfc2315 = RFC2315(
    data=core.ObjectIdentifier("1.2.840.113549.1.7.1"),
    encrypted_data=core.ObjectIdentifier("1.2.840.113549.1.7.6"),
)


def parse_pkcs12(my_der, keystore):
    password = keystore._password
    keystore._certs = []
    keystore._privatekeys = []
    keystore._secretkeys = []

    pfx = P12.Pfx.load(my_der)

    auth_safe = pfx["auth_safe"]

    content_type = auth_safe["content_type"]
    # data or encryptedData: here we expect data
    assert content_type == rfc2315.data
    content = auth_safe["content"]

    mac_data = pfx["mac_data"]
    digest = mac_data["mac"]["digest"].native
    LOG.debug(
        "PKCS12 file digest %s", mac_data["mac"]["digest_algorithm"]["algorithm"].native
    )
    c3 = pbe.hmac_pkcs12_pbkdf(password, None, None, content.native, mac_data=mac_data)

    if digest != c3:
        _msg = "Hash mismatch; incorrect password or data corrupted"
        LOG.error("digest != c3: digest = %s c3 = %s", digest, c3)
        raise ValueError(_msg)

    LOG.debug("MAC verified OK")
    # decode as AuthenticatedSafe
    content = auth_safe["content"].cast(core.ParsableOctetString)
    seq = content.parse(spec=P12.AuthenticatedSafe)

    for bag in seq:
        oid = bag["content_type"]
        if oid == rfc2315.data:
            # private/secret keys
            LOG.debug("parsing rfc2315.data content")
            process_data(bag, keystore)

        if oid == rfc2315.encrypted_data:
            # trusted certs
            LOG.debug("parsing rfc2315.encrypted_data content")
            process_encrypted_data(bag, keystore)

    check_chains(keystore)
    build_ks(keystore)


def process_data(bag, keystore):
    content = bag["content"].cast(core.ParsableOctetString)
    safe_content = content.parse(P12.SafeContents)
    process_safe_content(safe_content, keystore)


def process_encrypted_data(bag, keystore):
    password = keystore._password

    content = bag["content"]
    # encryptedData

    enc_info = content["encrypted_content_info"]

    octets = enc_info["encrypted_content"].native
    algo_id = enc_info["content_encryption_algorithm"]
    substrate = pbe.PBECipher(password, algo_id).decrypt(octets)

    safe_content = P12.SafeContents.load(substrate)

    process_safe_content(safe_content, keystore)


def attributes_message(col):
    for k in col:
        tag = _oid_to_str(k["type"])
        if tag == "localKeyId":
            values = ", ".join([pretty_hex(x.native) for x in k["values"]])
        elif tag == "friendlyName":
            values = ", ".join([x.native for x in k["values"]])
        elif tag == "trustedKeyUsage":
            values = ", ".join([x.native for x in k["values"]])
        else:
            values = "<unknown tag> {}...".format(pretty_hex(k["values"].dump()[:16]))
        LOG.debug("    {}: {}".format(tag, values))


def _oid_to_str(oid):
    _map = {
        "1.2.840.113549.1.9.20": "friendlyName",
        "1.2.840.113549.1.9.21": "localKeyId",
        "2.16.840.1.113894.746875.1.1": "trustedKeyUsage",
    }
    return _map.get(oid.dotted, oid.dotted)


def _oid_value_to_str(oid, value):
    if oid == pkcs9FriendlyName:
        return value
    elif oid == pkcs9LocalKeyId:
        return pretty_hex(value)


def do_cert(safe_bag, keystore):
    assert safe_bag["bag_id"] == id_CertBag
    _certs = keystore._certs

    cert_bag = safe_bag["bag_value"]
    cert_id = cert_bag["cert_id"]
    cert_DER = cert_bag["cert_value"].cast(core.OctetString)

    assert x509CertificateId == cert_id

    cert_dict = {}
    cert_dict["der"] = cert_DER.native

    if len(safe_bag) == 3:
        LOG.debug("Bag Attributes: CertBag")
        for k in safe_bag["bag_attributes"]:
            oid_str = _oid_to_str(k["type"])
            cert_dict[oid_str] = []
            for x in k["values"]:
                cert_dict[oid_str].append(x)
        attributes_message(safe_bag["bag_attributes"])

    cert_dict["subject"], cert_dict["issuer"] = cert_get_subject(cert_dict["der"])
    _certs.append(cert_dict)
    LOG.debug("subject={}".format(cert_dict["subject"][0]))
    LOG.debug("issuer={}".format(cert_dict["issuer"][0]))


def do_pkcs8_shrouded(bag, keystore):
    password = keystore._password
    _privatekeys = keystore._privatekeys
    assert bag["bag_id"] == id_PKCS8ShroudedKeyBag
    key = bag["bag_value"]
    assert isinstance(key, keys.EncryptedPrivateKeyInfo)
    newkey = dict()
    if len(bag) == 3:
        LOG.debug("Bag Attributes: Pkcs8ShroudedKeyBag")
        for k in bag["bag_attributes"]:
            oid_str = _oid_to_str(k["type"])
            newkey[oid_str] = []

            for y in k["values"]:
                newkey[oid_str].append(y)
        attributes_message(bag["bag_attributes"])
    newkey["der"] = pkcs8.pkcs8_unwrap(key, password)

    _privatekeys.append(newkey)


def do_secret_bag(bag, keystore):
    password = keystore._password
    _secretkeys = keystore._secretkeys
    assert bag["bag_id"] == id_SecretBag

    if bag["bag_value"]["secret_type_id"] == id_PKCS8ShroudedKeyBag:
        key = keys.EncryptedPrivateKeyInfo.load(bag["bag_value"]["secret_value"].native)
        key_der = pkcs8.pkcs8_unwrap(key, password)
        key_2 = SecretKeyInfo.load(key_der)
    else:
        LOG.error("Unknown SecretBag")
        return

    newkey = dict()
    if len(bag) == 3:
        LOG.debug("Bag Attributes: SecretBag")
        for k in bag["bag_attributes"]:
            oid_str = _oid_to_str(k["type"])
            newkey[oid_str] = []

            for y in k["values"]:
                newkey[oid_str].append(y)
        attributes_message(bag["bag_attributes"])

    # raw key, not DER
    newkey["der"] = key_2["secret_key"].native
    newkey["key_alg"] = key_2["secret_key_algorithm"]["algorithm"]

    _secretkeys.append(newkey)


# _privatekeys = []
# _certs = []
def process_safe_content(safe_content, keystore):
    for safe_bag in safe_content:
        if safe_bag["bag_id"] == id_CertBag:
            do_cert(safe_bag, keystore)

        if safe_bag["bag_id"] == id_PKCS8ShroudedKeyBag:
            do_pkcs8_shrouded(safe_bag, keystore)

        if safe_bag["bag_id"] == id_SecretBag:
            do_secret_bag(safe_bag, keystore)

        if safe_bag["bag_id"] == id_SafeContentsBag:
            process_safe_content(safe_bag["bag_value"], keystore)


def find_cert_chain(cert, _certs):
    chain = [cert]
    if cert["subject"][1] == cert["issuer"][1]:
        return chain

    next = [x for x in _certs if x["subject"][1] == cert["issuer"][1]]
    # a cert may appear multiple times
    # assert len(next) == 0 or len(next) == 1
    if len(next) == 0:
        return chain
    else:
        return chain + find_cert_chain(next[0], _certs)


def check_chains(ks):
    _privatekeys = ks._privatekeys
    _certs = ks._certs
    for k in _privatekeys:
        cert = [
            x
            for x in _certs
            if "localKeyId" in x and x["localKeyId"] == k["localKeyId"]
        ]
        # match on friendlyName if fail to match on localKeyId
        if len(cert) != 1:
            cert = [
                x
                for x in _certs
                if "friendlyName" in x and x["friendlyName"] == k["friendlyName"]
            ]
        assert len(cert) == 1
        chain = find_cert_chain(cert[0], _certs)
        k["chain"] = chain


def build_ks(myks):
    _privatekeys = myks._privatekeys
    _certs = myks._certs
    _secretkeys = myks._secretkeys
    alias_index = 0

    for k in _privatekeys:
        entry = sealedStoreEntry()
        if "alias" in k:
            entry.alias = k["alias"]
        elif "friendlyName" in k:
            entry.alias = str(k["friendlyName"][0]).lower()
        elif "alias" in myks.class_args and myks.class_args["alias"]:
            entry.alias = myks.class_args["alias"][0]
        else:
            entry.alias = f"privatekey-{alias_index}"
            alias_index += 1
        entry.timestamp = int(time.time() * 1000)
        entry.pkey = k["der"]
        entry.type = "PKCS#8"
        entry.key_type = 0
        entry.key_alg = pkcs8.keytype(entry)

        for cert in k["chain"]:
            entry.cert_chain.append(("X.509", cert["der"]))
        myks.add_private_key(entry)

    for k in _secretkeys:
        entry = sealedStoreEntry()
        if "alias" in k:
            entry.alias = k["alias"]
        else:
            entry.alias = str(k["friendlyName"][0]).lower()
        entry.timestamp = int(time.time() * 1000)
        entry.pkey = k["der"]
        entry.type = "SECRET"
        entry.key_type = 2
        entry.key_alg = map_alg_name(k["key_alg"])

        myks.add_secret_key(entry)

    for k in _certs:
        if "trustedKeyUsage" not in k:
            continue
        entry = certStoreEntry()
        entry.type = "X.509"
        if "alias" in k:
            entry.alias = k["alias"]
        else:
            entry.alias = str(k["friendlyName"][0]).lower()
        entry.cert = k["der"]
        entry.timestamp = int(time.time() * 1000)
        myks.add_cert(entry)

    return myks


def asn1_make_pkcs8_bag(k, password, kwargs={"driver": ""}):
    plaintext = k["der"]
    salt = os.urandom(16)
    count = 2048
    if kwargs and "pkcs12:pbes2-key" in kwargs.get("driver", ""):
        # PBES2 is support in JDK8u301
        iv = os.urandom(16)
        cipher = pbe.PBECipher.new_v2(password, AES128, iv, salt, count, id_sha256)
    else:
        cipher = pbe.PBECipher.new_v1(password, DES3, salt, count)

    e_key = pkcs8.pkcs8_wrap(plaintext, cipher)

    safe_bag = P12.SafeBag()
    safe_bag["bag_id"] = "pkcs8_shrouded_key_bag"
    safe_bag["bag_value"] = keys.EncryptedPrivateKeyInfo.load(e_key)

    asn1_attrs = asn1_make_attrs(k)

    if asn1_attrs is not None:
        safe_bag["bag_attributes"] = asn1_attrs

    return safe_bag


def asn1_make_secret_bag(k, password):
    # plaintext = k['der']
    salt = os.urandom(16)
    count = 2048
    # Use PBES2, not supported by Java keytool
    # iv = os.urandom(16)
    # cipher  = pbe.PBECipher.new_v2(password, AES128, iv, salt, count, id_sha256)

    raw = SecretKeyInfo()
    raw["version"] = 0
    raw["secret_key"] = k["der"]

    alg = algos.EncryptionAlgorithm()
    alg["algorithm"] = rev_oid_alg[k["key_alg"]]
    alg["parameters"] = core.Null()
    raw["secret_key_algorithm"] = alg

    plaintext = raw.dump()

    cipher = pbe.PBECipher.new_v1(password, DES3, salt, count)

    e_key = pkcs8.pkcs8_wrap(plaintext, cipher)

    safe_bag = P12.SafeBag()
    safe_bag["bag_id"] = "secret_bag"
    value = P12.SecretBag()
    value["secret_type_id"] = id_PKCS8ShroudedKeyBag
    value["secret_value"] = keys.EncryptedPrivateKeyInfo.load(e_key).dump()

    safe_bag["bag_value"] = value

    asn1_attrs = asn1_make_attrs(k)

    if asn1_attrs is not None:
        safe_bag["bag_attributes"] = asn1_attrs

    return safe_bag


def asn1_make_cert_bag(k):
    safe_bag = P12.SafeBag()
    safe_bag["bag_id"] = "cert_bag"
    contents = P12.CertBag()
    contents["cert_id"] = "x509"
    contents["cert_value"] = core.ParsableOctetString(k["der"])
    safe_bag["bag_value"] = contents
    asn1_attrs = asn1_make_attrs(k)

    if asn1_attrs is not None:
        safe_bag["bag_attributes"] = asn1_attrs

    return safe_bag


def asn1_make_attrs(k):
    attrs = []
    if "alias" in k:
        attr = P12.Attribute()
        attr["type"] = P12.AttributeType("friendly_name")
        attr["values"] = [k["alias"]]
        attrs.append(attr)

    if "localKeyId" in k:
        attr = P12.Attribute()
        attr["type"] = P12.AttributeType("local_key_id")
        attr["values"] = [k["localKeyId"]]
        attrs.append(attr)

    if "trustedKeyUsage" in k:
        attr = P12.Attribute()
        attr["type"] = "trusted_key_usage"
        attr["values"] = ["any_extended_key_usage"]
        attrs.append(attr)

    asn1_attrs = None
    if attrs:
        asn1_attrs = P12.Attributes()
        for r in attrs:
            asn1_attrs.append(r)

    return asn1_attrs


def pkcs12_write_ks(myks, password):
    out_certs = dict()
    for k in myks.certs:
        der = k.cert
        cert_finger_print = hashlib.sha1(der).digest()
        if cert_finger_print in out_certs:
            continue
        out_certs[cert_finger_print] = dict()
        out_certs[cert_finger_print]["der"] = der
        out_certs[cert_finger_print]["alias"] = k.alias
        out_certs[cert_finger_print]["trustedKeyUsage"] = True

    out_keys = []
    out_secret_keys = []
    key_certs = dict()
    for k in myks.private_keys:
        key = dict()
        key["der"] = k.pkey

        cert = k.cert_chain[0][1]
        key_id = hashlib.sha1(cert).digest()

        key["localKeyId"] = key_id
        key["alias"] = k.alias
        out_keys.append(key)

        if key_id not in key_certs:
            key_certs[key_id] = dict()
            key_certs[key_id]["der"] = cert
        key_certs[key_id]["localKeyId"] = key_id

        for certs in k.cert_chain[1:]:
            cert1 = certs[1]
            key_id = hashlib.sha1(cert1).digest()
            if key_id not in key_certs:
                key_certs[key_id] = dict()
                key_certs[key_id]["der"] = cert1

    for k in myks.secret_keys:
        key = dict()
        key["der"] = k.pkey
        key["localKeyId"] = k.alias.encode("ascii")
        key["alias"] = k.alias
        key["key_alg"] = k.key_alg
        out_secret_keys.append(key)

    safe_contents = P12.SafeContents()
    idx = 0
    for k in out_certs.values():
        safe_contents[idx] = asn1_make_cert_bag(k)
        idx += 1
    for k in key_certs.values():
        safe_contents[idx] = asn1_make_cert_bag(k)
        idx += 1

    if idx:
        no_certs = False
        plaintext = safe_contents.dump()
    else:
        no_certs = True

    salt = os.urandom(16)
    count = 2048
    if not no_certs:
        # Use PBES2, not supported by Java keytool
        if "pkcs12:pbes2" in myks.class_args.get("driver", {}):
            LOG.debug("Using PBES2 encryption")
            iv = os.urandom(16)
            algo = pbes2_algo_id(AES128, iv, salt, count, hash_oid=id_sha256)
            ciphertext = pbe.PBECipher(password, algo_id=algo).encrypt(plaintext)
        else:
            LOG.debug("Using PKCS12 encryption")
            cipher = pbe.PBECipher.new_v1(password, DES3, salt, count)
            algo = cipher.algo_id
            ciphertext = cipher.encrypt(plaintext)

        encrypted_content = cms.EncryptedContentInfo()
        encrypted_content["content_type"] = "data"
        encrypted_content["content_encryption_algorithm"] = algo
        encrypted_content["encrypted_content"] = ciphertext

        encrypted_data = cms.EncryptedData()
        encrypted_data["version"] = 0
        encrypted_data["encrypted_content_info"] = encrypted_content

        content_info = cms.ContentInfo()
        content_info["content_type"] = "encrypted_data"
        content_info["content"] = encrypted_data

    payload = P12.AuthenticatedSafe()

    if len(out_keys) + len(out_secret_keys):
        safe_contents_data = P12.SafeContents()
        idx = 0
        for k in out_keys:
            safe_contents_data[idx] = asn1_make_pkcs8_bag(k, password, myks.class_args)
            idx += 1

        for k in out_secret_keys:
            safe_contents_data[idx] = asn1_make_secret_bag(k, password)
            idx += 1

        content_info2 = cms.ContentInfo()
        content_info2["content_type"] = "data"
        content_info2["content"] = safe_contents_data.dump()
        payload.append(content_info2)

    if not no_certs:
        payload.append(content_info)

    tbh_payload = payload.dump()

    mac_data = P12.MacData()
    salt = os.urandom(20)
    count = 2048
    digest = pbe.hmac_pkcs12_pbkdf(password, salt, count, tbh_payload)

    d_info = algos.DigestInfo()
    d_info["digest"] = digest
    d_alg = algos.DigestAlgorithm()
    d_alg["algorithm"] = "sha1"
    d_info["digest_algorithm"] = d_alg

    mac_data["mac"] = d_info
    mac_data["mac_salt"] = salt
    mac_data["iterations"] = count

    payload = cms.ContentInfo()
    payload["content_type"] = "data"
    payload["content"] = tbh_payload

    pkcs12_f = P12.Pfx()

    pkcs12_f["version"] = 3
    pkcs12_f["auth_safe"] = payload
    pkcs12_f["mac_data"] = mac_data

    return pkcs12_f.dump()


class PKCS12KeyStore(KeyStore):
    def load_s(self, data, password):
        self._password = password
        parse_pkcs12(data, self)

        return self

    def write_s(self, password):
        LOG.debug(self.class_args)
        return pkcs12_write_ks(self, password)
