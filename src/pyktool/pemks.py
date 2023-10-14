# vim: set et ai ts=4 sts=4 sw=4:
import base64
import logging
import io
import hashlib
import re
import time
from datetime import datetime, timezone

from . import bks, certutil, pkcs12, pkcs8

from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from asn1crypto.x509 import Certificate as CERT

LOG = logging.getLogger(__name__)


class PEMKS(bks.BKS):
    def load_s(self, data, password):
        io_buffer = io.StringIO(data.decode("ascii"))
        pems = _pem_load(io_buffer)
        self._make_ks(pems, password)
        return self

    def _make_ks(self, pems, password):
        def _make_attrs(entry, k, args):
            for arg in args:
                setattr(entry, arg, k[arg])

        myks = self

        attrs = ("alias", "timestamp", "created_date", "last_modified_date")

        for k in pems:
            if k["type"] == "cert":
                entry = bks.certStoreEntry()
                entry.type = "X.509"
                _make_attrs(entry, k, attrs)
                entry.cert = base64.b64decode(k["data"])
                myks.add_cert(entry)

            if k["type"] == "key":
                entry = bks.sealedStoreEntry()
                entry.type = "PKCS#8"
                _make_attrs(entry, k, attrs)

                for cert in k["chain"]:
                    entry.cert_chain.append(("X.509", base64.b64decode(cert)))

                entry.pkey = pkcs8.pkcs8_der_from_pem(k["data"], password)[1]
                myks.add_private_key(entry)

            if k["type"] == "secretkey":
                entry = bks.sealedStoreEntry()
                _make_attrs(entry, k, attrs)
                entry.key_alg = k["key_alg"]
                entry.type = "SECRET"
                entry.pkey = base64.b64decode(k["data"])
                myks.add_secret_key(entry)
        return myks

    def write_s(self, password, uber=False):
        return self.pem_s().encode("ascii")


class RAWKS(PEMKS):
    def load_s(self, data, password):
        io_buffer = io.StringIO(data.decode("ascii"))
        _pem_load_raw(self, io_buffer, password)
        return self


PEM_KEY_RE = re.compile(
    "-----BEGIN (PRIVATE KEY|ENCRYPTED PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)"
)


def _pem_load(lines):
    keystore = []
    group = {}
    is_base64 = False
    pem = ""
    is_secretkey = is_chain = is_key = is_cert = False

    def _parse_entry(k):
        # tag, alias, index, timestamp, alg, ...:last_modified_date
        colon = k[:-1].split(":")

        base = colon[0]
        fields = base.split(",")
        alias = fields[1]
        key_alg = "NONE"
        if len(fields) >= 4:
            if fields[3].endswith("Z"):
                date_str = fields[3][:-1] + "+0000"
            else:
                date_str = fields[3]
            created_date = datetime.strptime(date_str, "%Y%m%d%H%M%S%z")
        else:
            created_date = datetime.now(timezone.utc)
        timestamp = int(created_date.timestamp() * 1000)

        if len(fields) >= 5:
            key_alg = fields[4]

        if len(colon) == 1:
            last_modified_date = created_date
        else:
            if colon[1].endswith("Z"):
                mod_str = colon[1][:-1] + "+0000"
            else:
                mod_str = colon[1]
            last_modified_date = datetime.strptime(mod_str, "%Y%m%d%H%M%S%z")

        return {
            "alias": alias,
            "timestamp": timestamp,
            "key_alg": key_alg,
            "created_date": created_date,
            "last_modified_date": last_modified_date,
        }

    for k in lines:
        if is_base64:
            if k.find("-----END") == 0:
                is_base64 = False
                if is_key:
                    group["data"] = pem + k  # append full PEM
                    is_key = False
                if is_chain:
                    group["chain"].append(pem)
                    is_chain = False
                if is_cert:
                    group["data"] = pem
                    is_cert = False
                if is_secretkey:
                    group["data"] = pem
                    is_secretkey = False
                pem = ""
            else:
                pem += k

        if k.find("-----BEGIN CERTIFICATE") == 0:
            is_base64 = True

        if k.find("-----BEGIN RAW") == 0:
            is_base64 = True

        m = PEM_KEY_RE.match(k)
        if m:
            assert is_key
            is_base64 = True
            pem += k

        if k.find("privatekey") == 0:
            entry = _parse_entry(k)
            alias = entry["alias"]
            cur_alias = alias
            LOG.debug("private key: %s", alias)
            if len(group) > 0 and group["data"] is not None:
                keystore.append(group)
            group = {"data": None, "chain": [], "type": "key"}
            group.update(entry)
            is_key = True

        if k.find("secretkey") == 0:
            entry = _parse_entry(k)
            cur_alias = entry["alias"]
            LOG.debug("secret key: %s", alias)
            if len(group) > 0 and group["data"] is not None:
                keystore.append(group)
            group = {"data": None, "type": "secretkey"}
            group.update(entry)
            is_secretkey = True

        if k.find("chain") == 0:
            alias = _parse_entry(k)["alias"]
            assert alias == cur_alias
            LOG.debug("cert in chain")
            is_chain = True

        if k.find("cert") == 0:
            entry = _parse_entry(k)
            LOG.debug("cert: %s", entry["alias"])
            if len(group) > 0 and group["data"] is not None:
                keystore.append(group)
            group = {"data": None, "chain": [], "type": "cert"}
            group.update(entry)
            is_cert = True

    keystore.append(group)
    return keystore


def _pem_load_raw(newks, lines, password=None, build=True):
    private_keys = []
    certs = []
    public_keys = {}
    is_base64 = is_key = is_cert = False
    pem = ""
    count = 0

    my_dict = getattr(newks, "class_args", {})
    my_alias = my_dict.get("alias", [])
    my_truststore = my_dict.get("truststore", False)
    for k in lines:
        if is_base64:
            if k.find("-----END") == 0:
                is_base64 = False
                if is_key:
                    pk, der_data = pkcs8.pkcs8_der_from_pem(pem + k, password)
                    pubk_der = pk.public_key().public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    pubk_hash = hashlib.sha256(pubk_der).hexdigest()
                    LOG.debug("private_key pubkey hash: %s", pubk_hash)
                    alias_me = my_alias[0] if my_alias else "private_key_" + str(count)
                    my_alias = my_alias[1:]
                    private_keys.append(
                        {
                            "private_key": pk,
                            "der": der_data,
                            "localKeyId": pubk_hash,
                            "alias": alias_me,
                        }
                    )
                    is_key = False
                if is_cert:
                    der_data = base64.b64decode(pem)
                    cert = x509.load_der_x509_certificate(
                        der_data, backend=default_backend()
                    )

                    subject, issuer = certutil.cert_get_subject(der_data)
                    pubk_der = cert.public_key().public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    pubk_hash = hashlib.sha256(pubk_der).hexdigest()
                    cert_entry = {
                        "cert": cert,
                        "der": der_data,
                        "public_hash": pubk_hash,
                        "alias": "x509_" + str(count),
                        "subject": subject,
                        "issuer": issuer,
                    }
                    if my_truststore:
                        cert_entry["trustedKeyUsage"] = True
                        if my_alias:
                            cert_entry["alias"] = my_alias[0]
                            my_alias = my_alias[1:]
                    certs.append(cert_entry)
                    LOG.debug("cert: subject %s; issuer %s", subject[0], issuer[0])
                    LOG.debug("cert pubkey hash: %s", pubk_hash)
                    public_keys[pubk_hash] = cert_entry
                    is_cert = False
                pem = ""
                count += 1
            else:
                pem += k

        if k.find("-----BEGIN CERTIFICATE") == 0:
            is_base64 = True
            is_cert = True

        if k.find("-----BEGIN RAW") == 0:
            LOG.warning("Raw PEM format does not handle secret keys, skipping...")

        m = PEM_KEY_RE.match(k)
        if m is not None:
            is_base64 = True
            is_key = True
            pem = k

    for k in private_keys:
        pk_hash = k["localKeyId"]
        if pk_hash in public_keys:
            LOG.debug(
                "private_key matching cert found: %s %s",
                k["alias"],
                public_keys[pk_hash]["alias"],
            )
            public_keys[pk_hash]["localKeyId"] = pk_hash

    newks._privatekeys = private_keys
    newks._certs = certs
    newks._secretkeys = []
    if not build:
        return newks
    pkcs12.check_chains(newks)
    pkcs12.build_ks(newks)
    return newks


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    import fileinput
    import argparse
    import pyktool

    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted", action="store_true")
    parser.add_argument("--out")
    parser.add_argument("--opass")
    opts, args = parser.parse_known_args()
    ks = _pem_load_raw(fileinput.input(files=args), truststore=opts.trusted)
    print(ks.pem_s())
    if opts.out:
        pyktool.keystore_to_file(ks, opts.out, opts.opass)
