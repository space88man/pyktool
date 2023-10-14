"""
JKS/JCEKS file format decoder.
Use in conjunction with PyOpenSSL to translate to PEM, or load private key and certs
directly into openssl structs and wrap sockets.

See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b14/sun/security/provider/JavaKeyStore.java#JavaKeyStore.engineLoad%28java.io.InputStream%2Cchar%5B%5D%29
See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b27/com/sun/crypto/provider/JceKeyStore.java#JceKeyStore
"""
import time
from time import gmtime, strftime

import hashlib
import base64

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from asn1crypto import keys, x509 as X509

from .util import uread_utf, uread_data, b4, b8
from .util import uwrite_utf, uwrite_data
from .util import envelope
from .util import load_cert_public_key, load_der_private_key

from . import pkcs8, sun_crypto

BACKEND = default_backend()


class KeyStore:
    def __init__(self, private_keys=[], certs=[], secret_keys=[], kwargs={}):
        self.private_keys = list(private_keys)
        self.certs = list(certs)
        self.secret_keys = list(secret_keys)
        self.class_args = kwargs

        self.index = {}
        for k in self.private_keys:
            self.index[k.alias] = k
        for k in self.certs:
            self.index[k.alias] = k
        for k in self.secret_keys:
            self.index[k.alias] = k

    @classmethod
    def factory(cls, ks, kwargs):
        return cls(private_keys=ks.private_keys, certs=ks.certs, kwargs=kwargs)

    def load(self, fp, password):
        # self.private_keys = []
        # self.certs = []
        # self.secret_keys = []
        # self.index = {}

        return self.load_s(fp.read(), password)

    def load_s(self, data, password):
        filetype = ""
        magic_number = data[:4]
        if magic_number == MAGIC_NUMBER_JKS:
            filetype = "jks"
        elif magic_number == MAGIC_NUMBER_JCEKS:
            filetype = "jceks"
        else:
            raise ValueError(
                "Not a JKS or JCEKS keystore (magic number wrong; expected FEEDFEED resp. CECECECE)"
            )

        version = b4.unpack_from(data, 4)[0]
        if version != 2:
            raise ValueError(
                "Unsupported keystore version; only v2 supported, found v"
                + repr(version)
            )

        entry_count = b4.unpack_from(data, 8)[0]
        pos = 12

        ks = self
        ks._version = version

        for i in range(entry_count):
            tag = b4.unpack_from(data, pos)[0]
            pos += 4

            alias, pos = uread_utf(data, pos)
            timestamp = b8.unpack_from(data, pos)[0]  # milliseconds since UNIX epoch
            pos += 8

            if tag == 1:  # private key
                ber_data, pos, dummy = uread_data(data, pos)
                chain_len = b4.unpack_from(data, pos)[0]
                pos += 4

                cert_chain = []
                for j in range(chain_len):
                    cert_type, pos = uread_utf(data, pos)
                    cert_data, pos, dummy = uread_data(data, pos)
                    cert_chain.append((cert_type, cert_data))

                # at this point, ber_data is a PKCS#8 EncryptedPrivateKeyInfo
                p_key = keys.EncryptedPrivateKeyInfo.load(ber_data)
                algo_oid = p_key["encryption_algorithm"]["algorithm"]

                encrypted_private_key = p_key["encrypted_data"].native

                if filetype == "jks":
                    if algo_oid != sun_crypto.SUN_JKS_ALGO_ID:
                        raise ValueError(
                            "Unknown JKS private key algorithm OID: {0}".format(
                                algo_oid
                            )
                        )
                    plaintext = sun_crypto.jks_pkey_decrypt(
                        encrypted_private_key, password
                    )

                elif filetype == "jceks":
                    if algo_oid == sun_crypto.SUN_JKS_ALGO_ID:
                        plaintext = sun_crypto.jks_pkey_decrypt(
                            encrypted_private_key, password
                        )
                    elif algo_oid == sun_crypto.SUN_JCE_ALGO_ID:
                        params = p_key["encryption_algorithm"]["parameters"]
                        salt = params[
                            "salt"
                        ].native  # see section A.3: PBES1 and definitions of AlgorithmIdentifier and PBEParameter in RFC 2898
                        iteration_count = params["iteration"].native
                        plaintext = sun_crypto.jce_pbe_decrypt(
                            encrypted_private_key, password, salt, iteration_count
                        )
                    else:
                        raise ValueError(
                            "Unknown JCEKS private key algorithm OID: {0}".format(
                                algo_oid
                            )
                        )

                # plaintext should be a PrivateKeyInfo structure: RFC5208
                # key is raw key
                # key = decoder.decode(plaintext)[0][2].asOctets()

                ks.add_private_key(PrivateKey(alias, timestamp, plaintext, cert_chain))

            elif tag == 2:  # cert
                cert_type, pos = uread_utf(data, pos)
                cert_data, pos, dummy = uread_data(data, pos)
                ks.add_cert(Cert(alias, timestamp, cert_type, cert_data))

            elif tag == 3:
                if filetype != "jceks":
                    raise ValueError(
                        "Unexpected entry tag {0} encountered in JKS keystore; only supported in JCEKS keystores".format(
                            tag
                        )
                    )
                # TODO: implement me

        # the keystore integrity check uses the UTF-16BE encoding of the password
        password_utf16 = password.encode("utf-16be")
        if (
            hashlib.sha1(password_utf16 + SIGNATURE_WHITENING + data[:pos]).digest()
            != data[pos:]
        ):
            raise ValueError("Hash mismatch; incorrect password or data corrupted")

        return self

    def write_f(self, fp, password):
        fp.write(self.write_s(password))

    def write_s(self, password):
        ks = self
        output = MAGIC_NUMBER_JKS
        output += VERSION

        entry_count = len(ks.certs) + len(ks.private_keys)

        output += b4.pack(entry_count)

        for k in ks.certs:
            output += b4.pack(2)

            output += uwrite_utf(k.alias)

            timestamp = b8.pack(int(time.time() * 1000))
            output += timestamp

            output += uwrite_utf("X.509")

            output += uwrite_data(k.cert)

        for k in ks.private_keys:
            output += b4.pack(1)

            output += uwrite_utf(k.alias)

            timestamp = b8.pack(int(time.time() * 1000))
            output += timestamp

            cert_chain = b""
            for l in k.cert_chain:
                cert_chain += uwrite_utf(l[0])
                cert_chain += uwrite_data(l[1])

            cipher = sun_crypto.SunCipher(password)
            ber_data = pkcs8.pkcs8_wrap(k.pkey, cipher)
            output += uwrite_data(ber_data)

            output += b4.pack(len(k.cert_chain))
            output += cert_chain

        password_utf16 = password.encode("utf-16be")
        hash = hashlib.sha1(password_utf16 + SIGNATURE_WHITENING + output).digest()
        return output + hash

    def add_cert(self, cert):
        self.certs.append(cert)
        self.index[cert.alias] = cert

    def add_private_key(self, private_key):
        self.private_keys.append(private_key)
        self.index[private_key.alias] = private_key

    def add_secret_key(self, secret_key):
        self.secret_keys.append(secret_key)
        self.index[secret_key.alias] = secret_key

    def public_key(self, alias, cert=False):
        if hasattr(self.index[alias], "pkey"):
            crt = self.index[alias].cert_chain[0][1]
        else:
            crt = self.index[alias].cert

        if cert:
            return x509.load_der_x509_certificate(crt, backend=BACKEND)
        else:
            return load_cert_public_key(crt)

    def private_key(self, alias):
        prv = self.index.get(alias, None)
        if not prv or not hasattr(prv, "pkey"):
            return None

        return load_der_private_key(prv.pkey)

    def key_type(self, alias):
        if hasattr(self.index[alias], "pkey"):
            cert = self.index[alias].cert_chain[0][1]
        else:
            cert = self.index[alias].cert

        my_cert = X509.Certificate.load(cert)

        if my_cert.public_key["algorithm"]["algorithm"].native.startswith("rsa"):
            return "RSA"
        else:
            return "EC"

    def pem_s(self):
        def utime(n):
            ts = n.timestamp if hasattr(n, "timestamp") else int(time.time() * 1000)
            return strftime("%Y%m%d%H%M%SZ", gmtime(ts / 1000))

        def mtime(n):
            return (
                n.last_modified_date.strftime("%Y%m%d%H%M%SZ")
                if hasattr(n, "last_modified_date")
                else utime(n)
            )

        outpem = ""
        count = 0
        base64.MAXBINSIZE = 48
        for k in self.certs:
            outpem += "cert,{0},{1},{2}:{3}\n".format(
                k.alias, count, utime(k), mtime(k)
            )
            outpem += envelope("CERTIFICATE", k.cert, encode=True)
            count += 1

        for k in self.private_keys:
            outpem += "privatekey,{0},{1},{2},{3}:{4}\n".format(
                k.alias, count, utime(k), pkcs8.keytype(k), mtime(k)
            )
            outpem += envelope("PRIVATE KEY", k.pkey, encode=True)

            ccount = 0
            for cert in k.cert_chain:
                outpem += "chain,{0},{1}\n".format(k.alias, ccount)
                outpem += envelope("CERTIFICATE", cert[1], encode=True)
                ccount += 1
            count += 1

        for k in self.secret_keys:
            outpem += "secretkey,{0},{1},{2},{3},{4}:{5}\n".format(
                k.alias, count, utime(k), k.key_alg, len(k.pkey), mtime(k)
            )
            outpem += envelope("RAW KEY", k.pkey, encode=True)

        return outpem

    def cert(self, alias, der=False):
        if alias in self.index:
            return self.index[alias].get_cert_pem(der=der)

    def delete(self, alias):
        if alias not in self.index:
            return

        entry = self.index[alias]
        lst = self.private_keys if hasattr(entry, "pkey") else self.certs
        lst.remove(entry)
        del self.index[alias]


JKS = KeyStore


class PEMMixin:
    def get_pem(self, full=False):
        if hasattr(self, "cert"):
            return self.get_cert_pem()
        elif hasattr(self, "pkey"):
            output = envelope("PRIVATE KEY", self.pkey, encode=True)
            if full:
                for k in self.cert_chain:
                    output += envelope("CERTIFICATE", k[1], encode=True)

            return output

    def get_cert_pem(self, chain=False, der=False):
        ret = None
        if hasattr(self, "cert"):
            ret = (
                envelope("CERTIFICATE", self.cert, encode=True)
                if not der
                else self.cert
            )
        elif hasattr(self, "pkey"):
            if not der:
                ret = envelope("CERTIFICATE", self.cert_chain[0][1], encode=True)
            else:
                return self.cert_chain[0][1]
            if chain:
                for cert in self.cert_chain[1:]:
                    ret += envelope("CERTIFICATE", cert[1], encode=True)

        return ret


class Cert(PEMMixin):
    def __init__(self, alias, timestamp, typz, cert):
        self.alias = alias
        self.timestamp = timestamp
        self.type = typz
        self.cert = cert


class PrivateKey(PEMMixin):
    def __init__(self, alias, timestamp, pkey, cert_chain):
        self.alias = alias
        self.timestamp = timestamp
        self.pkey = pkey
        self.cert_chain = cert_chain


MAGIC_NUMBER_JKS = b4.pack(0xFEEDFEED)
MAGIC_NUMBER_JCEKS = b4.pack(0xCECECECE)
VERSION = b4.pack(2)
SIGNATURE_WHITENING = b"Mighty Aphrodite"
