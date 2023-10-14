from .jks import JKS
from .bks import BKS, UBER
from .pkcs12 import PKCS12KeyStore as PKCS12
from .pemks import PEMKS, RAWKS
from .bcfks import BCFKeyStore as BCFKS
import logging
import re

LOG = logging.getLogger(__name__)

_map = {
    "jks": JKS,
    "bks": BKS,
    "uber": UBER,
    "p12": PKCS12,
    "pem": PEMKS,
    "raw": RAWKS,
    "fks": BCFKS,
    "bcfks": BCFKS,
}

KEYSTORE_RE = re.compile(r"\.(jks|bks|uber|p12|pem|fks|bcfks)$", re.I)
KEYSTORE_RE2 = re.compile(r"(jks|bks|uber|p12|pem|raw|fks|bcfks):(.*)", re.I)


def keystore_class(name):
    suffix = ""
    m2 = KEYSTORE_RE2.match(name)
    if m2:
        suffix, name = m2.group(1, 2)
    else:
        m = KEYSTORE_RE.search(name)
        if m:
            suffix = m.group(1)

    return _map.get(suffix, None), name


def keystore_from_file(filename, password, kwargs={}):
    # guess keystore from filename
    if kwargs and kwargs.get("in_format", None):
        suffix = kwargs["in_format"]
        del kwargs["in_format"]
        keystore_cls = _map.get(suffix, None)
    else:
        keystore_cls, filename = keystore_class(filename)

    if keystore_cls is not None:
        with open(filename, "rb") as fp:
            keystore = keystore_cls(kwargs=kwargs)
            keystore.load(fp, password)

        return keystore
    else:
        LOG.error("Unknown input keystore type %s", filename)
        return None


def keystore_to_file(ks, filename, password, kwargs={}):
    if kwargs and kwargs.get("out_format", None):
        suffix = kwargs["out_format"]
        del kwargs["out_format"]
        keystore_cls = _map.get(suffix, None)
    else:
        keystore_cls, filename = keystore_class(filename)
    if keystore_cls is not None:
        with open(filename, "wb") as fp:
            keystore_cls.factory(ks, kwargs=kwargs).write_f(fp, password)
    else:
        LOG.error("Unknown output keystore type %s", filename)
