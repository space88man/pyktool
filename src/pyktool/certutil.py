#! /usr/bin/python

from cryptography import x509
from cryptography.hazmat.backends import default_backend

_tags = {
    "2.5.4.3": ("CN", "commonName"),
    "2.5.4.4": ("SN", "surname"),
    "2.5.4.5": ("SERIALNUMBER", "serialNumber"),
    "2.5.4.6": ("C", "countryName"),
    "2.5.4.7": ("L", "localityName"),
    "2.5.4.8": ("ST", "stateOrProvinceName"),
    "2.5.4.9": ("STREET", "streetAddress"),
    "2.5.4.10": ("O", "organizationName"),
    "2.5.4.11": ("OU", "organizationalUnitName"),
    "2.5.4.97": ("organizationIdentifier", "organizationIdentifier"),
    "0.9.2342.19200300.100.1.1": ("UID", "userId"),
    "0.9.2342.19200300.100.1.25": ("DC", "domainComponent"),
    "1.2.840.113549.1.9.1": ("EMAILADDRESS", "emailAddress"),
}


def tag_to_text(oid: str)  -> str:
    """Maps dotted OID to a short name.
    If OID cannot be found that returns the dotted string as-is.
    """

    return _tags[oid][0] if oid in _tags else oid


"""__str__ representation of multi-valued RDN looks the same as a linear set of RDN
/CN=US/UID=abcd+/CN=User  appears the same as /CN=US/UID=abcd/CN=User
to observe the difference you need to use the rdns attribute
"""


def dn_to_str(DN):
    return ",".join(
        [
            "+".join(
                ["/{}={}".format(tag_to_text(x.oid.dotted_string), x.value) for x in y]
            )
            for y in DN.rdns
        ]
    )


def cert_get_subject(input):
    """Returns a tuple of string representation of
    of subject and issuer."""

    cert = x509.load_der_x509_certificate(input, backend=default_backend())
    issuer = cert.issuer
    subject = cert.subject

    # print(f"============ {dn_to_str(subject)} {dn_to_str(issuer)}")
    return ((dn_to_str(subject), subject), (dn_to_str(issuer), issuer))


if __name__ == "__main__":
    import sys
    import base64

    data = open(sys.argv[1]).read()
    if data.startswith("-----BEGIN CERTIFICATE"):
        data = base64.b64decode("".join(data.splitlines()[1:-1]))

    cert_get_subject(data)
