# Python keytool(as  pyktool)

A Python cli app like Java's  keytool

## Build

    # develop
    pip install -e .[dev]

    # tests
    pytest tests

    # build
    python -m build


## PKCS12

### Information

pkcs12.py: supports a subset of PKCS12

1. Payload(authSafe) is pkcs7-data

2. authSafe is an array of (1)pkcs7-data or (2)pkcs7-encryptedData

3. (1) is an array of SafeBags

4. (2) the plaintext is an array of SafeBags; (2) is usually encrypted by
PBEWithSHA1AndRC2_40

5. A SafeBag is PKCS8 encrypted key or X.509 cert; a PKCS8 encrypted key is usually encrypted with
PBEWithSHA1And3DES

OID 2.16.840.1.113894.746875.1.1: this attribute is used by SunJSSE PKCS12 KeyStore to
indicate a cert is a trustedCertEntry. It is not recognised by BC PKCS12 KeyStore.

Any cert with a friendlyName is shown by BC as a trustedCertEntry. Some tools set the
friendlyName to be the cert DN, as a Java KeyStore alias this is really weird.

### PKCS12 Structure

Outer layer: AuthenticatedSafe(pkcs7-data)

Payload: an array of SafeContent(pkcs7-data)  or encrypted-SafeContent(pkcs7-encryptedData)

SafeContent: an array of SafeBag

SafeBag: "leaf" bag (e.g. pkcs8ShroudedBag, certBag) or a SafeContent (leading to nested structure)
