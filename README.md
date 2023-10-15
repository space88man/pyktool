# Python keytool(as  pyktool)

A Python cli app like Java's  keytool

The JKS code is from pyjks: https://github.com/kurtbrose/pyjks

## Usage

* dump/undump keystores JKS, BKS, PKCS12 (BKS is a legacy format from BouncyCastle) to annotated PEM
* the annotated PEM is fully compatible with OpenSSL/Botan/GnuTLS
    * dump format is not specified ATM, dump a few keystores to see examples
    * undumping - dump format can be round-tripped to keystore
* (experimental) with a raw PEM file  (i.e. no annotations), if the certs/private key+cert chains
     exist, `pyktool` will attempt to undump to keystore -
     where you can specify the aliases you want. Use the store
     type &ldquo;raw&rdquo; for this use case

     It is always recommended to add annotations to the PEM file to avoid ambiguity

*  store type is identified from suffix, or else prepend the filename with `(jks|bks|pem|p12|raw):`

        pyktool dump (<prefix>:)<keystore> <storepass>
        # cacerts from any JRE/JDK, it is JKS format but has no suffix
        pyktool dump jks:cacerts changeit
        # dump/undump - i.e. conversion
        # convert from JKS to PKCS12
        pyktool convert mykeystore.jks storepass-1 mykeystore.p12 storepass-2

* (experimental) to avoid legacy ciphers, the pyktool can undump  with modern
    PBES2 ciphers - ATM coded, working, but no docs. Check the source code.
    PBES2 is correctly supported from JDK 8u301, JDK 11, JDK 17, JDK 21
* (experimental) support for bcfks format (this is a newer format from BouncyCastle) that
    uses modern ciphers

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
