# About KeyStores

## Bouncycastle Keystores

* UBER, BouncyCastle
* BKS, BKS-V1(different MAC computation)
* BCFKS (for FIPS certification)

## BCFKS
* ASN1 encoded as SEQUENCE with two chunks
* the first chunk is ObjectStoreData / EncryptedObjectStoreData aka StoreData
* the second chunk is the HMAC
* HMAC: the storepass is treated as an ascii string to be converted to bytes using PKCS12 utf-16be, appended with a string
    differentiator
    ```
	# pseudo_code
	hmac_key = key = kdf.derive(to_pkcs12(storepass) + to_pkcs12('INTEGRITY_CHECK'))
	```
	The message body is the raw octets of the StoreData

## OpenSSL

OpenSSL can create PKCS#8s keys encrypted with PBES2:

```
openssl pkcs12 -export -name fiendly -keypbe aes-256-cbc...
```

These PKCS#12 files cannot be read by Sun JCE, but can be read by bouncycastle as BCPKCS12 stores.


## Secret Keys

Java 8: 
* BKS uses secret/sealed entry. After `_pbe_decrypt` you have the raw key value.
* PKCS12: secret keys are stored in SecretBag. The OID is of `pkcs8_shrouded_key_bag` and the value is an `EncryptedPrivateKeyInfo`. After unwrapping the contents are `SecretKeyInfo`:

```
class SecretKeyInfo(core.Sequence):
    """
    Source: https://tools.ietf.org/html/rfc5208#page-3
    """

    _fields = [
        ('version', core.Integer),
        ('secret_key_algorithm', algos.EncryptionAlgorithm),
        ('secret_key', core.ParsableOctetString),
        ('attributes', keys.Attributes, {'implicit': 0, 'optional': True}),
    ]

```

## Crypto

### AES CCM

The parameters are `SEQUENCE(aes-nonce: OCTET STRING, aes-ICVlen: INTEGER(4 | 6 | 8 | 10 | 12 | 14 | 16))`
