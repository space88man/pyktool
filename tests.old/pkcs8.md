
Create pkcs8 DER files:

    openssl pkcs8 -topk8 -in abcd.key -out abcd.der -outform DER -passout pass:abcd1234 -v1 PBE-SHA1-3DES
    openssl pkcs8 -topk8 -in abcd.key -out abcd.der -outform DER -passout pass:abcd1234 -v1 PBE-SHA1-RC2-128
    openssl pkcs8 -topk8 -in abcd.key -out abcd.der -outform DER -passout pass:abcd1234 -v1 PBE-SHA1-RC4-128

    ## verify with non-PBE2 code
    python t-pkcs8.py abcd.der abcd1234

Use PBE2 algorithms:

    
    openssl pkcs8 -topk8 -in abcd.key -out abcd3.der -outform DER \
        -passout pass:abcd1234 -v2 aes-192-cbc -v2prf hmacWithSHA256