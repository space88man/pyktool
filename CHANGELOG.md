# CHANGELOG
## Changes
* 20.1.x:
    * clean up
* 19.10.1: [TASK-012] asn1crypto version update
* 19.5.2: [TASK-011] handled weird key identifier (consul — I'm looking at you)
* 19.5.1: [TASK-010] handled RSAES-OAEP
* 19.5.0: [TASK-009] handled RSASSA-PSS
* 19.3.5: TBD
* 19.3.4: use PKCS12 KDF from oscrypto instead of wrapper
* 19.3.3: cleanup of APIs since we are not using native extensiosn
* 19.3.2: make pure Python with oscrypto and https://github.com/sommer/loxodo
* 19.3.1: sync with pyejbca - add cert() method

## BUGS
### TASK-014
* use upstream asn1crypto 1.3.0

### TASK-013
* better error handling if passphrase is incorrect

### TASK-012
* asn1crypto dependency update

### TASK-011
* Handle key identifiers in hexlified form (59, 95 byte formats)

### TASK-010
* Handle RSAES-OAEP in keys and certificates

### TASK-009
* Handle RSASSA-PSS in keys and certificates

### BUG-008
* PKCS12: match on friendlyName if localKeyId fails

### BUG-007
* Cert can appear multiple times in P12 file

### BUG-006
* Missing friendlyName in P12 files

### BUG-005
* This has surfaced again during convert :-(
* pkcs12 was testing for non-existent driver string

### BUG-004

handle pkcs12 files without friendlyName


### BUG-003

`--in_format` not being passed to convert operation

### BUG-002

Serious mutation bug; the attributes private_keys, certs, secret keys etc were not copied
and creating another keystore could mutate them

### BUG-001

Cannot dump a raw keystore.
