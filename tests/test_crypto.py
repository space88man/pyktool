# vim: et:sts:sw=4:ts=4:
from pyktool.asn1_helper import (
    id_pbeWithSha1AndRC4_128 as RC4_128,
    id_pbeWithSha1AndRC4_40 as RC4_40,
    id_pbeWithSha1AndDESede as DES3,
    id_pbeWithSha1And2DES as DES2,
    id_pbeWithSha1AndRC2_128 as RC2_128,
    id_pbeWithSha1AndRC2_40 as RC2_40,
)
from pyktool.pbe import PBECipher, Legacy
import binascii

import yaml
with open("tests/fixtures/pbev1.yml") as fp:
    pbev1_data = yaml.safe_load(fp)

password = pbev1_data['password'].encode('ascii')
salt = pbev1_data['salt'].encode('ascii')
plain = pbev1_data['plaintext'].encode('ascii')


def create_cipher(a1):
    return PBECipher.new_v1(
        password,
        a1,
        salt,
        2000)


def answer_data(key):
    return binascii.unhexlify(pbev1_data[key]['ciphertext'].encode('ascii'))


class TestCrypto():

    def test_rc2(self):

        answer = answer_data('RC2_128')
        cipher = create_cipher(RC2_128)

        output = cipher.encrypt(plain)
        assert len(output) == 40
        assert output == answer

        cipher = create_cipher(RC2_128)

        ret = cipher.decrypt(output)

        assert ret == plain

    def test_rc2_40(self):

        answer = answer_data('RC2_40')
        cipher = create_cipher(RC2_40)

        output = cipher.encrypt(plain)
        assert len(output) == 40
        assert output == answer

        cipher = create_cipher(RC2_40)

        ret = cipher.decrypt(output)

        assert ret == plain

    def test_rc4(self):

        answer = answer_data('RC4_128')
        cipher = create_cipher(RC4_128)

        output = cipher.encrypt(plain)
        assert len(output) == 37
        assert output == answer

        cipher = create_cipher(RC4_128)

        ret = cipher.decrypt(output)

        assert ret == plain

    def test_rc4_40(self):

        answer = answer_data('RC4_40')
        cipher = create_cipher(RC4_40)

        output = cipher.encrypt(plain)
        assert len(output) == 37
        assert output == answer

        cipher = create_cipher(RC4_40)

        ret = cipher.decrypt(output)

        assert ret == plain

    def test_des3(self):

        answer = answer_data('DES3')
        cipher = create_cipher(DES3)

        output = cipher.encrypt(plain)
        assert len(output) == 40
        assert output == answer

        cipher = create_cipher(DES3)

        ret = cipher.decrypt(output)

        assert ret == plain

    def test_des2(self):

        answer = answer_data('DES2')
        cipher = create_cipher(DES2)

        output = cipher.encrypt(plain)
        assert len(output) == 40
        assert output == answer

        cipher = create_cipher(DES2)

        ret = cipher.decrypt(output)

        assert ret == plain

    def test_twofish(self):

        # no NID so we construct the Cipher object directly
        # 1.3.6.1.4.1.25258.3.3 = Twofish/CBC
        # https://github.com/randombit/botan/blob/master/src/build-data/oids.txt
        
        answer = answer_data('TWOFISH_256')
        cipher = Legacy(900, password, salt, 2048)

        output = cipher.encrypt(plain)
        assert len(output) == 48
        assert output == answer

        cipher = Legacy(900, password, salt, 2048)

        ret = cipher.decrypt(output)

        assert ret == plain

    def test_pkcs12_kdf(self):

        from oscrypto.kdf import pkcs12_kdf

        for idx, answer in enumerate(pbev1_data['PKCS12_KDF']):
            answer = binascii.unhexlify(answer.encode('ascii'))
            output = pkcs12_kdf('sha1', password, salt, 2000, 40, idx+1)

            assert answer == output

    def test_pkcs12_kdf_sha256(self):

        from oscrypto.kdf import pkcs12_kdf

        for idx, answer in enumerate(pbev1_data['PKCS12_KDF_SHA256']):
            answer = binascii.unhexlify(answer.encode('ascii'))
            output = pkcs12_kdf('sha256', password, salt, 2000, 40, idx+1)

            assert answer == output
