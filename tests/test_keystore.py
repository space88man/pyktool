import pytest
from pyktool import keystore_from_file, keystore_to_file
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from pyktool.errors import PKCS12Error


class TestKS():

    ks = keystore_from_file("tests/fixtures/cacerts.pem", "")

    def test_read_pem(self):

        ks_new = keystore_from_file("tests/fixtures/cacerts.pem", "")

        assert "affirmtrustcommercialca [jdk]" in ks_new.index
        assert isinstance(ks_new.public_key("affirmtrustcommercialca [jdk]"), RSAPublicKey)
        assert isinstance(ks_new.private_key("superadmin"), RSAPrivateKey)

    def test_read_jks_new(self):

        ks_new = keystore_from_file("tests/fixtures/cacerts.jks", "changeit")

        assert "addtrustexternalca [jdk]" in ks_new.index
        assert isinstance(ks_new.public_key("addtrustexternalca [jdk]"), RSAPublicKey)
        assert isinstance(ks_new.private_key("superadmin"), RSAPrivateKey)

    def test_read_bks_new(self):

        ks_new = keystore_from_file("tests/fixtures/cacerts.bks", "changeit")

        assert "ssl.comevrootcertificationauthorityecc" in ks_new.index
        assert isinstance(
            ks_new.public_key("ssl.comevrootcertificationauthorityecc"),
            EllipticCurvePublicKey
        )
        assert isinstance(ks_new.private_key("superadmin"), RSAPrivateKey)

    def test_read_p12(self):

        ks_new = keystore_from_file("tests/fixtures/cacerts.p12", "changeit")

        assert "accvraiz1" in ks_new.index
        assert isinstance(ks_new.public_key("accvraiz1"), RSAPublicKey)
        # assert isinstance(ks_new.private_key("superadmin"), RSAPrivateKey)

    def test_read_raw(self):

        ks_new = keystore_from_file("tests/fixtures/private.pem", "changeit", {"in_format": "raw", "alias": ["superman"]})
        assert len(ks_new.private_keys) == 1
        assert ks_new.private_keys[0].alias == 'superman'

    def test_write_jks(self, tmpdir):

        keystore_to_file(self.ks, tmpdir.dirname + "/certstore.jks", "changeit")
        ks = keystore_from_file(tmpdir.dirname + "/certstore.jks", "changeit")

        assert "affirmtrustcommercialca [jdk]" in ks.index
        assert isinstance(ks.public_key("affirmtrustcommercialca [jdk]"), RSAPublicKey)
        assert isinstance(ks.private_key("superadmin"), RSAPrivateKey)

    def test_write_bks(self, tmpdir):

        keystore_to_file(self.ks, tmpdir.dirname + "/certstore.bks", "changeit")
        ks = keystore_from_file(tmpdir.dirname + "/certstore.bks", "changeit")

        assert "ssl.comevrootcertificationauthorityecc" in ks.index
        assert isinstance(
            ks.public_key("ssl.comevrootcertificationauthorityecc"),
            EllipticCurvePublicKey
        )
        assert isinstance(ks.private_key("superadmin"), RSAPrivateKey)

    def test_write_p12(self, tmpdir):

        keystore_to_file(self.ks, tmpdir.dirname + "/certstore.p12", "changeit")
        ks = keystore_from_file(tmpdir.dirname + "/certstore.p12", "changeit")

        assert "accvraiz1" in ks.index
        assert isinstance(ks.public_key("accvraiz1"), RSAPublicKey)
        assert isinstance(ks.private_key("superadmin"), RSAPrivateKey)

    def test_write_p12_pbes2(self, tmpdir):

        keystore_to_file(self.ks, tmpdir.dirname + "/certstore.p12", "changeit", {'driver': ['pkcs12:pbes2-key', 'pkcs12:pbes2']})
        ks = keystore_from_file(tmpdir.dirname + "/certstore.p12", "changeit")

        assert "accvraiz1" in ks.index
        assert isinstance(ks.public_key("accvraiz1"), RSAPublicKey)
        assert isinstance(ks.private_key("superadmin"), RSAPrivateKey)

    def test_write_pem(self, tmpdir):

        keystore_to_file(self.ks, tmpdir.dirname + "/certstore.pem", "changeit")
        ks = keystore_from_file(tmpdir.dirname + "/certstore.pem", "changeit")

        assert "addtrustexternalca [jdk]" in ks.index
        assert isinstance(ks.public_key("addtrustexternalca [jdk]"), RSAPublicKey)
        assert isinstance(ks.private_key("superadmin"), RSAPrivateKey)
