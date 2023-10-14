#include <cryptopp/twofish.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <string>
#include <iostream>
#include <cstring>

using namespace std;
using namespace CryptoPP;

/*
e is CBC_Mode<Twofish>::Encryption
  is CipherModeFinalTemplate_CipherHolder<CPP_TYPENAME CIPHER::Encryption, CBC_Encryption>
     BASE == CBC_Encryption
  is AlgorithmImpl<BASE, CipherModeFinalTemplate_CipherHolder<CIPHER, BASE> >
  is CBC_Encryption
  is StreamTransformation

 */

void output(string prefix, byte* array, int length) {
	string encoded = "";
	StringSource(array, length, true, new HexEncoder(new StringSink(encoded)));
	cout << prefix << encoded << endl;
}

void output(string prefix, string cipher) {
	string encoded = "";
	StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
	cout << prefix << encoded << endl;
}

int main(int argc, char**argv) {


	PKCS12_PBKDF<SHA1> kdf;

	string salt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
	string plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789a";
	string password = "this_is_a_very_long_secure_Passw0rd";

	byte key[32];
	byte iv[16];
	byte zero = '\x00';

	string uPassword = "";
	for (int k = 0; k < password.length(); k++) {
		uPassword.append(1, 0);
		uPassword += password[k];
	}
	uPassword.append(2, 0);
			
	kdf.DeriveKey(key, 32, 1, uPassword.c_str(), uPassword.length(), salt.c_str(), 32, 2048, 0);
	kdf.DeriveKey( iv, 16, 2, uPassword.c_str(), uPassword.length(), salt.c_str(), 32, 2048, 0);

	output("_KEY: ", key, 32);
	output("_IV: ", iv, 16);

	CBC_Mode<Twofish>::Encryption e(key, 32, iv);
	CBC_Mode<Twofish>::Decryption d(key, 32, iv);

	string cipher, encoded;
	StringSource(plain, true,
		     new StreamTransformationFilter(
						     e,
						     new StringSink(cipher)
						     )
		     );

	output("_CIPHER: ", cipher);

	string recovered;
	StringSource(cipher, true,
		     new StreamTransformationFilter(
						     d,
						     new StringSink(recovered)
						     )
		     );

	output("_RECOVERED: ", recovered);
	cout << endl << endl;
	
	cout << "TWOFISH_256:" << endl;
	output("  ciphertext: ", cipher);

	byte key2[40];
	cout << "PKCS12_KDF:" << endl;
	for (int i = 1; i < 4; i++) {
		kdf.DeriveKey(key2, 40, i, uPassword.c_str(), uPassword.length(), salt.c_str(), 32, 2000, 0);

		output("  - ", key2, 40);
	}
		


	PKCS12_PBKDF<SHA256> kdf2;
	
	cout << "PKCS12_KDF_SHA256:" << endl;

	for (int i = 1; i < 4; i++) {
		kdf2.DeriveKey(key2, 40, i, uPassword.c_str(), uPassword.length(), salt.c_str(), 32, 2000, 0);

		output("  - ", key2, 40);
	}
		
}
